// SPDX-License-Identifier: Apache-2.0

// Package exposure estimates how reachable a workload is: public, lan,
// internal or unknown. Detection is heuristic and every result carries its
// evidence; Varde cannot see router port forwards or firewalls.
package exposure

import (
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/inventory"
)

// LabelExposure lets users declare exposure authoritatively.
const LabelExposure = buildinfo.LabelPrefix + "exposure"

// Confidence of a detector result; higher wins.
type Confidence int

// Confidence levels.
const (
	ConfNone   Confidence = 0
	ConfLow    Confidence = 1 // port bindings
	ConfMedium Confidence = 2 // reverse proxy configuration
	ConfManual Confidence = 3 // explicit user statement
)

// Result is the combined exposure of a workload.
type Result struct {
	Exposure inventory.Exposure `json:"exposure"`
	Evidence []string           `json:"evidence,omitempty"`
}

// Config holds the user's domain knowledge.
type Config struct {
	// PublicDomains are suffixes of host names reachable from the
	// internet (e.g. "example.com").
	PublicDomains []string
	// InternalDomains are suffixes only resolvable or routed in the LAN.
	InternalDomains []string
}

// Route is a host name a reverse proxy serves (read through its API) and
// the backend it forwards to ("10.0.0.5:8080", "immich-server:2283").
type Route struct {
	Host, Backend, Via string
	// Hosts are the host records the proxy runs on. Container names and
	// container network addresses are unique only within one Docker host,
	// so they match only containers there.
	Hosts []string
}

// Detector combines all detectors.
type Detector struct {
	cfg Config
	// routes are the reverse proxy routes; hostAddrs the addresses of each
	// host record, to match backends on published ports.
	routes    []Route
	hostAddrs map[string][]string
}

// WithRoutes returns a detector that also counts reverse proxy routes
// whose backend is a container (ADR 0029).
func (d *Detector) WithRoutes(routes []Route, hostAddrs map[string][]string) *Detector {
	c := *d
	c.routes, c.hostAddrs = routes, hostAddrs
	return &c
}

// New returns a Detector.
func New(cfg Config) *Detector {
	norm := func(in []string) []string {
		var out []string
		for _, d := range in {
			d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
			if d != "" {
				out = append(out, d)
			}
		}
		return out
	}
	return &Detector{cfg: Config{PublicDomains: norm(cfg.PublicDomains), InternalDomains: norm(cfg.InternalDomains)}}
}

type finding struct {
	exposure   inventory.Exposure
	confidence Confidence
	evidence   string
}

// Detect estimates the exposure of w.
func (d *Detector) Detect(w inventory.Workload) Result {
	var fs []finding
	switch w.Kind {
	case inventory.KindManual:
		if w.Manual != nil && w.Manual.Exposure != "" && w.Manual.Exposure != inventory.ExposureUnknown {
			fs = append(fs, finding{w.Manual.Exposure, ConfManual, "manual entry"})
		}
	case inventory.KindContainer:
		if c := w.Container; c != nil {
			fs = append(fs, d.fromLabel(c)...)
			fs = append(fs, d.fromTraefik(c)...)
			fs = append(fs, d.fromRoutes(w)...)
			fs = append(fs, fromPorts(c)...)
		}
	}
	return combine(fs)
}

// combine keeps the most confident findings; among equally confident ones
// the most exposed wins.
func combine(fs []finding) Result {
	if len(fs) == 0 {
		return Result{Exposure: inventory.ExposureUnknown}
	}
	best := ConfNone
	for _, f := range fs {
		if f.confidence > best {
			best = f.confidence
		}
	}
	res := Result{Exposure: inventory.ExposureUnknown}
	for _, f := range fs {
		if f.confidence != best {
			continue
		}
		if rank(f.exposure) > rank(res.Exposure) {
			res.Exposure = f.exposure
		}
	}
	for _, f := range fs {
		res.Evidence = append(res.Evidence, f.evidence)
	}
	sort.Strings(res.Evidence)
	return res
}

func rank(e inventory.Exposure) int {
	switch e {
	case inventory.ExposurePublic:
		return 3
	case inventory.ExposureLAN:
		return 2
	case inventory.ExposureInternal:
		return 1
	}
	return 0
}

func (d *Detector) fromLabel(c *inventory.Container) []finding {
	v := strings.ToLower(strings.TrimSpace(c.Labels[LabelExposure]))
	switch e := inventory.Exposure(v); e {
	case inventory.ExposurePublic, inventory.ExposureLAN, inventory.ExposureInternal:
		return []finding{{e, ConfManual, "label " + LabelExposure + "=" + v}}
	}
	return nil
}

var (
	hostCall   = regexp.MustCompile(`Host\(([^)]*)\)`)
	backticked = regexp.MustCompile("`([^`]*)`")
)

// fromTraefik inspects Traefik Docker labels: routers whose Host rules use
// a configured public or internal domain.
func (d *Detector) fromTraefik(c *inventory.Container) []finding {
	if strings.EqualFold(c.Labels["traefik.enable"], "false") {
		return nil
	}
	var out []finding
	keys := make([]string, 0, len(c.Labels))
	for k := range c.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.HasPrefix(k, "traefik.http.routers.") || !strings.HasSuffix(k, ".rule") {
			continue
		}
		router := strings.TrimSuffix(strings.TrimPrefix(k, "traefik.http.routers."), ".rule")
		for _, host := range RuleHosts(c.Labels[k]) {
			switch {
			case host == "*":
				// Catch-all route: reachability depends on the entrypoint,
				// which labels do not reveal.
			case matchesSuffix(host, d.cfg.PublicDomains):
				out = append(out, finding{inventory.ExposurePublic, ConfMedium, "traefik router " + router + " serves " + host})
			case matchesSuffix(host, d.cfg.InternalDomains):
				out = append(out, finding{inventory.ExposureLAN, ConfMedium, "traefik router " + router + " serves " + host + " (internal domain)"})
			}
		}
	}
	return out
}

// fromRoutes counts the reverse proxy routes whose backend is the
// container: its address in a Docker network and a container port, the
// host's address and a published port, or its name (or Compose service)
// and a container port, as proxies on the same Docker network use it.
func (d *Detector) fromRoutes(w inventory.Workload) []finding {
	c := w.Container
	var out []finding
	for _, rt := range d.routes {
		host, port, err := net.SplitHostPort(rt.Backend)
		if err != nil {
			continue
		}
		local := false
		for _, h := range rt.Hosts {
			local = local || h == w.HostID
		}
		if !backendIs(w, c, d.hostAddrs[w.HostID], strings.ToLower(host), port, local) {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(rt.Host, "."))
		switch {
		case matchesSuffix(name, d.cfg.PublicDomains):
			out = append(out, finding{inventory.ExposurePublic, ConfMedium, rt.Via + " route " + name + " forwards to " + rt.Backend})
		case matchesSuffix(name, d.cfg.InternalDomains):
			out = append(out, finding{inventory.ExposureLAN, ConfMedium, rt.Via + " route " + name + " forwards to " + rt.Backend + " (internal domain)"})
		}
	}
	return out
}

// Routes returns the reverse proxy routes the detector counts.
func (d *Detector) Routes() []Route { return d.routes }

// HostExposure says where a host name served by a proxy can be reached
// from: public under a public domain, lan under an internal one, unknown
// otherwise.
func (d *Detector) HostExposure(host string) inventory.Exposure {
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case matchesSuffix(name, d.cfg.PublicDomains):
		return inventory.ExposurePublic
	case matchesSuffix(name, d.cfg.InternalDomains):
		return inventory.ExposureLAN
	}
	return inventory.ExposureUnknown
}

func backendIs(w inventory.Workload, c *inventory.Container, hostAddrs []string, host, port string, local bool) bool {
	containerPort := func() bool {
		for _, p := range c.Ports {
			if itoa(p.PrivatePort) == port {
				return true
			}
		}
		// Containers that expose no port in the image still listen.
		return len(c.Ports) == 0
	}
	for _, n := range c.Networks {
		if local && n.IPAddress != "" && n.IPAddress == host && containerPort() {
			return true
		}
	}
	for _, a := range hostAddrs {
		if a != host {
			continue
		}
		for _, p := range c.Ports {
			if p.PublicPort != 0 && itoa(p.PublicPort) == port {
				return true
			}
		}
	}
	if !local {
		return false
	}
	for _, n := range []string{strings.ToLower(w.Name), strings.ToLower(c.ComposeService)} {
		if n != "" && n == host && containerPort() {
			return true
		}
	}
	return false
}

// RuleHosts extracts host names from Host(...) matchers of a Traefik rule.
// HostRegexp is ignored: its matches cannot be enumerated reliably.
func RuleHosts(rule string) []string {
	var hosts []string
	for _, call := range hostCall.FindAllStringSubmatchIndex(rule, -1) {
		// Skip "HostRegexp(" and "HostSNI(": the match must not be preceded
		// by a letter and the name must be exactly "Host".
		start := call[0]
		if start > 0 && isIdent(rule[start-1]) {
			continue
		}
		args := rule[call[2]:call[3]]
		for _, m := range backticked.FindAllStringSubmatch(args, -1) {
			h := strings.ToLower(strings.TrimSpace(m[1]))
			h = strings.TrimPrefix(strings.TrimPrefix(h, "**."), "*.")
			if h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	return hosts
}

func isIdent(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func matchesSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// fromPorts uses published ports: bound to all interfaces means reachable
// in the LAN (router forwards are invisible), loopback-only or unpublished
// means internal.
func fromPorts(c *inventory.Container) []finding {
	if rt := c.Runtime; rt != nil {
		switch {
		case rt.NetworkMode == "host":
			// Every port it listens on is a port of the host.
			return []finding{{inventory.ExposureLAN, ConfLow, "uses the host's network: its ports are the host's; router port forwards are not visible"}}
		case strings.HasPrefix(rt.NetworkMode, "container:"):
			// Another container's network: that one's exposure applies
			// (resolved by the analysis, which knows the other containers).
			return []finding{{inventory.ExposureUnknown, ConfLow, "uses the network of another container"}}
		}
	}
	published, reachable := false, false
	var evidence string
	for _, p := range c.Ports {
		if p.PublicPort == 0 {
			continue
		}
		published = true
		if loopback(p.IP) {
			continue
		}
		reachable = true
		if evidence == "" {
			switch p.IP {
			case "", "0.0.0.0", "::":
				evidence = "port " + itoa(p.PublicPort) + " published on all interfaces"
			default:
				evidence = "port " + itoa(p.PublicPort) + " published on " + p.IP
			}
		}
	}
	switch {
	case reachable:
		return []finding{{inventory.ExposureLAN, ConfLow, evidence + "; router port forwards are not visible"}}
	case published:
		return []finding{{inventory.ExposureInternal, ConfLow, "ports published on loopback only"}}
	default:
		return []finding{{inventory.ExposureInternal, ConfLow, "no published ports"}}
	}
}

// loopback reports whether a bind address reaches only the host itself.
func loopback(ip string) bool {
	if ip == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Unmap().IsLoopback()
}

func itoa(n uint16) string {
	if n == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
