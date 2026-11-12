// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/exposure"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/store"
)

// pathState is what the attack path analysis reads besides the findings.
type pathState struct {
	ws       []inventory.Workload
	hosts    []inventory.Host
	ins      []store.Integration
	detector *exposure.Detector
	exp      map[string]exposure.Result
}

// analysePaths builds the analysis input from the stored state and runs it
// (ADR 0034).
func (p *Pipeline) analysePaths(ctx context.Context, st pathState, fs []store.Finding, details map[string]match.Finding) (paths.Result, error) {
	devs, err := p.store.Devices(ctx)
	if err != nil {
		return paths.Result{}, fmt.Errorf("load devices: %w", err)
	}
	surfaces, err := p.store.HostSurfaces(ctx)
	if err != nil {
		return paths.Result{}, err
	}
	owner, err := p.store.AssetIDs(ctx)
	if err != nil {
		return paths.Result{}, err
	}
	ms := coverage.Machines(coverage.MachineInput{Hosts: st.hosts, Devices: devs, Integrations: st.ins, Scope: p.opts.Scope(), Now: p.now()})
	coverage.ApplyAssetIDs(ms, owner)

	in := paths.Input{Hosts: map[string]paths.Host{}, HostMachine: map[string]string{}}
	byAddr := map[string]string{}
	for _, m := range ms {
		in.Machines = append(in.Machines, paths.Machine{ID: m.ID, Name: m.Name, Kind: m.Kind, ParentID: m.ParentID, HostIDs: m.HostIDs})
		for _, h := range m.HostIDs {
			in.HostMachine[h] = m.ID
		}
		for _, a := range m.Addresses {
			if _, ok := byAddr[a]; !ok {
				byAddr[a] = m.ID
			}
		}
	}
	// Guests the node inventory reads name no parent record: their node is
	// the machine at the integration's address.
	nodeOf := map[string]string{}
	for _, it := range st.ins {
		if mid := byAddr[addressHost(it.Address)]; mid != "" {
			nodeOf[it.ID] = mid
		}
	}
	hostByID := map[string]inventory.Host{}
	for _, h := range st.hosts {
		hostByID[h.ID] = h
	}
	for i, m := range in.Machines {
		if m.ParentID != "" {
			continue
		}
		for _, h := range m.HostIDs {
			if hr := hostByID[h]; hr.Source == inventory.SourceNodeInventory && hr.IntegrationID != "" && nodeOf[hr.IntegrationID] != m.ID {
				in.Machines[i].ParentID = nodeOf[hr.IntegrationID]
				break
			}
		}
	}
	svcs := serviceSet{seen: map[string]bool{}}
	// Containers first: a port a container publishes is the container's,
	// not the host's.
	published := map[string]string{} // machine|port → workload
	for _, w := range st.ws {
		c := w.Container
		if c == nil || w.RemovedAt != nil {
			continue
		}
		mid := in.HostMachine[w.HostID]
		if mid == "" {
			continue
		}
		e, ok := st.exp[w.ID]
		if !ok {
			e = st.detector.Detect(w)
			st.exp[w.ID] = e
		}
		var entry paths.Entry
		switch e.Exposure {
		case inventory.ExposurePublic:
			entry = paths.Internet
		case inventory.ExposureLAN:
			entry = paths.LAN
		}
		port := uint16(0)
		for _, pt := range c.Ports {
			if pt.PublicPort == 0 {
				continue
			}
			published[mid+"|"+strconv.Itoa(int(pt.PublicPort))] = w.ID
			if port == 0 {
				port = pt.PublicPort
			}
		}
		if entry != "" {
			svcs.add(paths.Service{MachineID: mid, Port: port, Proto: "tcp", Entry: entry, Via: routeVia(e.Evidence), WorkloadID: w.ID, Product: w.Name})
		}
	}
	// Proxy routes from the internet to a machine rather than a container,
	// and to the proxy itself.
	hostMachine := func(id string) string { return in.HostMachine[id] }
	for _, rt := range st.detector.Routes() {
		if st.detector.HostExposure(rt.Host) != inventory.ExposurePublic {
			continue
		}
		for _, h := range rt.Hosts {
			if mid := hostMachine(h); mid != "" {
				svcs.add(paths.Service{MachineID: mid, Port: 443, Proto: "tcp", Product: rt.Via, Entry: paths.Internet, Via: rt.Host, WorkloadID: published[mid+"|443"]})
			}
		}
		host, port, err := net.SplitHostPort(rt.Backend)
		if err != nil {
			continue
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			continue
		}
		if mid := byAddr[host]; mid != "" && published[mid+"|"+port] == "" {
			svcs.add(paths.Service{MachineID: mid, Port: uint16(n), Proto: "tcp", Entry: paths.Internet, Via: rt.Host})
		}
	}
	// What the network scan found answering.
	for _, d := range devs {
		mid := byAddr[d.Address]
		if mid == "" {
			continue
		}
		for _, s := range d.Services {
			if s.Port <= 0 || s.Port > 65535 {
				continue
			}
			product := strings.TrimSpace(s.Product + " " + s.Version)
			svcs.add(paths.Service{MachineID: mid, Port: uint16(s.Port), Proto: strings.ToLower(s.Proto), Product: product, Entry: paths.LAN, Via: "scan",
				WorkloadID: published[mid+"|"+strconv.Itoa(s.Port)], Open: openAccess(s)})
		}
	}
	// The sockets hosts listen on beyond loopback. A host's packages can be
	// called unreachable only when every port it serves is accounted for:
	// a known server port or a container's; an unknown one is missing data.
	hostIDs := make([]string, 0, len(surfaces))
	for id := range surfaces {
		hostIDs = append(hostIDs, id)
	}
	sort.Strings(hostIDs)
	for _, id := range hostIDs {
		s := surfaces[id]
		h := paths.Host{Known: len(s.Listen) > 0, Sources: s.Sources}
		mid := in.HostMachine[id]
		for _, l := range s.Listen {
			if l.Local() {
				continue
			}
			owner := published[mid+"|"+strconv.Itoa(int(l.Port))]
			if owner == "" && l.Proto == "tcp" && l.Port < 32768 && !paths.ServicePort(l.Port) && !slices.Contains(h.UnknownPorts, l.Port) {
				h.UnknownPorts = append(h.UnknownPorts, l.Port)
			}
			if mid != "" {
				svcs.add(paths.Service{MachineID: mid, Port: l.Port, Proto: l.Proto, Entry: paths.LAN, Via: "listener", WorkloadID: owner})
			}
		}
		in.Hosts[id] = h
	}
	in.Services = svcs.sorted()

	names := map[string]string{}
	for _, w := range st.ws {
		pw := paths.Workload{ID: w.ID, HostID: w.HostID, Name: w.Name}
		switch {
		case w.Container != nil:
			pw.Container = true
			pw.Escape = escapeOf(w.Container)
			for _, n := range w.Container.Networks {
				if n.Name != "host" && n.Name != "none" && n.Name != "" {
					pw.Networks = append(pw.Networks, n.Name)
				}
			}
			if e, ok := st.exp[w.ID]; ok {
				pw.Exposure = string(e.Exposure)
			}
			pw.Proxy = proxyRole(w.Container)
		case w.Package != nil:
			pw.Package = w.Package.Source
			if pw.Package == "" {
				pw.Package = w.Package.Name
			}
		}
		in.Workloads = append(in.Workloads, pw)
		names[w.ID] = w.Name
	}
	cat := p.cat.Current()
	for _, f := range fs {
		if f.State == store.StateResolved {
			continue
		}
		m := details[f.ID]
		pf := paths.Finding{ID: f.ID, WorkloadID: f.WorkloadID, AppID: f.AppID, AdvisoryID: f.AdvisoryID, Vector: m.Vector, CVSS: m.CVSS,
			EPSS: m.EPSS, KEV: m.KEV, FixedIn: f.FixedIn, Affected: f.MatchState == string(match.Affected), Name: names[f.WorkloadID]}
		if app, ok := cat.App(f.AppID); ok {
			pf.Name = app.Name
		} else if _, name, ok := distro.ParseSystemAppID(f.AppID); ok {
			pf.Name = name
			if m.Image {
				pf.ImagePackage = name
			}
		}
		in.Findings = append(in.Findings, pf)
	}
	return paths.Analyze(in), nil
}

type serviceSet struct {
	seen map[string]bool
	list []paths.Service
}

// add keeps one service per machine, protocol, port, entry and container:
// containers reached through a route have no port, so the container tells
// them apart.
func (s *serviceSet) add(svc paths.Service) {
	if svc.Proto == "" {
		svc.Proto = "tcp"
	}
	key := svc.MachineID + "|" + svc.Proto + "|" + strconv.Itoa(int(svc.Port)) + "|" + string(svc.Entry) + "|" + svc.WorkloadID
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	s.list = append(s.list, svc)
}

// sorted returns the services in a fixed order, so every run gives the
// same paths: internet entries first, then by machine, port and source.
func (s *serviceSet) sorted() []paths.Service {
	out := append([]paths.Service(nil), s.list...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Entry != b.Entry {
			return a.Entry == paths.Internet
		}
		if a.MachineID != b.MachineID {
			return a.MachineID < b.MachineID
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.WorkloadID != b.WorkloadID {
			return a.WorkloadID < b.WorkloadID
		}
		return a.Via < b.Via
	})
	return out
}

// proxyRoles are images that forward traffic to the containers on their
// networks: reverse proxies, and tunnels that reach the internet without a
// published port.
var proxyRoles = map[string]string{
	"traefik": "proxy", "jc21/nginx-proxy-manager": "proxy", "nginx-proxy-manager": "proxy", "caddy": "proxy",
	"haproxy": "proxy", "linuxserver/swag": "proxy", "nginxproxy/nginx-proxy": "proxy", "jwilder/nginx-proxy": "proxy",
	"nginx": "proxy", "nginxinc/nginx-unprivileged": "proxy", "lucaslorentz/caddy-docker-proxy": "proxy",
	"cloudflare/cloudflared": "tunnel", "tailscale/tailscale": "tunnel", "ngrok/ngrok": "tunnel", "fractalnetworks/gateway-client": "tunnel",
}

// proxyRole says whether a container forwards traffic to its neighbours.
func proxyRole(c *inventory.Container) string {
	ref, err := imageref.Parse(c.ImageRef)
	if err != nil {
		return ""
	}
	repo := ref.Repository
	for _, prefix := range []string{"docker.io/library/", "docker.io/", "ghcr.io/", "lscr.io/", "quay.io/"} {
		repo = strings.TrimPrefix(repo, prefix)
	}
	return proxyRoles[repo]
}

// containerExposures estimates the exposure of every container. A
// container in another's network ("network_mode: service:gluetun") is
// reached like that one: it takes over its exposure.
func containerExposures(ws []inventory.Workload, d *exposure.Detector) map[string]exposure.Result {
	out := map[string]exposure.Result{}
	byRuntime := map[string]inventory.Workload{}
	for _, w := range ws {
		if w.Container == nil || w.RemovedAt != nil {
			continue
		}
		out[w.ID] = d.Detect(w)
		byRuntime[w.HostID+"|"+w.RuntimeID] = w
		byRuntime[w.HostID+"|name|"+w.Name] = w
	}
	for _, w := range ws {
		c := w.Container
		if c == nil || w.RemovedAt != nil || c.Runtime == nil {
			continue
		}
		target, ok := strings.CutPrefix(c.Runtime.NetworkMode, "container:")
		if !ok || target == "" {
			continue
		}
		t, found := byRuntime[w.HostID+"|"+target]
		if !found {
			t, found = byRuntime[w.HostID+"|name|"+target]
		}
		if !found {
			for k, cand := range byRuntime {
				if id, ok := strings.CutPrefix(k, w.HostID+"|"); ok && len(target) >= 12 && strings.HasPrefix(id, target) {
					t, found = cand, true
					break
				}
			}
		}
		if !found || t.ID == w.ID {
			continue
		}
		e := out[t.ID]
		out[w.ID] = exposure.Result{Exposure: e.Exposure, Evidence: append([]string{"shares the network of " + t.Name}, e.Evidence...)}
	}
	return out
}

// routeVia returns the public host name from exposure evidence: a proxy
// route ("NPM route app.example.com forwards to …") or a Traefik router
// label ("traefik router app serves app.example.com"); empty without one.
func routeVia(evidence []string) string {
	for _, e := range evidence {
		if _, rest, ok := strings.Cut(e, " route "); ok {
			if host, _, ok := strings.Cut(rest, " "); ok {
				return host
			}
		}
		if _, rest, ok := strings.Cut(e, " serves "); ok && strings.HasPrefix(e, "traefik router ") && !strings.HasSuffix(rest, "(internal domain)") {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// openAccess names a service that grants control without authentication.
func openAccess(s discovery.Service) string {
	if !s.Insecure {
		return ""
	}
	if s.Product != "" {
		return s.Product + " without authentication"
	}
	return "a service without authentication"
}

// escapeOf says how control of a container gives its host, empty when
// nothing Varde knows does.
func escapeOf(c *inventory.Container) string {
	for _, m := range c.Mounts {
		switch m.Source {
		case "/var/run/docker.sock", "/run/docker.sock":
			return "the Docker socket is mounted into the container"
		case "/":
			if m.Type == "bind" {
				return "the host's root file system is mounted into the container"
			}
		}
	}
	rt := c.Runtime
	if rt == nil {
		return ""
	}
	if rt.Privileged {
		return "the container runs privileged"
	}
	for _, cap := range rt.CapAdd {
		switch cap {
		case "ALL", "SYS_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO":
			return "the container has CAP_" + cap
		case "SYS_PTRACE":
			if rt.PidMode == "host" {
				return "the container has CAP_SYS_PTRACE and the host's processes"
			}
		}
	}
	return ""
}

// pathPriority adjusts a finding's priority by its place on the attack
// paths: on a path from the internet it is urgent, an amplifier or a path
// from the LAN at least P2, background noise at most P3 (P2 when known to
// be exploited). Unclear findings keep the matrix's priority.
func pathPriority(prio policy.Priority, reason string, pl paths.Placement, m match.Finding, exposure inventory.Exposure) (policy.Priority, string) {
	if prio == policy.None {
		return prio, reason
	}
	switch pl.Class {
	case paths.OnPathInternet:
		if m.KEV || m.CVSS >= 7 {
			return policy.P1, "on an attack path from the internet"
		}
		return maxPrio(prio, policy.P2), "on an attack path from the internet"
	case paths.OnPathLAN:
		return maxPrio(prio, policy.P2), "on an attack path from the LAN"
	case paths.Amplifier:
		return maxPrio(prio, policy.P2), "turns a foothold on an attack path into root"
	case paths.Noise:
		if m.KEV {
			// Only physical access keeps a known exploited flaw in the
			// noise (paths.place); it is still worth the daily digest.
			return policy.P2, "known exploited, but " + pl.Reason
		}
		return policy.P3, "background noise: " + pl.Reason
	case paths.Unclear:
		// A package inside an image that nothing says is exploited and
		// no known path uses: nearly every image has such flaws, and each
		// one in the daily digest would bury what matters. It is fixed
		// with the image's next regular update. On a container reachable
		// from the internet the priority stays as the policy set it.
		if m.Image && !m.KEV && m.EPSS < libraryEPSS && prio.Rank() > policy.P3.Rank() && exposure != inventory.ExposurePublic {
			return policy.P3, "a package inside the image; nothing says it is exploited, and no known attack path uses it"
		}
	}
	return prio, reason
}

// libraryEPSS is the probability of exploitation from which a library flaw
// counts as being used (internal/paths uses the same threshold).
const libraryEPSS = 0.10

func maxPrio(a, b policy.Priority) policy.Priority {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// addressHost is the host part of an integration address
// ("ssh://10.0.0.5:22", "10.0.0.5:22", "10.0.0.5").
func addressHost(addr string) string {
	if u, err := url.Parse(addr); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
