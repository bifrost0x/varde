// SPDX-License-Identifier: Apache-2.0

// Package coverage reconciles independent sources of "what exists" with the
// identified inventory and turns gaps into system notices (ADR 0012).
package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/exposure"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// PublicRouteHosts returns the hosts of the container's Traefik routers that
// fall under one of the public domain suffixes, sorted and deduplicated.
// Routes and containers need no separate deduplication: a route declared by
// labels belongs to the container that carries them.
func PublicRouteHosts(wl inventory.Workload, publicDomains []string) []string {
	if wl.Container == nil || len(publicDomains) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for k, v := range wl.Container.Labels {
		if !strings.HasPrefix(k, "traefik.http.routers.") || !strings.HasSuffix(k, ".rule") {
			continue
		}
		for _, h := range exposure.RuleHosts(v) {
			if UnderSuffix(h, publicDomains) {
				seen[h] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// UnderSuffix reports whether host equals or is a subdomain of a suffix.
func UnderSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// Assessable reports whether Varde can check the workload: identified with
// confidence and with a known version.
func Assessable(id identify.Result) bool {
	return id.Confidence.Notifiable() && id.VersionKnown()
}

// PublicRouteNotices lists public routes whose workload Varde cannot assess:
// the most important coverage gap, because something is exposed that no
// advisory check covers. Workloads that are not an app (see NotAnApp) are
// left out.
func PublicRouteNotices(ws []inventory.Workload, ids map[string]identify.Result, publicDomains []string, marked map[string]bool) []store.Notice {
	var out []store.Notice
	for _, g := range AssessWorkloads(ws, ids, publicDomains, marked).PublicRoutes {
		reason := "the app is not in the catalog"
		switch {
		case g.ID.Confidence == identify.Weak:
			reason = "the app is only a probable match"
		case g.ID.Confidence.Notifiable():
			reason = "the running version is unknown"
		}
		image := ""
		if g.Workload.Container != nil {
			image = g.Workload.Container.ImageRef
		}
		out = append(out, store.Notice{
			Key:     store.NoticePublicRoute + ":" + g.Workload.ID + ":" + g.Route,
			Subject: g.Workload.ID,
			Title:   fmt.Sprintf("Public route %s is not checked", g.Route),
			Detail:  fmt.Sprintf("Container %s (%s) is reachable from the internet, but %s.", g.Workload.Name, image, reason),
		})
	}
	return out
}

// StaleHostNotices lists agents that stopped reporting.
func StaleHostNotices(hosts []inventory.Host) []store.Notice {
	var out []store.Notice
	for _, h := range hosts {
		if h.State != inventory.HostStale {
			continue
		}
		out = append(out, store.Notice{
			Key:     store.NoticeHostStale + ":" + h.ID,
			Subject: h.ID,
			Title:   fmt.Sprintf("Host %s is not reporting", h.Name),
			Detail: fmt.Sprintf("Last contact %s. Its workloads are not checked against new advisories until the agent reports again.",
				h.LastContact.UTC().Format("2006-01-02 15:04 MST")),
		})
	}
	return out
}

// NoticeStore is what refreshing notices needs.
type NoticeStore interface {
	MarkStaleHosts(ctx context.Context, now time.Time) error
	Hosts(ctx context.Context) ([]inventory.Host, error)
	SyncNotices(ctx context.Context, kind string, current []store.Notice, now time.Time) error
}

// RefreshHosts marks agents stale that missed three intervals and syncs the
// stale-host notices.
func RefreshHosts(ctx context.Context, st NoticeStore, now time.Time) error {
	if err := st.MarkStaleHosts(ctx, now); err != nil {
		return err
	}
	hosts, err := st.Hosts(ctx)
	if err != nil {
		return err
	}
	return st.SyncNotices(ctx, store.NoticeHostStale, StaleHostNotices(hosts), now)
}

// IntegrationStore is what refreshing the integration notices needs.
type IntegrationStore interface {
	Integrations(ctx context.Context) ([]store.Integration, error)
	SyncNotices(ctx context.Context, kind string, current []store.Notice, now time.Time) error
}

// RefreshIntegrations syncs the notices for failing integrations.
func RefreshIntegrations(ctx context.Context, st IntegrationStore, now time.Time, interval func(kind string) time.Duration) error {
	ins, err := st.Integrations(ctx)
	if err != nil {
		return err
	}
	if err := st.SyncNotices(ctx, store.NoticeIntegrationFailing, IntegrationNotices(ins, now, interval), now); err != nil {
		return err
	}
	return st.SyncNotices(ctx, store.NoticeFirmware, FirmwareNotices(ins), now)
}

// FirmwareNotices lists the network devices whose controller offers a
// firmware update, from the integrations' last reads.
func FirmwareNotices(ins []store.Integration) []store.Notice {
	var out []store.Notice
	for _, in := range ins {
		if !in.Enabled || len(in.Status) == 0 {
			continue
		}
		var st struct {
			Devices []struct {
				Name, Model, MAC, IP, Firmware string
				Updatable                      bool
			} `json:"devices"`
		}
		if json.Unmarshal(in.Status, &st) != nil {
			continue
		}
		for _, d := range st.Devices {
			if !d.Updatable || d.MAC == "" {
				continue
			}
			name := d.Name
			if name == "" {
				name = d.Model
			}
			out = append(out, store.Notice{
				Key:     store.NoticeFirmware + ":" + in.ID + ":" + d.MAC,
				Subject: d.MAC,
				Title:   fmt.Sprintf("Firmware update for %s", truncateText(name, 80)),
				Detail: fmt.Sprintf("%s %s runs firmware %s and %s offers a newer one. Device firmware has no advisory feed Varde can check, and network devices sit on every path from the internet.",
					truncateText(d.Model, 40), truncateText(d.IP, 45), truncateText(d.Firmware, 40), in.Name),
			})
		}
	}
	return out
}

// AssetStore is what keeping asset IDs stable needs.
type AssetStore interface {
	Hosts(ctx context.Context) ([]inventory.Host, error)
	Devices(ctx context.Context) ([]store.StoredDevice, error)
	Integrations(ctx context.Context) ([]store.Integration, error)
	SyncAssets(ctx context.Context, groups [][]string, now time.Time) (map[int]string, error)
}

// RefreshAssets merges the current evidence into machines and records
// their identity keys, so each host keeps its asset ID over time.
func RefreshAssets(ctx context.Context, st AssetStore, scope discovery.Scope, now time.Time, interval func(kind string) time.Duration) error {
	hosts, err := st.Hosts(ctx)
	if err != nil {
		return err
	}
	devs, err := st.Devices(ctx)
	if err != nil {
		return err
	}
	ins, err := st.Integrations(ctx)
	if err != nil {
		return err
	}
	ms := Machines(MachineInput{Hosts: hosts, Devices: devs, Integrations: ins, Scope: scope, Now: now, Interval: interval})
	keys := AssetKeys(ms)
	groups := make([][]string, 0, len(keys))
	for i := range ms {
		if k, ok := keys[i]; ok {
			groups = append(groups, k)
		}
	}
	_, err = st.SyncAssets(ctx, groups, now)
	return err
}

// ProxyRoutes are the routes the reverse proxy integrations (Traefik API,
// Nginx Proxy Manager) last read, and the addresses of each host record,
// for exposure detection. The analysis and the pages use the same.
func ProxyRoutes(ins []store.Integration, hosts []inventory.Host) ([]exposure.Route, map[string][]string) {
	byAddr := map[string][]string{}
	for _, h := range hosts {
		for _, a := range h.Addresses {
			byAddr[a] = append(byAddr[a], h.ID)
		}
	}
	var routes []exposure.Route
	for _, in := range ins {
		if !in.Enabled || len(in.Status) == 0 {
			continue
		}
		var st struct {
			Routes []struct {
				Host     string   `json:"host"`
				Backends []string `json:"backends"`
			} `json:"routes"`
		}
		if json.Unmarshal(in.Status, &st) != nil {
			continue
		}
		proxyHosts := byAddr[addressHost(in.Address)]
		for _, r := range st.Routes {
			for _, b := range r.Backends {
				routes = append(routes, exposure.Route{Host: r.Host, Backend: b, Via: in.Name, Hosts: proxyHosts})
			}
		}
	}
	addrs := make(map[string][]string, len(hosts))
	for _, h := range hosts {
		addrs[h.ID] = h.Addresses
	}
	return routes, addrs
}

// addressHost is the host part of an integration address ("https://10.0.0.5:8080",
// "10.0.0.5:81", "10.0.0.5").
func addressHost(addr string) string {
	if u, err := url.Parse(addr); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
