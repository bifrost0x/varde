// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// EndpointHosts groups the hosts created from version endpoints, in place
// of an integration ID: each scan replaces them.
const EndpointHosts = "scan:endpoints"

const (
	// endpointsInFlight bounds concurrent version requests.
	endpointsInFlight = 8
	// endpointCandidates bounds the apps tried on one port.
	endpointCandidates = 3
)

type endpointCandidate struct {
	app *catalog.App
	ep  discovery.VersionEndpoint
}

// endpointCandidates picks the catalog apps whose version endpoint is
// worth asking on a web service: the port is one of the app's default
// ports, or the page title or server header names the app. That choice only
// decides what is asked; the app is identified only by the response.
func endpointCandidatesFor(cat *catalog.Catalog, svc discovery.Service) []endpointCandidate {
	product := strings.ToLower(svc.Product)
	type scored struct {
		c     endpointCandidate
		score int
	}
	var list []scored
	for _, app := range cat.Apps() {
		p := app.Version.Probe
		if p == nil || p.HTTP == nil {
			continue
		}
		score := 0
		if slices.Contains(app.ExposureHints.DefaultPorts, svc.Port) {
			score += 2
		}
		if product != "" && strings.Contains(product, strings.ToLower(app.Name)) {
			score++
		}
		if score == 0 {
			continue
		}
		list = append(list, scored{endpointCandidate{app, discovery.VersionEndpoint{
			Path: p.HTTP.Path, VersionPointer: p.HTTP.JSONPointer, VersionPattern: p.HTTP.Pattern(),
			Expect: p.HTTP.Expect, CheckPath: p.HTTP.CheckPath,
		}}, score})
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].score != list[j].score {
			return list[i].score > list[j].score
		}
		return list[i].c.app.ID < list[j].c.app.ID
	})
	var out []endpointCandidate
	for i := 0; i < len(list) && i < endpointCandidates; i++ {
		out = append(out, list[i].c)
	}
	return out
}

// readVersions asks the web services of the devices for their version and
// stores what the apps report, one host per address. Every request goes
// through the scope-checked dialer.
func (m *Manager) readVersions(ctx context.Context, devs []discovery.Device, now time.Time) error {
	if m.o.Catalog == nil {
		return nil
	}
	cat := m.o.Catalog()
	if cat == nil {
		return nil
	}
	type job struct {
		dev  discovery.Device
		svc  discovery.Service
		cand endpointCandidate
	}
	var jobs []job
	for _, d := range devs {
		for _, s := range d.Services {
			if s.Proto != discovery.ProtoHTTP && s.Proto != discovery.ProtoHTTPS {
				continue
			}
			for _, c := range endpointCandidatesFor(cat, s) {
				jobs = append(jobs, job{d, s, c})
			}
		}
	}
	type found struct {
		dev discovery.Device
		w   inventory.Workload
	}
	var (
		mu      sync.Mutex
		results []found
		wg      sync.WaitGroup
		sem     = make(chan struct{}, endpointsInFlight)
	)
	for _, j := range jobs {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		wg.Go(func() {
			defer func() { <-sem }()
			target := net.JoinHostPort(j.dev.Address, strconv.Itoa(j.svc.Port))
			tlsOn := j.svc.Proto == discovery.ProtoHTTPS
			v, err := discovery.ReadVersion(ctx, m.Dial(), target, tlsOn, j.cand.ep)
			if err != nil {
				return
			}
			scheme := "http"
			if tlsOn {
				scheme = "https"
			}
			w := inventory.Workload{
				Kind: inventory.KindEndpoint, RuntimeID: j.cand.app.ID + "@" + strconv.Itoa(j.svc.Port), Name: j.cand.app.Name, State: "running",
				Endpoint: &inventory.Endpoint{URL: scheme + "://" + target + j.cand.ep.Path, AppID: j.cand.app.ID, Version: v},
			}
			mu.Lock()
			results = append(results, found{j.dev, w})
			mu.Unlock()
		})
	}
	wg.Wait()

	known, err := m.knownApps(ctx)
	if err != nil {
		return err
	}
	byAddr := map[string][]inventory.Workload{}
	devOf := map[string]discovery.Device{}
	for _, r := range results {
		// The app is already read there as a container or package: the
		// endpoint would only count it twice.
		if known[r.dev.Address+"\x00"+r.w.Endpoint.AppID] {
			continue
		}
		byAddr[r.dev.Address] = append(byAddr[r.dev.Address], r.w)
		devOf[r.dev.Address] = r.dev
	}
	var hosts []inventory.Host
	for addr, ws := range byAddr {
		d := devOf[addr]
		name := d.Hostname
		if name == "" {
			name = addr
		}
		hosts = append(hosts, inventory.Host{
			ID: "endpoint-" + addr, Name: name, Kind: inventory.HostDevice, Source: inventory.SourceEndpoint,
			Addresses: []string{addr}, LastContact: now, IntegrationID: EndpointHosts,
			Detail: strconv.Itoa(len(ws)) + " app(s) reported their version",
		})
	}
	sort.Slice(hosts, func(i, j int) bool {
		a, _ := netip.ParseAddr(hosts[i].Addresses[0])
		b, _ := netip.ParseAddr(hosts[j].Addresses[0])
		return a.Less(b)
	})
	if err := m.o.Store.SyncIntegrationHosts(ctx, EndpointHosts, hosts); err != nil {
		return err
	}
	for _, h := range hosts {
		if _, err := m.o.Store.ApplySnapshot(ctx, h.ID, inventory.KindEndpoint, byAddr[h.Addresses[0]], now); err != nil {
			return err
		}
	}
	// Hosts that no longer answer were removed as well; analysis is cheap.
	if m.o.Changed != nil {
		m.o.Changed(ctx)
	}
	return nil
}

// knownApps lists (address, app) pairs that a source reading workloads
// already identified: the host's addresses and, for containers, the
// container's own network addresses. Endpoint hosts do not count, nor do
// agents: an agent states its own addresses, and a compromised one could
// claim another device's to hide what its version endpoint reveals. An
// app an agent reads may therefore also show through its endpoint.
func (m *Manager) knownApps(ctx context.Context) (map[string]bool, error) {
	hosts, err := m.o.Store.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	ws, err := m.o.Store.Workloads(ctx, store.WorkloadFilter{})
	if err != nil {
		return nil, err
	}
	ids, err := m.o.Store.Identifications(ctx)
	if err != nil {
		return nil, err
	}
	addrs := map[string][]string{}
	for _, h := range hosts {
		if h.Source != inventory.SourceEndpoint && h.Source != inventory.SourceAgent && h.State != inventory.HostRevoked {
			addrs[h.ID] = h.Addresses
		}
	}
	out := map[string]bool{}
	for _, w := range ws {
		host, ok := addrs[w.HostID]
		id := ids[w.ID]
		if !ok || !id.Confidence.Notifiable() {
			continue
		}
		all := append([]string(nil), host...)
		if w.Container != nil {
			for _, n := range w.Container.Networks {
				if n.IPAddress != "" {
					all = append(all, n.IPAddress)
				}
			}
		}
		for _, a := range all {
			out[a+"\x00"+id.AppID] = true
		}
	}
	return out, nil
}
