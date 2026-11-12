// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

const jellyfinProbeEntry = `id: jellyfin
name: Jellyfin
homepage: https://jellyfin.org
images: [{match: jellyfin/jellyfin}]
version:
  scheme: semver
  probe:
    http:
      path: /System/Info/Public
      json_pointer: /Version
      expect: {/ProductName: Jellyfin Server}
advisories: {coverage: full, github_repos: [jellyfin/jellyfin]}
exposure_hints: {default_ports: [8096]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-09
`

func probeCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load(fstest.MapFS{"jellyfin.yaml": {Data: []byte(jellyfinProbeEntry)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestEndpointCandidates(t *testing.T) {
	cat := probeCatalog(t)
	if c := endpointCandidatesFor(cat, discovery.Service{Port: 8096, Proto: discovery.ProtoHTTP}); len(c) != 1 || c[0].app.ID != "jellyfin" {
		t.Errorf("default port: %+v", c)
	}
	if c := endpointCandidatesFor(cat, discovery.Service{Port: 443, Proto: discovery.ProtoHTTPS, Product: "Jellyfin"}); len(c) != 1 {
		t.Error("named in the page title: not asked")
	}
	if c := endpointCandidatesFor(cat, discovery.Service{Port: 3000, Proto: discovery.ProtoHTTP, Product: "Grafana"}); len(c) != 0 {
		t.Error("asked an unrelated service")
	}
}

// After a scan the web services are asked for their version; a verified
// answer becomes an endpoint workload with an exact identification, and an
// address that stops answering loses its host.
func TestReadVersionsAfterScan(t *testing.T) {
	m, st := newManager(t)
	cat := probeCatalog(t)
	m.o.Catalog = func() *catalog.Catalog { return cat }
	answer := `{"Version":"12.4.0","ProductName":"Jellyfin Server"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/System/Info/Public" {
			_, _ = io.WriteString(w, answer)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	devs := []discovery.Device{{Address: host, Kind: discovery.KindWeb, Label: "Jellyfin",
		Services: []discovery.Service{{Port: p, Proto: discovery.ProtoHTTP, Product: "Jellyfin"}}}}
	if err := m.readVersions(t.Context(), devs, time.Now()); err != nil {
		t.Fatal(err)
	}
	ws, err := st.Workloads(t.Context(), store.WorkloadFilter{HostID: "endpoint-" + host})
	if err != nil || len(ws) != 1 || ws[0].Kind != inventory.KindEndpoint {
		t.Fatalf("workloads %+v %v", ws, err)
	}
	if r := identify.Identify(cat, ws[0]); r.AppID != "jellyfin" || r.Confidence != identify.Exact || r.Version != "12.4.0" {
		t.Errorf("identification %+v", r)
	}
	h, err := st.Host(t.Context(), "endpoint-"+host)
	if err != nil || h.Source != inventory.SourceEndpoint || h.IntegrationID != EndpointHosts {
		t.Errorf("host %+v %v", h, err)
	}
	// Something else answers now: the host and its workload go.
	answer = `{"Version":"1.0","ProductName":"Not Jellyfin"}`
	if err := m.readVersions(t.Context(), devs, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Host(t.Context(), "endpoint-"+host); err == nil {
		t.Error("host kept after the app stopped answering")
	}
}

func TestProxmoxManagerPackage(t *testing.T) {
	st := ProxmoxStatus{Version: "9.2.26", Nodes: []ProxmoxNode{{Name: "pve1", Addresses: []string{"10.10.1.253"}}, {Name: "pve2", Addresses: []string{"10.10.1.252"}}}}
	if n := proxmoxAPINode(st, "10.10.1.253"); n != "pve1" {
		t.Errorf("node by address: %q", n)
	}
	if n := proxmoxAPINode(st, "pve.lan"); n != "" {
		t.Errorf("ambiguous cluster: %q", n)
	}
	if n := proxmoxAPINode(ProxmoxStatus{Nodes: st.Nodes[:1]}, "pve.lan"); n != "pve1" {
		t.Errorf("single node: %q", n)
	}

	m, s := newManager(t)
	in := store.Integration{ID: "px", Kind: KindProxmox, Name: "Proxmox", Address: "10.10.1.253", Enabled: true, CreatedAt: time.Now()}
	if err := s.CreateIntegration(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	if err := m.storeProxmox(t.Context(), in, st, time.Now()); err != nil {
		t.Fatal(err)
	}
	ws, _ := s.Workloads(t.Context(), store.WorkloadFilter{HostID: "pve-px-node-pve1"})
	if len(ws) != 1 || ws[0].Package == nil || ws[0].Package.Name != "pve-manager" || ws[0].Package.Version != "9.2.26" {
		t.Errorf("pve-manager workload: %+v", ws)
	}
	if ws, _ := s.Workloads(t.Context(), store.WorkloadFilter{HostID: "pve-px-node-pve2"}); len(ws) != 0 {
		t.Error("version of the API node attributed to another node")
	}
}

// An app already read as a container is not counted again through its
// endpoint; that doubled every finding.
func TestEndpointSkipsKnownApps(t *testing.T) {
	m, st := newManager(t)
	cat := probeCatalog(t)
	m.o.Catalog = func() *catalog.Catalog { return cat }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Version":"12.4.0","ProductName":"Jellyfin Server"}`)
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	now := time.Now()
	if err := st.UpsertHost(t.Context(), inventory.Host{ID: "local", Name: "docker", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplySnapshot(t.Context(), "local", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "c1", Name: "jellyfin",
		Container: &inventory.Container{ImageRef: "jellyfin/jellyfin:12.4.0", Networks: []inventory.Network{{Name: "lan", IPAddress: host}}},
	}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	if err := st.ReplaceIdentifications(t.Context(), []identify.Result{{WorkloadID: wid, AppID: "jellyfin", Confidence: identify.Exact, Version: "12.4.0"}}, now); err != nil {
		t.Fatal(err)
	}
	devs := []discovery.Device{{Address: host, Kind: discovery.KindWeb, Services: []discovery.Service{{Port: p, Proto: discovery.ProtoHTTP, Product: "Jellyfin"}}}}
	if err := m.readVersions(t.Context(), devs, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Host(t.Context(), "endpoint-"+host); err == nil {
		t.Error("app read as a container counted again through its endpoint")
	}
}
