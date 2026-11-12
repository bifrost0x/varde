// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func scope(t *testing.T, s string) discovery.Scope {
	t.Helper()
	sc, err := discovery.ParseScope(s)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func device(addr, name string) store.StoredDevice {
	return store.StoredDevice{Device: discovery.Device{Address: addr, Hostname: name, Kind: discovery.KindSSH, Label: "SSH"}, LastSeen: time.Now()}
}

func byID(ms []Machine) map[string]Machine {
	out := map[string]Machine{}
	for _, m := range ms {
		out[m.ID] = m
	}
	return out
}

// A Proxmox guest that Varde also reads over SSH and finds in the scan is one
// machine; it used to appear twice (pve-… and ssh-…) plus as a device.
func TestMachinesMergeByAddress(t *testing.T) {
	now := time.Now()
	in := MachineInput{
		Scope: scope(t, "10.10.1.0/24"),
		Hosts: []inventory.Host{
			{ID: "pve-a-101", Name: "docker-vm", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, OS: "QEMU VM",
				Addresses: []string{"10.10.1.20", "172.17.0.1"}, IntegrationID: "a", LastContact: now},
			{ID: "ssh-b", Name: "docker-vm.lan", Kind: inventory.HostDocker, Source: inventory.SourceSSH,
				Addresses: []string{"10.10.1.20"}, IntegrationID: "b", LastContact: now},
		},
		Devices:      []store.StoredDevice{device("10.10.1.20", "docker-vm.lan"), device("10.10.1.99", "printer")},
		Integrations: []store.Integration{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}},
		Workloads:    map[string]int{"ssh-b": 4},
	}
	ms := Machines(in)
	if len(ms) != 2 {
		t.Fatalf("got %d machines, want 2: %+v", len(ms), ms)
	}
	m := byID(ms)["pve-a-101"]
	if m.Name != "docker-vm" || m.Kind != "vm" || m.Workloads != 4 || len(m.Evidence) != 3 || !m.Inventoried() {
		t.Errorf("merged machine wrong: %+v", m)
	}
	if !m.Has(EvidenceSSH) || !m.Has(EvidenceScan) || !m.IsHost() {
		t.Error("evidence missing")
	}
	dev := byID(ms)["device:10.10.1.99"]
	if dev.IsHost() || dev.State != MachineSeen || dev.Name != "printer" {
		t.Errorf("scan-only device wrong: %+v", dev)
	}
	c := CountMachines(ms)
	if c != (MachineCounts{Hosts: 1, Inventoried: 1, Devices: 1}) {
		t.Errorf("counts: %+v", c)
	}
	if !LastInventory(ms).Equal(now) {
		t.Error("last inventory not taken from the SSH source")
	}
}

// Records of the same platform are never merged, and addresses claimed by
// two of them, outside the scope or link-local tie nothing together.
func TestMachinesKeepDistinctRecordsApart(t *testing.T) {
	in := MachineInput{
		Scope: scope(t, "10.10.1.0/24"),
		Hosts: []inventory.Host{
			// Two guests behind the same address (NAT, VIP, stale lease).
			{ID: "pve-a-1", Name: "g1", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, Addresses: []string{"10.10.1.5"}, IntegrationID: "a"},
			{ID: "pve-a-2", Name: "g2", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, Addresses: []string{"10.10.1.5"}, IntegrationID: "a"},
			{ID: "ssh-x", Name: "d", Kind: inventory.HostDocker, Source: inventory.SourceSSH, Addresses: []string{"10.10.1.5"}, IntegrationID: "x"},
			// Docker bridge addresses are on every Docker VM and out of scope.
			{ID: "pve-a-3", Name: "g3", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, Addresses: []string{"172.17.0.1", "fe80::1"}, IntegrationID: "a"},
			{ID: "pve-a-4", Name: "g4", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, Addresses: []string{"172.17.0.1", "fe80::1"}, IntegrationID: "a"},
			// A node and its guest are two machines even with one address.
			{ID: "pve-a-node-pve", Name: "pve", Kind: inventory.HostBareMetal, Source: inventory.SourceProxmox, Addresses: []string{"10.10.1.253"}, IntegrationID: "a"},
			{ID: "pve-a-6", Name: "g6", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, Addresses: []string{"10.10.1.253"}, IntegrationID: "a"},
		},
		Integrations: []store.Integration{{ID: "a", Enabled: true}, {ID: "x", Enabled: true}},
	}
	if ms := Machines(in); len(ms) != len(in.Hosts) {
		t.Fatalf("got %d machines, want %d", len(ms), len(in.Hosts))
	}
}

func TestMachineStates(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour)
	in := MachineInput{
		Scope: scope(t, "10.10.1.0/24"),
		Hosts: []inventory.Host{
			{ID: "local", Name: "varde", Kind: inventory.HostDocker, Source: inventory.SourceLocal, Addresses: []string{"10.10.1.150"}},
			{ID: "pve-a-1", Name: "guest", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, IntegrationID: "a", OS: "LXC container"},
			{ID: "ssh-off", Name: "paused", Kind: inventory.HostDocker, Source: inventory.SourceSSH, IntegrationID: "off"},
			{ID: "agent-1", Name: "far", Kind: inventory.HostDocker, Source: inventory.SourceAgent, State: inventory.HostStale, LastContact: old},
			{ID: "agent-2", Name: "gone", Kind: inventory.HostDocker, Source: inventory.SourceAgent, State: inventory.HostRevoked},
		},
		Devices:      []store.StoredDevice{device("10.10.1.150", ""), device("192.168.9.9", "outside")},
		Integrations: []store.Integration{{ID: "a", Enabled: true}, {ID: "off", Enabled: false}},
	}
	ms := byID(Machines(in))
	if len(ms) != 4 {
		t.Fatalf("got %d machines, want 4 (revoked agent and out-of-scope device left out): %v", len(ms), ms)
	}
	if m := ms["local"]; !m.Self || !m.Has(EvidenceScan) || !m.Inventoried() {
		t.Errorf("Varde's own host not tied to its scanned address: %+v", m)
	}
	if m := ms["pve-a-1"]; m.State != MachineSeen || m.Kind != "lxc" {
		t.Errorf("Proxmox-only guest: %+v", m)
	}
	if m := ms["ssh-off"]; m.State != MachinePaused {
		t.Errorf("host of a switched-off integration: %+v", m)
	}
	if m := ms["agent-1"]; m.State != MachineStale {
		t.Errorf("stale agent: %+v", m)
	}
	c := CountMachines(Machines(in))
	if c != (MachineCounts{Hosts: 4, Inventoried: 1, Stale: 1, Paused: 1}) {
		t.Errorf("counts: %+v", c)
	}
}

// A workload behind a public route that is also not in the catalog is one
// blind spot, and helpers are not counted.
func TestAssessWorkloads(t *testing.T) {
	ws := []inventory.Workload{
		{ID: "w1", Kind: inventory.KindContainer, Name: "web", Container: &inventory.Container{ImageRef: "nginx:alpine",
			Labels: map[string]string{"traefik.http.routers.a.rule": "Host(`web.example.com`)"}}},
		{ID: "w2", Kind: inventory.KindContainer, Name: "proxy", Container: &inventory.Container{ImageRef: "tecnativa/docker-socket-proxy:v0.5.0"}},
	}
	c := AssessWorkloads(ws, nil, []string{"example.com"}, nil)
	if c.Total != 1 || len(c.NotApps) != 1 || len(c.NotInCatalog) != 1 || len(c.PublicRoutes) != 1 || c.BlindSpots() != 1 {
		t.Errorf("coverage: total %d, not apps %d, not in catalog %d, routes %d, blind spots %d",
			c.Total, len(c.NotApps), len(c.NotInCatalog), len(c.PublicRoutes), c.BlindSpots())
	}
}
