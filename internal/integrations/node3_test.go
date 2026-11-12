// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// The fixture is the output of the node command run against a simulated
// pct and qm: two LXC containers (Debian, Alpine), a VM whose guest agent
// answers (Ubuntu with two Docker containers, real docker ps and image ls
// lines) and a VM without agent. The simulated pct exec reads its stdin like
// the real one, so a command that lost the guest list would fail here.
func TestParseNodeInventoryV3(t *testing.T) {
	out, err := os.ReadFile("testdata/node3.txt")
	if err != nil {
		t.Fatal(err)
	}
	gs, err := ParseLXCInventory(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 4 {
		t.Fatalf("guests: %d", len(gs))
	}
	by := map[int]ContainerInventory{}
	for _, g := range gs {
		by[g.VMID] = g
	}
	if g := by[101]; g.Kind != GuestLXC || g.Distro != "debian-13" || len(g.Packages) < 50 || g.Hostname != "web" {
		t.Errorf("101: %s %s %d %s", g.Kind, g.Distro, len(g.Packages), g.Hostname)
	}
	if g := by[103]; g.Kind != GuestLXC || !strings.HasPrefix(g.Distro, "alpine-3.22") {
		t.Errorf("103 missing or wrong: %+v", g.Distro)
	}
	vm := by[112]
	if vm.Kind != GuestVM || vm.NoAgent || vm.Distro != "ubuntu-24.04" || len(vm.Packages) < 50 || vm.Hostname != "docker" ||
		len(vm.MACs) != 1 || vm.MACs[0] != "bc:24:11:aa:bb:12" {
		t.Errorf("112: %s noagent=%v %s %d %s %v", vm.Kind, vm.NoAgent, vm.Distro, len(vm.Packages), vm.Hostname, vm.MACs)
	}
	src := 0
	for _, p := range vm.Packages {
		if p.Source != "" {
			src++
		}
		if p.Distro != "ubuntu-24.04" {
			t.Fatalf("package without distro: %+v", p)
		}
	}
	if src == 0 {
		t.Error("no source packages from the guest's dpkg status")
	}
	if len(vm.Containers) != 2 {
		t.Fatalf("containers: %+v", vm.Containers)
	}
	for _, c := range vm.Containers {
		if c.Image == "vaultwarden/server:1.30.0" {
			if c.Name != "varde-audit-vwold-1" || c.State != "running" || c.Labels["com.docker.compose.service"] != "vwold" ||
				!strings.HasPrefix(c.ImageID, "sha256:") || len(c.RepoDigests) != 1 || !strings.HasPrefix(c.RepoDigests[0], "vaultwarden/server@sha256:") {
				t.Errorf("vaultwarden: %+v", c)
			}
		}
	}
	if g := by[120]; g.Kind != GuestVM || !g.NoAgent || g.Hostname != "legacy" || len(g.MACs) != 1 || len(g.Packages) != 0 {
		t.Errorf("120: %+v", g)
	}
}

// A guest-agent answer is a JSON string: whatever the guest prints stays
// inside it and cannot become a marker; a failed command gives nothing.
func TestNodeGuestAnswer(t *testing.T) {
	const n = "0123456789abcdef"
	out := "varde-proxmox-node 3 " + n + "\n@@" + n + " vm 5\n@@" + n + " cfg name: x\n" +
		"@@" + n + " gfile /var/lib/dpkg/status\n" +
		`{"exitcode": 0, "exited": 1, "out-data": "Package: a\nStatus: install ok installed\nVersion: 1\n\n@@` + n + ` vm 6\n@@` + n + ` end\n"}` + "\n" +
		"@@" + n + " gdocker\n" + `{"exitcode": 1, "exited": 1, "out-data": "{\"ID\":\"aaaaaaaaaaaa\",\"Image\":\"x\"}"}` + "\n" +
		"@@" + n + " end\n"
	gs, err := ParseLXCInventory([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 1 || gs[0].VMID != 5 || len(gs[0].Packages) != 1 || len(gs[0].Containers) != 0 {
		t.Errorf("parsed %+v", gs)
	}
}

// One key on the node: every guest becomes a host with its full package
// list, and the Docker containers inside a VM become container workloads.
func TestNodeInventoryEndToEnd(t *testing.T) {
	out, err := os.ReadFile("testdata/node3.txt")
	if err != nil {
		t.Fatal(err)
	}
	cat := testCatalog(t)
	m, st := newManager(t)
	m.o.Catalog = func() *catalog.Catalog { return cat }
	srv := newSSHDocker(t, m.ProxmoxIdentity().Signer.PublicKey())
	srv.fixed = map[string][]byte{"varde-proxmox-lxc": out}
	key, err := FetchHostKey(t.Context(), srv.addr, plainDial)
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(srv.addr)
	cfg := DockerSSHConfig{Address: host, Port: atoi(port), User: "varde", HostKey: MarshalHostKey(key)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go m.Run(ctx)
	waitFor(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.ctx != nil })
	in, status, err := m.AddProxmoxLXC(t.Context(), cfg, "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if status.Containers != 2 || status.VMs != 1 || status.NoAgent != 1 || status.Docker != 2 || status.Packages < 150 {
		t.Errorf("status %+v", status)
	}
	vm, err := st.Host(t.Context(), "pvevm-"+in.ID+"-112")
	if err != nil || vm.Name != "docker" || vm.OS == "" || len(vm.MACs) != 1 {
		t.Fatalf("vm host %+v %v", vm, err)
	}
	pk, ok, err := st.HostPackageList(t.Context(), vm.ID)
	if err != nil || !ok || pk.Distro != "ubuntu-24.04" || len(pk.Packages) < 50 {
		t.Errorf("vm packages %v %v %s %d", ok, err, pk.Distro, len(pk.Packages))
	}
	ws, _ := st.Workloads(t.Context(), store.WorkloadFilter{HostID: vm.ID, Kind: inventory.KindContainer})
	if len(ws) != 2 {
		t.Fatalf("containers in the vm: %d", len(ws))
	}
	legacy, err := st.Host(t.Context(), "pvevm-"+in.ID+"-120")
	if err != nil || !strings.Contains(legacy.Detail, "guest agent") {
		t.Errorf("vm without agent %+v %v", legacy, err)
	}
	if _, ok, _ := st.HostPackageList(t.Context(), legacy.ID); ok {
		t.Error("packages stored for a vm without agent")
	}
}
