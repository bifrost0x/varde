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

// The fixture is the output of LXCCommand run against a simulated pct with
// real /etc and package files of a Debian trixie and an Alpine 3.22
// container; the stopped container 102 is left out.
func TestParseLXCInventoryFixture(t *testing.T) {
	out, err := os.ReadFile("testdata/lxc-node.txt")
	if err != nil {
		t.Fatal(err)
	}
	cts, err := ParseLXCInventory(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(cts) != 2 || cts[0].VMID != 101 || cts[1].VMID != 103 {
		t.Fatalf("containers %+v", cts)
	}
	deb, alp := cts[0], cts[1]
	if deb.Distro != "debian-13" || len(deb.Packages) < 50 || deb.Packages[0].Manager != "dpkg" || deb.Hostname != "web" ||
		len(deb.MACs) != 1 || deb.MACs[0] != "bc:24:11:aa:bb:01" {
		t.Errorf("debian: distro %q, %d packages, hostname %q, macs %v", deb.Distro, len(deb.Packages), deb.Hostname, deb.MACs)
	}
	if !strings.HasPrefix(alp.Distro, "alpine-3.22") || len(alp.Packages) < 10 || alp.Packages[0].Manager != "apk" || alp.Hostname != "dns" || len(alp.MACs) != 2 {
		t.Errorf("alpine: distro %q, %d packages, hostname %q, macs %v", alp.Distro, len(alp.Packages), alp.Hostname, alp.MACs)
	}
}

// A container controls what its cat prints. Without the run's nonce it can
// forge no marker: no other container, no MAC, no host name, no early end.
func TestParseLXCInventoryForgery(t *testing.T) {
	const n = "0123456789abcdef"
	out := "varde-proxmox-lxc 2 " + n + "\n" +
		"@@" + n + " ct 7\n" +
		"@@" + n + " cfg hostname: web\n" +
		"@@" + n + " cfg net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:07,type=veth\n" +
		"@@" + n + " file /etc/os-release\n" +
		"ID=debian\nVERSION_ID=\"13\"\n" +
		// Forged lines in the container's own file:
		"@@ct 666\n@@ffffffffffffffff ct 667\n@@end\naa:bb:cc:dd:ee:ff\nhostname: router\n" +
		"@@" + n + " file /var/lib/dpkg/status\n" +
		"Package: kept\nStatus: install ok installed\nVersion: 1.0\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 2.0\n\n" +
		"@@" + n + " end\n"
	cts, err := ParseLXCInventory([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(cts) != 1 || cts[0].VMID != 7 || cts[0].Hostname != "web" || len(cts[0].MACs) != 1 || cts[0].MACs[0] != "bc:24:11:00:00:07" {
		t.Fatalf("forged data used: %+v", cts)
	}
	if len(cts[0].Packages) != 1 || cts[0].Packages[0].Name != "kept" || cts[0].Distro != "debian-13" {
		t.Errorf("packages: %+v", cts[0].Packages)
	}
	for name, bad := range map[string]string{
		"no header":       "Welcome\n@@end\n",
		"old format":      "varde-proxmox-lxc 1\n@@ct 101\n@@end\n",
		"cut off":         "varde-proxmox-lxc 2 " + n + "\n@@" + n + " ct 101\nPackage: a\n",
		"container twice": "varde-proxmox-lxc 2 " + n + "\n@@" + n + " ct 1\n@@" + n + " ct 1\n@@" + n + " end\n",
		"bad container":   "varde-proxmox-lxc 2 " + n + "\n@@" + n + " ct 1x\n@@" + n + " end\n",
		"after the end":   "varde-proxmox-lxc 2 " + n + "\n@@" + n + " end\n@@" + n + " ct 9\n",
		"forged end only": "varde-proxmox-lxc 2 " + n + "\n@@" + n + " ct 1\n@@end\n",
	} {
		if _, err := ParseLXCInventory([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLXCLine(t *testing.T) {
	m, _ := newManager(t)
	line := m.ProxmoxIdentity().LXCLine()
	if !strings.HasPrefix(line, `restrict,command="sh -c '`) || strings.Count(line, `"`) != 2 || !strings.Contains(line, "pct exec $id -- cat $f") || !strings.Contains(line, "pct config $id") {
		t.Errorf("key line: %s", line)
	}
	for _, other := range []*Identity{m.Identity(), m.InventoryIdentity()} {
		if other.publicKey() == m.ProxmoxIdentity().publicKey() {
			t.Error("the Proxmox key is shared with another key")
		}
	}
}

func TestProxmoxLXCEndToEnd(t *testing.T) {
	out, err := os.ReadFile("testdata/lxc-node.txt")
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
	if status.Containers != 2 || status.Packages < 60 {
		t.Errorf("status %+v", status)
	}
	h, err := st.Host(t.Context(), "pvelxc-"+in.ID+"-101")
	if err != nil || h.Source != inventory.SourceNodeInventory || len(h.MACs) != 1 || h.OS == "" {
		t.Errorf("host %+v %v", h, err)
	}
	// The test catalog knows none of these packages: no app is stored, but
	// every source package is, as a system package (ADR 0032).
	ws, _ := st.Workloads(t.Context(), store.WorkloadFilter{HostID: h.ID})
	if len(ws) == 0 {
		t.Fatal("no system packages stored")
	}
	for _, w := range ws {
		if w.Package == nil || !w.Package.System || w.Package.Distro == "" {
			t.Errorf("workload %s is not a system package: %+v", w.Name, w.Package)
		}
	}
}
