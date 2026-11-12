// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// The fixtures are the real output of InventoryCommand in Debian, Fedora
// and Alpine containers.
func TestParseInventoryFixtures(t *testing.T) {
	for _, c := range []struct {
		file, os, manager, name, version string
	}{
		{"inventory-debian.txt", "Debian GNU/Linux 13", "dpkg", "apt", "3.0.4"},
		{"inventory-fedora.txt", "Fedora Linux 42", "rpm", "setup", "2.15.0-13.fc42"},
		{"inventory-alpine.txt", "Alpine Linux 3.22", "apk", "alpine-baselayout", "3.7.0-r0"},
	} {
		out, err := os.ReadFile("testdata/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		inv, err := ParseInventory(out)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if !strings.HasPrefix(inv.OS, c.os) || len(inv.Packages) < 10 {
			t.Errorf("%s: os %q, %d packages", c.file, inv.OS, len(inv.Packages))
		}
		found := false
		for _, p := range inv.Packages {
			if p.Manager != c.manager {
				t.Errorf("%s: package %s from manager %s", c.file, p.Name, p.Manager)
			}
			found = found || (p.Name == c.name && p.Version == c.version)
		}
		if !found {
			t.Errorf("%s: %s %s not found", c.file, c.name, c.version)
		}
	}
}

func TestParseInventoryRejects(t *testing.T) {
	for name, out := range map[string]string{
		"no header":  "Welcome to my shell\n@@end\n",
		"cut off":    "varde-inventory 1\n@@dpkg\nii  apt  3.0.4  amd64  x\n",
		"other tool": "",
	} {
		if _, err := ParseInventory([]byte(out)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Hostile lines are skipped, not trusted: removed packages, overlong
	// fields, units that are not services.
	out := "varde-inventory 1\n@@hostname\nweb 1\n@@dpkg\nrc  old  1.0  amd64  removed\nii  " + strings.Repeat("x", 300) + "  1.0  amd64  long\n" +
		"ii  nginx:amd64  1.26.3-3+deb13u1  amd64  web\n@@systemd\nfoo.socket loaded active running x\nnginx.service loaded active running nginx\n@@end\n"
	inv, err := ParseInventory([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Hostname != "" || len(inv.Packages) != 1 || inv.Packages[0].Name != "nginx" || len(inv.Services) != 1 || inv.Services[0].Unit != "nginx.service" {
		t.Errorf("parsed %+v", inv)
	}
}

const testInventoryCatalog = `id: jellyfin
name: Jellyfin
homepage: https://jellyfin.org
packages:
  - {manager: dpkg, name: jellyfin-server, versioning: upstream, version_pattern: '^(?P<v>\d+\.\d+\.\d+)\+'}
services:
  - {unit: jellyfin.service}
version: {scheme: semver}
advisories: {coverage: full, github_repos: [jellyfin/jellyfin]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-09
`

const testDistroCatalog = `id: nginx-test
name: nginx
homepage: https://nginx.org
packages:
  - {manager: dpkg, name: nginx}
services:
  - {unit: nginx.service}
version: {scheme: semver}
advisories: {coverage: limited, cpe: ['cpe:2.3:a:f5:nginx']}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-09
`

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load(fstest.MapFS{
		"jellyfin.yaml": {Data: []byte(testInventoryCatalog)},
		"nginx.yaml":    {Data: []byte(testDistroCatalog)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// Only catalog apps are kept; a service of an app read as a package is not
// kept twice. A vendor package yields a comparable version, a distribution
// package never does (backports, ADR 0008).
func TestInventoryWorkloadsAndIdentification(t *testing.T) {
	cat := testCatalog(t)
	inv := HostInventory{
		Packages: []inventory.Package{
			{Manager: "dpkg", Name: "jellyfin-server", Version: "10.11.2+deb13"},
			{Manager: "dpkg", Name: "nginx", Version: "1.26.3-3+deb13u1"},
			{Manager: "dpkg", Name: "libc6", Version: "2.41-12"},
		},
		Services: []inventory.Service{{Unit: "jellyfin.service", Active: true}, {Unit: "cron.service"}},
	}
	pkgs, svcs, unmatched := InventoryWorkloads(cat, inv)
	if len(pkgs) != 2 || len(svcs) != 0 || unmatched != 1 {
		t.Fatalf("kept %d packages, %d services, %d unmatched", len(pkgs), len(svcs), unmatched)
	}
	got := map[string]identify.Result{}
	for _, w := range pkgs {
		got[w.Package.Name] = identify.Identify(cat, w)
	}
	if r := got["jellyfin-server"]; r.AppID != "jellyfin" || r.Confidence != identify.Exact || r.Version != "10.11.2" {
		t.Errorf("vendor package: %+v", r)
	}
	if r := got["nginx"]; r.AppID != "nginx-test" || r.Version != "" || !strings.Contains(r.Note, "distribution package") {
		t.Errorf("distribution package compared with upstream ranges: %+v", r)
	}
	// A unit alone identifies the app, without a version.
	_, svcs, _ = InventoryWorkloads(cat, HostInventory{Services: []inventory.Service{{Unit: "jellyfin.service"}}})
	if len(svcs) != 1 {
		t.Fatal("service of an app without its package not kept")
	}
	if r := identify.Identify(cat, svcs[0]); r.AppID != "jellyfin" || r.Confidence != identify.Strong || r.Version != "" {
		t.Errorf("service: %+v", r)
	}
}

func TestInventoryLine(t *testing.T) {
	m, _ := newManager(t)
	line := m.InventoryIdentity().InventoryLine()
	if !strings.HasPrefix(line, `restrict,command="sh -c '`) || strings.Count(line, `"`) != 2 {
		t.Errorf("key line must force the command and hold no further double quotes: %s", line)
	}
	if m.InventoryIdentity().publicKey() == m.Identity().publicKey() {
		t.Error("inventory and Docker share one key; a host could only force one command")
	}
}

func TestSSHInventoryEndToEnd(t *testing.T) {
	cat := testCatalog(t)
	m, st := newManager(t)
	m.o.Catalog = func() *catalog.Catalog { return cat }
	srv := newSSHDocker(t, m.InventoryIdentity().Signer.PublicKey())
	srv.inventory = []byte("varde-inventory 1\n@@hostname\nmedia\n@@os-release\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\n@@dpkg\n" +
		"ii  jellyfin-server  10.11.2+deb13  amd64  Jellyfin\nii  libc6  2.41-12  amd64  libc\n@@rpm\n\n@@apk\n@@systemd\n" +
		"jellyfin.service loaded active running Jellyfin\n@@end\n")
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

	in, status, err := m.AddSSHInventory(t.Context(), cfg, "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if status.Packages != 2 || status.Apps != 1 || status.OS != "Debian GNU/Linux 13" {
		t.Errorf("status %+v", status)
	}
	h, err := st.Host(t.Context(), "sshinv-"+in.ID)
	if err != nil || h.Name != "media" || h.Source != inventory.SourceSSHInventory || h.IntegrationID != in.ID {
		t.Fatalf("host %+v %v", h, err)
	}
	ws, _ := st.Workloads(t.Context(), store.WorkloadFilter{HostID: h.ID})
	if len(ws) != 1 || ws[0].Kind != inventory.KindPackage || ws[0].Package.Name != "jellyfin-server" {
		t.Errorf("workloads %+v", ws)
	}
	// The client only ever asks for the inventory command.
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, c := range srv.cmds {
		if c != "varde-inventory" {
			t.Errorf("Varde ran %q", c)
		}
	}
}

func TestParseInventoryIdentity(t *testing.T) {
	out := "varde-inventory 1\n@@hostname\nweb\n@@machine-id\n0123456789abcdef0123456789abcdef\n@@mac\n00:00:00:00:00:00\nBC:24:11:AA:BB:CC\nnot-a-mac\n" +
		"@@os-release\nID=debian\nVERSION_ID=\"13\"\n@@dpkg\nii  curl  8.14.1-2  amd64  x\n@@end\n"
	inv, err := ParseInventory([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if inv.MachineID != "0123456789abcdef0123456789abcdef" || len(inv.MACs) != 1 || inv.MACs[0] != "bc:24:11:aa:bb:cc" || inv.Distro != "debian-13" {
		t.Errorf("identity %+v", inv)
	}
	if len(inv.Packages) != 1 || inv.Packages[0].Distro != "debian-13" {
		t.Errorf("packages %+v", inv.Packages)
	}
}
