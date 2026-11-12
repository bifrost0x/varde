// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/exposure"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/store"
)

// A host listening on SSH with a remote flaw in OpenSSH and a local one in
// the kernel: the LAN path goes through SSH to root, while the remote flaw
// in CUPS, which does not listen, is background noise (ADR 0034).
func TestAttackPathsFromListeners(t *testing.T) {
	ctx := t.Context()
	cat, err := catalog.Load(fstest.MapFS{"immich.yaml": {Data: []byte(entry)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	if err := st.UpsertHost(ctx, inventory.Host{ID: "web", Name: "web", Kind: inventory.HostLinux, Source: inventory.SourceAgent, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	pkg := func(name, version string) inventory.Package {
		return inventory.Package{Manager: "dpkg", Name: name, Version: version, Distro: "debian-13", Source: name, System: true}
	}
	pkgs := []inventory.Package{pkg("openssh", "1:10.0p1-1"), pkg("cups", "2.4.10-1"), pkg("linux", "6.12.1-1")}
	var ws []inventory.Workload
	for _, p := range pkgs {
		ws = append(ws, inventory.Workload{Kind: inventory.KindPackage, RuntimeID: "os:dpkg:" + p.Name, Name: p.Name, Package: &p})
	}
	if _, err := st.ApplySnapshot(ctx, "web", inventory.KindPackage, ws, now); err != nil {
		t.Fatal(err)
	}
	if err := st.SetHostPackages(ctx, store.HostPackages{HostID: "web", Distro: "debian-13", Packages: pkgs, Read: now,
		Listen: []inventory.Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 22}, {Proto: "tcp", Address: "127.0.0.1", Port: 631}}}); err != nil {
		t.Fatal(err)
	}
	rec := func(id, name, fixed, vector string, score float64) store.AdvisoryRecord {
		return store.AdvisoryRecord{Source: match.SourceDistro, CVSS: score, Vuln: advisory.Vulnerability{ID: id, Modified: now,
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vector}},
			Affected: []advisory.Affected{{Package: advisory.Package{Ecosystem: "Debian:13", Name: name},
				Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}}}}}}
	}
	for name, r := range map[string]store.AdvisoryRecord{
		"openssh": rec("DEBIAN-CVE-2026-10", "openssh", "1:10.0p1-2", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
		"cups":    rec("DEBIAN-CVE-2026-11", "cups", "2.4.10-2", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
		"linux":   rec("DEBIAN-CVE-2026-12", "linux", "6.12.1-2", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
	} {
		if err := st.ReplaceAdvisories(ctx, distro.SystemAppID("Debian:13", name), match.SourceDistro, []store.AdvisoryRecord{r}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New(cat, st, slog.New(slog.DiscardHandler), Options{}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	fs, err := st.Findings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.Finding{}
	for _, f := range fs {
		got[f.AdvisoryID] = f
	}
	if f := got["DEBIAN-CVE-2026-10"]; f.PathClass != "path-lan" || f.Priority != "P2" {
		t.Errorf("openssh: %s %s %q", f.PathClass, f.Priority, f.PriorityReason)
	}
	if f := got["DEBIAN-CVE-2026-12"]; f.PathClass != "amplifier" || f.Priority != "P2" {
		t.Errorf("kernel: %s %s", f.PathClass, f.Priority)
	}
	// CUPS listens on loopback only: a CVSS 9.8 flaw nobody can reach.
	if f := got["DEBIAN-CVE-2026-11"]; f.PathClass != "noise" || f.Priority != "P3" || !strings.Contains(f.PathReason, "cups") {
		t.Errorf("cups: %s %s %q", f.PathClass, f.Priority, f.PathReason)
	}
	ps, err := st.Paths(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) == 0 || ps[0].Entry != paths.LAN || ps[0].Impact != "root on web" || !strings.Contains(ps[0].Steps[0].Label, "port 22/tcp") {
		t.Fatalf("paths: %+v", ps)
	}
}

func TestPathPriority(t *testing.T) {
	for _, c := range []struct {
		prio  policy.Priority
		class paths.Class
		m     match.Finding
		want  policy.Priority
	}{
		{policy.P2, paths.OnPathInternet, match.Finding{CVSS: 7.5}, policy.P1},
		{policy.P3, paths.OnPathInternet, match.Finding{CVSS: 5}, policy.P2},
		{policy.P3, paths.OnPathLAN, match.Finding{CVSS: 5}, policy.P2},
		{policy.P1, paths.OnPathLAN, match.Finding{KEV: true}, policy.P1},
		{policy.P2, paths.Noise, match.Finding{CVSS: 9.8}, policy.P3},
		// Known exploited stays in the noise only for physical access.
		{policy.P1, paths.Noise, match.Finding{KEV: true}, policy.P2},
		{policy.P2, paths.Unclear, match.Finding{CVSS: 8}, policy.P2},
		// A package of the image, nothing says it is exploited, no path:
		// the next regular update, unless the container is public.
		{policy.P2, paths.Unclear, match.Finding{CVSS: 8, Image: true}, policy.P3},
		{policy.P2, paths.Unclear, match.Finding{CVSS: 8, Image: true, EPSS: 0.2}, policy.P2},
		{policy.P1, paths.Unclear, match.Finding{CVSS: 9, Image: true, KEV: true}, policy.P1},
		{policy.None, paths.OnPathInternet, match.Finding{CVSS: 9}, policy.None},
	} {
		if got, _ := pathPriority(c.prio, "r", paths.Placement{Class: c.class, Reason: "x"}, c.m, inventory.ExposureLAN); got != c.want {
			t.Errorf("%s %s: got %s, want %s", c.prio, c.class, got, c.want)
		}
	}
}

func TestEscapeOf(t *testing.T) {
	for want, c := range map[string]*inventory.Container{
		"":                 {},
		"privileged":       {Runtime: &inventory.Runtime{Privileged: true}},
		"Docker socket":    {Mounts: []inventory.Mount{{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}}},
		"CAP_SYS_ADMIN":    {Runtime: &inventory.Runtime{CapAdd: []string{"NET_ADMIN", "SYS_ADMIN"}}},
		"host's processes": {Runtime: &inventory.Runtime{CapAdd: []string{"SYS_PTRACE"}, PidMode: "host"}},
		"root file system": {Mounts: []inventory.Mount{{Type: "bind", Source: "/", Destination: "/host"}}},
	} {
		got := escapeOf(c)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("want %q, got %q", want, got)
		}
	}
	if got := escapeOf(&inventory.Container{Runtime: &inventory.Runtime{CapAdd: []string{"SYS_PTRACE"}}}); got != "" {
		t.Errorf("ptrace without the host's processes: %q", got)
	}
}

func TestRouteVia(t *testing.T) {
	if got := routeVia([]string{"no published ports", "NPM route photos.example.com forwards to 10.0.0.5:2283"}); got != "photos.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := routeVia([]string{"traefik router old serves old.example.com"}); got != "old.example.com" {
		t.Fatalf("traefik: got %q", got)
	}
}

// Two containers behind routes, without published ports, are two entries.
func TestServiceSetKeepsContainersApart(t *testing.T) {
	s := serviceSet{seen: map[string]bool{}}
	s.add(paths.Service{MachineID: "m", Entry: paths.Internet, WorkloadID: "a"})
	s.add(paths.Service{MachineID: "m", Entry: paths.Internet, WorkloadID: "b"})
	s.add(paths.Service{MachineID: "m", Entry: paths.Internet, WorkloadID: "b"})
	if len(s.list) != 2 {
		t.Fatalf("services: %+v", s.list)
	}
}

// A container in another container's network takes over its exposure.
func TestContainerExposuresSharedNetwork(t *testing.T) {
	ws := []inventory.Workload{
		{ID: "vpn", HostID: "h", RuntimeID: strings.Repeat("a", 64), Name: "gluetun", Kind: inventory.KindContainer,
			Container: &inventory.Container{Ports: []inventory.Port{{PrivatePort: 8080, PublicPort: 8080}}}},
		{ID: "arr", HostID: "h", RuntimeID: strings.Repeat("b", 64), Name: "sonarr", Kind: inventory.KindContainer,
			Container: &inventory.Container{Runtime: &inventory.Runtime{NetworkMode: "container:" + strings.Repeat("a", 64)}}},
	}
	got := containerExposures(ws, exposure.New(exposure.Config{}))
	if got["arr"].Exposure != inventory.ExposureLAN || !strings.Contains(strings.Join(got["arr"].Evidence, ";"), "gluetun") {
		t.Fatalf("shared network: %+v", got["arr"])
	}
	if proxyRole(&inventory.Container{ImageRef: "jc21/nginx-proxy-manager:2.11.3"}) != "proxy" ||
		proxyRole(&inventory.Container{ImageRef: "cloudflare/cloudflared:2024.10.0"}) != "tunnel" ||
		proxyRole(&inventory.Container{ImageRef: "postgres:16"}) != "" {
		t.Fatal("proxy roles")
	}
}

func TestPathPriorityKeepsPublicImagePackages(t *testing.T) {
	// The exposure decides, not the wording of the policy's reason: a P2
	// "high severity" on a public container stays P2.
	for _, c := range []struct {
		prio   policy.Priority
		reason string
		cvss   float64
	}{{policy.P1, "critical severity and publicly exposed", 9.8}, {policy.P2, "high severity", 8.0}} {
		m := match.Finding{CVSS: c.cvss, Image: true}
		if got, _ := pathPriority(c.prio, c.reason, paths.Placement{Class: paths.Unclear, Reason: "x"}, m, inventory.ExposurePublic); got != c.prio {
			t.Errorf("public container, %s: got %s, want %s", c.reason, got, c.prio)
		}
	}
}
