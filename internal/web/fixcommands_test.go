// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"log/slog"
	"net/url"
	"regexp"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/pipeline"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/upstream"
)

// labWithLabels runs the CyberChef lab with a newer release that fixes a
// flaw of the image (v10.20.0), and other container labels.
func labWithLabels(t *testing.T, h *harness, labels map[string]string) string {
	t.Helper()
	cand := remedy.Candidate{Distro: "debian-12", Packages: []inventory.Package{debPkg("nginx", "1.22.1-9"), debPkg("openssl", "3.0.15-1~deb12u1"), debPkg("busybox", "1:1.35.0-4")}}
	b, err := upstream.EncodeCandidate(cand)
	if err != nil {
		t.Fatal(err)
	}
	chefLab(t, h, "mpepping/cyberchef:v10.19.0", "openssl",
		&store.UpstreamCheck{HeadDigest: runDigest, CandidateTag: "v10.20.0", CandidateDigest: newDigest, Candidate: b, CandidateReadAt: time.Now()})
	ctx := t.Context()
	ws, err := h.store.Workloads(ctx, store.WorkloadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	c := *ws[0].Container
	c.Labels = labels
	if _, err := h.store.ApplySnapshot(ctx, "docker", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: ws[0].Name, Container: &c}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return inventory.WorkloadID("docker", inventory.KindContainer, "c1")
}

func appPageText(t *testing.T, h *harness, id string) (string, string) {
	t.Helper()
	_, body := h.do(t, "GET", "/apps/"+id, nil, nil)
	return body, stripTags(html.UnescapeString(body))
}

// A Portainer stack is updated in Portainer: the page names the stack and
// the clicks, and no command for the host, whose shell would not reach
// Portainer's copy of the file.
func TestFixInPortainer(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	id := labWithLabels(t, h, map[string]string{"com.docker.compose.project": "cyberchef", "com.docker.compose.service": "cyber-chef",
		"com.docker.compose.project.working_dir": "/data/compose/7", "com.docker.compose.project.config_files": "/data/compose/7/docker-compose.yml"})
	body, text := appPageText(t, h, id)
	mustContain(t, "app page", text, "Stacks › cyberchef", "image: mpepping/cyberchef:v10.20.0", "Update the stack", "Re-pull image and redeploy")
	mustNotContain(t, "app page", body, "docker compose", "cd '/data/compose")
}

// Unraid's Docker manager: its own page and buttons.
func TestFixInUnraid(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	id := labWithLabels(t, h, map[string]string{"net.unraid.docker.managed": "dockerman"})
	body, text := appPageText(t, h, id)
	mustContain(t, "app page", text, "Unraid's Docker page", "Repository", "image: mpepping/cyberchef:v10.20.0")
	mustNotContain(t, "app page", body, "docker compose", "docker pull")
}

// A container started with docker run: the pull of the image, and no
// invented run command, since Varde does not see all its options.
func TestFixForDockerRun(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	id := labWithLabels(t, h, nil)
	body, text := appPageText(t, h, id)
	mustContain(t, "app page", text, "docker pull mpepping/cyberchef:v10.20.0", "Varde does not see all of them")
	mustNotContain(t, "app page", body, "docker compose", "docker run mpepping")
}

// A Compose service on a host: the exact command, and WebSSH to run it
// there once its address is set; before, a hint where to set it.
func TestFixComposeWithWebSSH(t *testing.T) {
	var set *settings.Service
	h := newHarness(t, func(d *Deps) { set = d.Settings })
	csrf := h.signIn(t)
	id := labWithLabels(t, h, map[string]string{"com.docker.compose.project": "chef", "com.docker.compose.service": "cyber-chef",
		"com.docker.compose.project.working_dir": "/srv/chef", "com.docker.compose.project.config_files": "/srv/chef/compose.yaml,/srv/chef/compose.tls.yaml"})
	body, text := appPageText(t, h, id)
	mustContain(t, "app page", text, "cd '/srv/chef' && docker compose -f 'compose.yaml' -f 'compose.tls.yaml' pull 'cyber-chef'", "Run it on docker")
	mustContain(t, "app page", body, `href="https://github.com/bifrost0x/webssh"`, `href="/settings#webssh"`)
	mustNotContain(t, "app page", body, "Copy and open WebSSH")

	// A URL WebSSH could not be: refused.
	if resp, _ := h.do(t, "POST", "/settings", url.Values{"csrf": {csrf}, "WEBSSH_URL": {"javascript:alert(1)"}}, nil); resp.StatusCode != 400 {
		t.Errorf("a javascript address was accepted: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "POST", "/settings", url.Values{"csrf": {csrf}, "WEBSSH_URL": {"https://webssh.example.lan"}}, nil); resp.StatusCode != 303 {
		t.Fatalf("saving the address: %d", resp.StatusCode)
	}
	if set.Get().WebSSHURL != "https://webssh.example.lan" {
		t.Fatalf("WebSSH address %q", set.Get().WebSSHURL)
	}
	body, _ = appPageText(t, h, id)
	mustContain(t, "app page", body, `href="https://webssh.example.lan" target="_blank" rel="noopener noreferrer" data-copy="#app-cmd"`, "Copy and open WebSSH")
}

// The packages of a system get the command that installs exactly their
// updates: the binary packages of each affected source package, and for
// the kernel the metapackage that brings the new one; for an LXC container
// also from its Proxmox node.
func TestHostFixCommand(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "pve-1-node-pve1", Name: "pve1", Kind: inventory.HostBareMetal, Source: inventory.SourceProxmox, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "pve-1-105", Name: "web", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, OS: "LXC container",
		ParentID: "pve-1-node-pve1", Addresses: []string{"192.168.1.5"}, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	pkg := func(name, source string) inventory.Workload {
		return inventory.Workload{Kind: inventory.KindPackage, RuntimeID: "os:dpkg:" + source, Name: source,
			Package: &inventory.Package{Manager: "dpkg", Name: name, Version: "1", Distro: "debian-12", Source: source, System: true}}
	}
	if _, err := h.store.ApplySnapshot(ctx, "pve-1-105", inventory.KindPackage, []inventory.Workload{pkg("openssl", "openssl"), pkg("linux-image-6.1.0-18-amd64", "linux")}, now); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetHostPackages(ctx, store.HostPackages{HostID: "pve-1-105", Distro: "debian-12", Read: now, Packages: []inventory.Package{
		{Manager: "dpkg", Name: "openssl", Version: "3.0.11-1~deb12u1", Source: "openssl"},
		{Manager: "dpkg", Name: "libssl3", Version: "3.0.11-1~deb12u1", Source: "openssl"},
		{Manager: "dpkg", Name: "curl", Version: "7.88.1-10", Source: "curl"},
		{Manager: "dpkg", Name: "linux-image-6.1.0-18-amd64", Version: "6.1.76-1", Source: "linux-signed-amd64"},
		{Manager: "dpkg", Name: "linux-image-amd64", Version: "6.1.76-1", Source: "linux-signed-amd64"},
	}}); err != nil {
		t.Fatal(err)
	}
	openssl := inventory.WorkloadID("pve-1-105", inventory.KindPackage, "os:dpkg:openssl")
	kernel := inventory.WorkloadID("pve-1-105", inventory.KindPackage, "os:dpkg:linux")
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{
		{WorkloadID: openssl, AppID: "os:Debian:12/openssl", AdvisoryID: "DEBIAN-CVE-2026-1", MatchState: "affected", FixedIn: "3.0.11-1~deb12u2"},
		{WorkloadID: kernel, AppID: "os:Debian:12/linux", AdvisoryID: "DEBIAN-CVE-2026-2", MatchState: "affected", FixedIn: "6.1.80-1"},
		// Without a fix: not for the command.
		{WorkloadID: openssl, AppID: "os:Debian:12/openssl", AdvisoryID: "DEBIAN-CVE-2026-3", MatchState: "affected"},
	}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems", nil, nil)
	m := regexp.MustCompile(`href="(/systems/[^"#]+)">web</a>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("system web not linked")
	}
	_, body = h.do(t, "GET", m[1], nil, nil)
	text := stripTags(html.UnescapeString(body))
	cmd := "apt-get update && apt-get install --only-upgrade libssl3 linux-image-6.1.0-18-amd64 linux-image-amd64 openssl"
	mustContain(t, "system page", text, "Install the security updates", "sudo sh -c '"+cmd+"'", "pct exec 105 -- sh -c '"+cmd+"'",
		"Proxmox node pve1", "takes effect after a restart", "Run it on web")
	mustNotContain(t, "system page", text, "curl'", " curl ")
}

// An app installed from its distribution's archive gets its package
// manager's command, to run on its system.
func TestFixForDistributionPackage(t *testing.T) {
	h := newHarness(t, withNginx(t))
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "ssh-web", Name: "web", Kind: inventory.HostLinux, Source: inventory.SourceSSHInventory,
		Addresses: []string{"192.168.1.7"}, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "ssh-web", inventory.KindPackage, []inventory.Workload{
		{Kind: inventory.KindPackage, RuntimeID: "dpkg:nginx", Name: "nginx", Package: &inventory.Package{Manager: "dpkg", Name: "nginx", Version: "1.22.1-9+deb12u2", Distro: "debian-12"}},
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := h.store.ReplaceAdvisories(ctx, "nginx", "vulndb", []store.AdvisoryRecord{debAdvisory("DEBIAN-CVE-2099-5", "CVE-2099-5", "nginx", "1.22.1-9+deb12u3")}, now); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(fstest.MapFS{"nginx.yaml": {Data: []byte(nginxEntry)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.New(cat, h.store, slog.New(slog.DiscardHandler), pipeline.Options{}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	_, text := appPageText(t, h, inventory.WorkloadID("ssh-web", inventory.KindPackage, "dpkg:nginx"))
	mustContain(t, "app page", text, "sudo sh -c 'apt-get update && apt-get install --only-upgrade nginx'", "Run it on web")
}

// A container read through the node's key: its package list is on the
// node inventory's record ("pvelxc-…"), which names no parent; the node is
// the address its integration connects to.
func TestHostFixNodeInventoryLXC(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.CreateIntegration(ctx, store.Integration{ID: "k1", Kind: "proxmox-lxc", Name: "pve", Address: "192.168.1.2", Enabled: true, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "pvelxc-k1-107", Name: "db", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceNodeInventory,
		OS: "Debian GNU/Linux 12", IntegrationID: "k1", LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "pvelxc-k1-107", inventory.KindPackage, []inventory.Workload{{Kind: inventory.KindPackage, RuntimeID: "os:dpkg:openssl", Name: "openssl",
		Package: &inventory.Package{Manager: "dpkg", Name: "openssl", Version: "1", Distro: "debian-12", Source: "openssl", System: true}}}, now); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetHostPackages(ctx, store.HostPackages{HostID: "pvelxc-k1-107", Distro: "debian-12", Read: now, Packages: []inventory.Package{
		{Manager: "dpkg", Name: "libssl3", Version: "1", Source: "openssl"}}}); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("pvelxc-k1-107", inventory.KindPackage, "os:dpkg:openssl")
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "os:Debian:12/openssl", AdvisoryID: "DEBIAN-CVE-2026-1", MatchState: "affected", FixedIn: "2"}}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems", nil, nil)
	m := regexp.MustCompile(`href="(/systems/[^"#]+)">db</a>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("system db not linked")
	}
	_, body = h.do(t, "GET", m[1], nil, nil)
	mustContain(t, "system page", stripTags(html.UnescapeString(body)), "pct exec 107 -- sh -c 'apt-get update && apt-get install --only-upgrade libssl3'", "Proxmox node 192.168.1.2")
}

// Without an update that fixes something, a Portainer or Unraid container
// is not sent to redeploy: the page gives the mitigation.
func TestNoRedeployWithoutFix(t *testing.T) {
	for _, labels := range []map[string]string{
		{"com.docker.compose.project": "chef", "com.docker.compose.service": "cyber-chef", "com.docker.compose.project.working_dir": "/data/compose/3"},
		{"net.unraid.docker.managed": "dockerman"},
	} {
		h := newHarness(t)
		h.signIn(t)
		chefLab(t, h, "mpepping/cyberchef:latest", "openssl", &store.UpstreamCheck{HeadDigest: runDigest})
		ctx := t.Context()
		ws, err := h.store.Workloads(ctx, store.WorkloadFilter{})
		if err != nil {
			t.Fatal(err)
		}
		c := *ws[0].Container
		c.Labels = labels
		if _, err := h.store.ApplySnapshot(ctx, "docker", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: ws[0].Name, Container: &c}}, time.Now()); err != nil {
			t.Fatal(err)
		}
		_, text := appPageText(t, h, inventory.WorkloadID("docker", inventory.KindContainer, "c1"))
		mustContain(t, "app page", text, "No fixed image upstream yet", "Limit who can reach it")
		mustNotContain(t, "app page", text, "Update the stack", "Force update")
	}
}

// Upper case is valid in a tag: the pull command stays.
func TestFitCommandUpperCaseTag(t *testing.T) {
	c := appCard{Platform: "run", Line: "image: registry.example/app:V1.2.3", Action: "Update to V1.2.3"}
	c.fitCommand()
	if c.Command != "docker pull registry.example/app:V1.2.3" {
		t.Errorf("command %q", c.Command)
	}
	c = appCard{Platform: "run", Line: "image: app:1; rm -rf /"}
	c.fitCommand()
	if c.Command != "" {
		t.Errorf("an invalid reference reached a command: %q", c.Command)
	}
}

// A package whose flaws are all snoozed still says what fixes them.
func TestReportSnoozedKeepsFixedVersion(t *testing.T) {
	ev := match.Evidence{Package: "Debian:12/vim", Version: "2:9.0-1"}
	a := reportFinding(t, "os:Debian:12/vim", "DEBIAN-CVE-2026-1", "2:9.0-1+deb12u2", match.Finding{Evidence: ev})
	b := reportFinding(t, "os:Debian:12/vim", "DEBIAN-CVE-2026-2", "2:9.0-1+deb12u10", match.Finding{Evidence: ev})
	a.State, b.State = store.StateSnoozed, store.StateSnoozed
	r := buildReport([]store.Finding{a, b}, "app")
	if r.Total != 0 || r.Snoozed != 2 || len(r.Packages) != 1 || r.Packages[0].FixedIn != "2:9.0-1+deb12u10" || r.Packages[0].Unfixed != 0 {
		t.Fatalf("report %+v", r)
	}
}

// When the only flaw a newer image fixes is snoozed, the card no longer
// sends the user to that image for the flaws left open.
func TestUpdateOnlyForOpenFlaws(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	id := labWithLabels(t, h, map[string]string{"com.docker.compose.project": "chef", "com.docker.compose.service": "cyber-chef"})
	mustContain(t, "card before", overviewCard(t, h), "Update to v10.20.0")
	if resp, _ := h.do(t, "POST", "/findings/"+store.FindingID(id, "DEBIAN-CVE-2099-2")+"/snooze", url.Values{"csrf": {csrf}, "days": {"7"}}, nil); resp.StatusCode != 303 {
		t.Fatalf("snooze: %d", resp.StatusCode)
	}
	card := overviewCard(t, h)
	mustContain(t, "card", card, "No fixed image for the open flaws yet")
	mustNotContain(t, "card", card, "Update to v10.20.0")
}
