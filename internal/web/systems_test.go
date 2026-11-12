// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
)

// The systems list answers per machine what is installed, what is
// affected and where Varde knows it from; a guest follows its node.
func TestSystemsList(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	addFinding(t, h, "c1", "P1")
	if err := h.store.SetHostPackages(ctx, store.HostPackages{HostID: "local", Distro: "debian-13", Read: now, Packages: []inventory.Package{
		{Manager: "dpkg", Name: "bash", Version: "5.2.37-2"}, {Manager: "dpkg", Name: "libssl3t64", Version: "3.5.1-1", Source: "openssl"},
	}}); err != nil {
		t.Fatal(err)
	}
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "pve-a-node-pve1", Name: "pve1", Kind: inventory.HostBareMetal, Source: inventory.SourceProxmox,
		Addresses: []string{"10.0.0.2"}, LastContact: now})
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "pve-a-201", Name: "guest-lxc", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox,
		Addresses: []string{"10.0.0.21"}, ParentID: "pve-a-node-pve1", LastContact: now})

	resp, body := h.do(t, "GET", "/systems", nil, nil)
	body = html.UnescapeString(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	nas := rowOf(t, body, "nas")
	for _, want := range []string{"2 packages", "1 container", "1 urgent", "Docker on this server"} {
		if !strings.Contains(nas, want) {
			t.Errorf("nas row lacks %q:\n%s", want, nas)
		}
	}
	guest := rowOf(t, body, "guest-lxc")
	if !strings.Contains(guest, "row--guest") || !strings.Contains(guest, "unknown") || !strings.Contains(guest, "How to read it") {
		t.Errorf("guest row:\n%s", guest)
	}
	if strings.Index(body, ">pve1</a>") > strings.Index(body, ">guest-lxc</a>") {
		t.Error("the guest is listed before its node")
	}
	// One number for "read", here and on the overview.
	if !strings.Contains(body, "Varde knows what is installed on 1 of 3 systems") {
		t.Error("read count missing")
	}
	if _, body := h.do(t, "GET", "/", nil, nil); !strings.Contains(body, `1 of 3 systems</a>`) {
		t.Error("overview counts differently")
	}
	// Area navigation: five entries, Systems current, its tabs shown.
	for _, want := range []string{`href="/systems" aria-current="page">Systems</a>`, `href="/connections" >Connections</a>`, `href="/systems/apps">Apps and containers</a>`, `href="/systems/gaps">Gaps</a>`} {
		if !strings.Contains(body, want) {
			t.Errorf("navigation lacks %s", want)
		}
	}
	for _, gone := range []string{`>Inventory</a>`, `>Coverage</a>`, `>Hosts</a>`, `>Sources</a>`, `>Network</a>`} {
		if strings.Contains(body, gone) {
			t.Errorf("old navigation entry %s still shown", gone)
		}
	}
}

// rowOf returns the table row that links the named system.
func rowOf(t *testing.T, body, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<tr[^>]*>\s*<td data-label="System"><a href="/systems/[^"]+">` + regexp.QuoteMeta(name) + `</a>.*?</tr>`).FindString(body)
	if m == "" {
		t.Fatalf("no row for %s", name)
	}
	return m
}

// Pages of earlier versions lead to their new place, with query and method.
func TestMovedPages(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	for old, want := range map[string]string{
		"/hosts":                      "/systems",
		"/inventory":                  "/systems/apps",
		"/coverage?x=1":               "/systems/gaps?x=1",
		"/network":                    "/connections",
		"/network/connect/docker?a=1": "/connections/connect/docker?a=1",
		"/sources":                    "/settings/sources",
		"/hosts/agent/install?a=1":    "/connections/agents/install?a=1",
	} {
		resp, _ := h.do(t, "GET", old, nil, nil)
		if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != want {
			t.Errorf("%s: %d %q, want %q", old, resp.StatusCode, resp.Header.Get("Location"), want)
		}
	}
	for old, want := range map[string]string{
		"/hosts/enroll":          "/connections/agents/tokens",
		"/hosts/enroll/x/delete": "/connections/agents/tokens/x/delete",
		"/hosts/abc/revoke":      "/connections/agents/abc/revoke",
		"/inventory/manual":      "/systems/apps/manual",
		"/network/scope":         "/connections/scope",
	} {
		resp, _ := h.do(t, "POST", old, url.Values{"csrf": {csrf}}, nil)
		if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want {
			t.Errorf("POST %s: %d %q, want %q", old, resp.StatusCode, resp.Header.Get("Location"), want)
		}
	}
	// A stored host ID (the agents list links them) leads to its system,
	// which carries the asset ID once identities are assigned.
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	if err := coverage.RefreshAssets(ctx, h.store, discovery.Scope{}, now, func(string) time.Duration { return time.Hour }); err != nil {
		t.Fatal(err)
	}
	resp, _ := h.do(t, "GET", "/systems/local", nil, nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/systems/") || resp.Header.Get("Location") == "/systems/local" {
		t.Errorf("host ID: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// A fresh Varde leads through the steps instead of claiming all is clear;
// after a scan the next step names the found Linux hosts.
func TestOverviewGuide(t *testing.T) {
	var set *settings.Service
	h := newHarness(t, withNetwork(t), withAgentBinaries(t), func(d *Deps) { set = d.Settings })
	h.signIn(t)
	_, body := h.do(t, "GET", "/", nil, nil)
	body = html.UnescapeString(body)
	for _, want := range []string{"Varde does not know your systems yet", "Allow your networks", `aria-current="step"`, `href="/connections#scope">Allow a network</a>`} {
		if !strings.Contains(body, want) {
			t.Errorf("empty overview lacks %q", want)
		}
	}
	if strings.Contains(body, "All clear") || strings.Contains(body, "No notification channel is configured") {
		t.Error("empty overview claims all clear or repeats the banner")
	}
	ctx, now := t.Context(), time.Now()
	if err := set.Update(ctx, map[string]string{settings.KeyNetworks: "10.10.1.0/24"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	_ = h.store.RecordDevices(ctx, []discovery.Device{
		{Address: "10.10.1.11", Kind: discovery.KindSSH, Label: "Linux host (Ubuntu)", Services: []discovery.Service{{Port: 22, Proto: discovery.ProtoSSH}}},
		{Address: "10.10.1.12", Kind: discovery.KindSSH, Label: "Linux host (Ubuntu)", Services: []discovery.Service{{Port: 22, Proto: discovery.ProtoSSH}}},
		{Address: "10.10.1.2", Kind: discovery.KindProxmox, Label: "Proxmox VE", Services: []discovery.Service{{Port: 22, Proto: discovery.ProtoSSH}, {Port: 8006, Proto: discovery.ProtoHTTPS}}},
	}, nil, now)
	_, body = h.do(t, "GET", "/", nil, nil)
	body = html.UnescapeString(body)
	if !strings.Contains(body, "Varde found 2 Linux hosts") || !strings.Contains(body, `/connections/agents/install?address=10.10.1.11&address=10.10.1.12">Install the agent on 2 hosts</a>`) {
		t.Errorf("next step does not name the found hosts:\n%s", body)
	}
	if !strings.Contains(body, "3 devices</a> found in the network") {
		t.Error("coverage contradicts the scan")
	}
	// The found hosts offer the agent first.
	_, body = h.do(t, "GET", "/connections", nil, nil)
	if !strings.Contains(body, `/connections/agents/install?address=10.10.1.11">Install the agent</a>`) {
		t.Error("device row does not recommend the agent")
	}
	// One host reads through its agent; the other, whose agent did not get
	// through, stays offered instead of the step counting as done.
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "a1", Name: "one", Kind: inventory.HostLinux, Source: inventory.SourceAgent,
		Addresses: []string{"10.10.1.11"}, LastContact: now, State: inventory.HostActive}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetHostPackages(ctx, store.HostPackages{HostID: "a1", Distro: "debian-12", Read: now,
		Packages: []inventory.Package{{Manager: "dpkg", Name: "bash", Version: "5.2.15-2+b2"}}}); err != nil {
		t.Fatal(err)
	}
	_, body = h.do(t, "GET", "/", nil, nil)
	body = html.UnescapeString(body)
	if !strings.Contains(body, "1 Linux host still reports nothing") || !strings.Contains(body, `/connections/agents/install?address=10.10.1.12">Install the agent on 1 host</a>`) {
		t.Errorf("the host left without an agent is no longer offered:\n%s", body)
	}
}

// Recognised platforms offer their connection or say how Varde reads them.
func TestDeviceOffers(t *testing.T) {
	var set *settings.Service
	h := newHarness(t, withNetwork(t), withAgentBinaries(t), func(d *Deps) { set = d.Settings })
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := set.Update(ctx, map[string]string{settings.KeyNetworks: "10.10.1.0/24"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	_ = h.store.RecordDevices(ctx, []discovery.Device{
		{Address: "10.10.1.1", Kind: discovery.KindNetwork, Label: "UniFi OS (gateway or console)", Services: []discovery.Service{{Port: 443, Proto: discovery.ProtoHTTPS, Product: "UniFi OS"}}},
		{Address: "10.10.1.3", Kind: discovery.KindPortainer, Label: "Portainer", Services: []discovery.Service{{Port: 22, Proto: discovery.ProtoSSH}, {Port: 9443, Proto: discovery.ProtoHTTPS, Product: "Portainer"}}},
		{Address: "10.10.1.5", Kind: discovery.KindNAS, Label: "Synology NAS", Services: []discovery.Service{{Port: 5001, Proto: discovery.ProtoHTTPS, Product: "Synology DSM"}}},
	}, nil, now)
	_, body := h.do(t, "GET", "/connections", nil, nil)
	if !strings.Contains(body, `/connections/connect/synology?address=10.10.1.5">Connect Synology DSM</a>`) {
		t.Error("Synology not offered")
	}
	if resp, body := h.do(t, "GET", "/connections/connect/synology?address=10.10.1.5", nil, nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, "without two-factor") {
		t.Errorf("Synology setup: %d", resp.StatusCode)
	}
	if !strings.Contains(body, `/connections/connect/unifi?address=10.10.1.1">Connect UniFi</a>`) {
		t.Error("UniFi not offered")
	}
	if !strings.Contains(body, "Portainer manages Docker here") || !strings.Contains(body, `/connections/agents/install?address=10.10.1.3">Install the agent</a>`) {
		t.Error("Portainer host without hint or agent")
	}
	if resp, body := h.do(t, "GET", "/connections/connect/unifi?address=10.10.1.1", nil, nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, "no read-only keys") || strings.Contains(body, "View Only") {
		t.Errorf("UniFi setup: %d", resp.StatusCode)
	}
}

// Behind an HTTPS proxy Varde does not trust, the pages say which proxy to
// trust instead of only "not encrypted"; the setup page says where the
// token is.
func TestProxyAndSetupHints(t *testing.T) {
	h := newHarness(t)
	_, body := h.do(t, "GET", "/setup", nil, map[string]string{"X-Forwarded-Proto": "https"})
	body = html.UnescapeString(body)
	for _, want := range []string{"VARDE_TRUSTED_PROXIES=127.0.0.1", "findstr setup_token", "Select-String setup_token", "grep setup_token", "Restart Varde"} {
		if !strings.Contains(body, want) {
			t.Errorf("setup page lacks %q", want)
		}
	}
	_, body = h.do(t, "GET", "/setup", nil, nil)
	if strings.Contains(body, "VARDE_TRUSTED_PROXIES") {
		t.Error("proxy hint without a proxy")
	}
}

// System packages are not apps: their findings count on the system, they
// are named as packages, and they do not fill the apps list or the gaps.
func TestSystemPackageFindingsShown(t *testing.T) {
	var set *settings.Service
	h := newHarness(t, func(d *Deps) { set = d.Settings })
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "web", Name: "web", Kind: inventory.HostLinux, Source: inventory.SourceAgent, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "web", inventory.KindPackage, []inventory.Workload{{
		Kind: inventory.KindPackage, RuntimeID: "os:dpkg:openssl", Name: "openssl",
		Package: &inventory.Package{Manager: "dpkg", Name: "openssl", Version: "3.5.1-1", Distro: "debian-13", Source: "openssl", System: true},
	}}, now)
	wid := inventory.WorkloadID("web", inventory.KindPackage, "os:dpkg:openssl")
	app := "os:Debian:13/openssl"
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: app, AdvisoryID: "DEBIAN-CVE-2026-1", MatchState: "affected", FixedIn: "3.5.1-1+deb13u1"}}, now); err != nil {
		t.Fatal(err)
	}
	_ = h.store.SetAssessments(ctx, []store.Assessment{{ID: store.FindingID(wid, "DEBIAN-CVE-2026-1"), Priority: "P3", Exposure: "unknown"}})
	_, body := h.do(t, "GET", "/systems", nil, nil)
	if row := rowOf(t, html.UnescapeString(body), "web"); !strings.Contains(row, "1 P3") {
		t.Errorf("system row does not count the package finding:\n%s", row)
	}
	_, body = h.do(t, "GET", "/findings", nil, nil)
	if !strings.Contains(body, "openssl (Debian 13 package)") {
		t.Error("finding not named as a package")
	}
	// Open issues without a fix show on the system page as information,
	// once the packages are checked.
	if err := h.store.ReplaceIdentifications(ctx, []identify.Result{{WorkloadID: wid, AppID: app, Confidence: identify.Exact, Unfixed: 3}}, now); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetHostPackages(ctx, store.HostPackages{HostID: "web", Distro: "debian-13", Read: now, Packages: []inventory.Package{
		{Manager: "dpkg", Name: "libssl3t64", Version: "3.5.1-1", Source: "openssl"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := set.Update(ctx, map[string]string{settings.KeyDirectOSV: "true"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	_, body = h.do(t, "GET", "/systems", nil, nil)
	m := regexp.MustCompile(`href="(/systems/[^"#]+)">web</a>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("system not linked")
	}
	_, body = h.do(t, "GET", m[1], nil, nil)
	if !strings.Contains(body, "3 without fix") || !strings.Contains(body, "3 known issues have no fix from the distribution yet") {
		t.Error("unfixed issues not shown")
	}
	for _, path := range []string{"/systems/apps", "/systems/gaps"} {
		if _, body := h.do(t, "GET", path, nil, nil); strings.Contains(body, ">openssl<") || strings.Contains(body, "os:dpkg:openssl") {
			t.Errorf("%s lists the system package", path)
		}
	}
}

// A distribution package's group names the update: the newest fixed
// version, compared in the package manager's order.
func TestDistroTarget(t *testing.T) {
	g := findingGroup{Rows: []findingRow{
		{MatchState: "affected", FixedIn: "2.36-9+deb12u3"},
		{MatchState: "affected", FixedIn: "2.36-9+deb12u14"},
		{MatchState: "affected", FixedIn: "2.36-9+deb12u4"},
		{MatchState: "unverified", FixedIn: "2.36-9+deb12u99"},
	}}
	tg := distroTarget(g, "Debian:12")
	if tg == nil || tg.Version != "2.36-9+deb12u14" || tg.Fixes != 3 || tg.Total != 3 {
		t.Fatalf("target %+v", tg)
	}
	if distroTarget(g, "") != nil {
		t.Fatal("target without an ecosystem")
	}
}

// The link of a grouped digest opens the package's findings.
func TestFindingsFilterBySystemPackage(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "web", Name: "web", Kind: inventory.HostLinux, Source: inventory.SourceAgent, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "web", inventory.KindPackage, []inventory.Workload{{
		Kind: inventory.KindPackage, RuntimeID: "os:dpkg:glibc", Name: "glibc",
		Package: &inventory.Package{Manager: "dpkg", Name: "glibc", Version: "2.36-9", Distro: "debian-12", Source: "glibc", System: true},
	}}, now)
	wid := inventory.WorkloadID("web", inventory.KindPackage, "os:dpkg:glibc")
	_, _ = h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "os:Debian:12/glibc", AdvisoryID: "DEBIAN-CVE-2023-4911", MatchState: "affected", FixedIn: "2.36-9+deb12u3"}}, now)
	_, body := h.do(t, "GET", "/findings?app=os%3ADebian%3A12%2Fglibc", nil, nil)
	if !strings.Contains(body, "DEBIAN-CVE-2023-4911") {
		t.Error("filtered findings miss the package's finding")
	}
}

// A package finding in a container's image asks for a newer image.
func TestImageFindingGroup(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "nas", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "nas", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich_server",
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}}}, now)
	wid := inventory.WorkloadID("nas", inventory.KindContainer, "c1")
	detail := map[string]any{"advisory_id": "DEBIAN-CVE-2023-4911", "match_state": "affected", "fixed_in": "2.36-9+deb12u3", "image": true,
		"evidence": map[string]any{"version": "2.36-9"}}
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "os:Debian:12/glibc", AdvisoryID: "DEBIAN-CVE-2023-4911",
		MatchState: "affected", FixedIn: "2.36-9+deb12u3", Detail: detail}}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/findings", nil, nil)
	if !strings.Contains(body, "Pull a newer image whose") || !strings.Contains(body, "glibc (Debian 12 package)") {
		t.Errorf("image finding without the image action:\n%s", body)
	}
}

// A host whose updates wait for a restart says so in the list, on its page
// and on the overview.
func TestRestartNeeded(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "web", Name: "web", Kind: inventory.HostLinux, Source: inventory.SourceAgent, LastContact: now})
	if err := h.store.SetHostPackages(ctx, store.HostPackages{HostID: "web", Distro: "debian-12", Read: now, Kernel: "6.1.0-25-amd64",
		Reboot:   "kernel 6.1.0-28-amd64 is installed, 6.1.0-25-amd64 is running",
		Packages: []inventory.Package{{Manager: "dpkg", Name: "linux-image-6.1.0-28-amd64", Version: "6.1.119-1"}}}); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems", nil, nil)
	if !strings.Contains(rowOf(t, body, "web"), "restart needed") {
		t.Error("list without the restart badge")
	}
	m := regexp.MustCompile(`href="(/systems/[^"#]+)">web</a>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("system not linked")
	}
	_, body = h.do(t, "GET", m[1], nil, nil)
	if !strings.Contains(body, "Restart needed.") || !strings.Contains(body, "6.1.0-25-amd64") {
		t.Error("page without the restart banner or kernel")
	}
	_, body = h.do(t, "GET", "/", nil, nil)
	if !strings.Contains(body, "Waiting for a restart") || !strings.Contains(body, "kernel 6.1.0-28-amd64 is installed") {
		t.Error("overview without the restart panel")
	}
}

// Once Varde has something to show, the setup guide is one line under the
// numbers, not a block above them, and the user can hide it.
func TestSetupReminderCompactAndHideable(t *testing.T) {
	h := newHarness(t, withNetwork(t), withAgentBinaries(t))
	csrf := h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}},
	}, now)
	_, body := h.do(t, "GET", "/", nil, nil)
	if strings.Contains(body, "Finish getting started") || strings.Contains(body, `class="panel guide"`) {
		t.Error("the full guide is shown although Varde has something to show")
	}
	setup, stats := strings.Index(body, `<details class="panel setup"`), strings.Index(body, `class="stats"`)
	if setup < 0 || stats < 0 || setup < stats {
		t.Fatalf("the setup reminder is missing or above the numbers (setup %d, stats %d)", setup, stats)
	}
	if !strings.Contains(body, "Setup: ") || !strings.Contains(body, "Next: Allow your networks") || !strings.Contains(body, `action="/setup-guide/hide"`) {
		t.Error("the reminder does not name what is left or cannot be hidden")
	}
	if resp, _ := h.do(t, "POST", "/setup-guide/hide", url.Values{"csrf": {csrf}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("hide: %d", resp.StatusCode)
	}
	_, body = h.do(t, "GET", "/", nil, nil)
	if strings.Contains(body, `<details class="panel setup"`) || !strings.Contains(body, `action="/setup-guide/show"`) || !strings.Contains(body, "left, hidden") {
		t.Error("hidden reminder still shown, or no way to bring it back")
	}
	if resp, _ := h.do(t, "POST", "/setup-guide/show", url.Values{"csrf": {csrf}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("show: %d", resp.StatusCode)
	}
	if _, body = h.do(t, "GET", "/", nil, nil); !strings.Contains(body, `<details class="panel setup"`) {
		t.Error("reminder not back after show")
	}
}

// While advisory data is still being fetched, every page says that what it
// shows is not yet everything.
func TestCatchingUpNotice(t *testing.T) {
	busy, limited, failed := true, false, false
	h := newHarness(t, func(d *Deps) { d.CatchingUp = func() (bool, bool, bool) { return busy, limited, failed } })
	h.signIn(t)
	for _, path := range []string{"/", "/findings", "/systems/gaps"} {
		if _, body := h.do(t, "GET", path, nil, nil); !strings.Contains(body, "Findings and versions keep arriving") || !strings.Contains(body, "goes away by itself") {
			t.Errorf("%s does not say that data is still arriving", path)
		}
	}
	limited = true
	if _, body := h.do(t, "GET", "/", nil, nil); !strings.Contains(body, "limits how many requests") {
		t.Error("a rate limit is not named")
	}
	limited, failed = false, true
	if _, body := h.do(t, "GET", "/", nil, nil); !strings.Contains(body, "answered with an error") || strings.Contains(body, "goes away by itself") {
		t.Error("a failed source is not named, or the notice promises to go away")
	}
	busy, failed = false, false
	if _, body := h.do(t, "GET", "/", nil, nil); strings.Contains(body, "keep arriving") {
		t.Error("the notice stays after the data is complete")
	}
}

// The advisory data page says per app what it is compared with and how
// much is known, instead of leaving one line "feed" for the whole package.
func TestAdvisoryDataPerApp(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}},
	}, now)
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	if err := h.store.ReplaceIdentifications(ctx, []identify.Result{{WorkloadID: wid, AppID: "immich", Confidence: identify.Exact, Version: "1.120.0"}}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/settings/sources", nil, nil)
	body = html.UnescapeString(body)
	for _, want := range []string{"What Varde knows for your apps", "Immich", "advisories of github.com/immich-app/immich", "none published", "Requests Varde sends"} {
		if !strings.Contains(body, want) {
			t.Errorf("advisory data page lacks %q", want)
		}
	}
}

// An app whose only source is switched off is not "compared, none
// published": the page says that it is not checked and which switch does it.
func TestAdvisoryDataNamesSwitchedOffSources(t *testing.T) {
	cat, err := catalog.Load(fstest.MapFS{"pg.yaml": {Data: []byte(`id: postgresql
name: PostgreSQL
homepage: https://www.postgresql.org
images: [{match: library/postgres}]
version: {scheme: semver}
advisories: {coverage: limited, cpe: ["cpe:2.3:a:postgresql:postgresql"]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-12
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var set *settings.Service
	h := newHarness(t, func(d *Deps) { d.Catalog = catalog.NewLive(cat); set = d.Settings })
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "db", Container: &inventory.Container{ImageRef: "postgres:16.4"}},
	}, now)
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	if err := h.store.ReplaceIdentifications(ctx, []identify.Result{{WorkloadID: wid, AppID: "postgresql", Confidence: identify.Exact, Version: "16.4"}}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/settings/sources", nil, nil)
	body = html.UnescapeString(body)
	if !strings.Contains(body, "not checked") || !strings.Contains(body, "the NVD, which is switched off") || strings.Contains(body, "none published") {
		t.Errorf("an app whose only source is off is shown as compared:\n%s", body)
	}
	if err := set.Update(ctx, map[string]string{settings.KeyDirectNVD: "true"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	_, body = h.do(t, "GET", "/settings/sources", nil, nil)
	body = html.UnescapeString(body)
	if !strings.Contains(body, "none published") || strings.Contains(body, "switched off") {
		t.Errorf("with the NVD on the app counts as compared:\n%s", body)
	}
}
