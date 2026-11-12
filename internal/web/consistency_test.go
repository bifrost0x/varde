// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
)

// addFinding stores one affected finding with the given priority on a new
// container workload of the local host.
func addFinding(t *testing.T, h *harness, runtimeID, priority string) {
	t.Helper()
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: runtimeID, Name: "immich_" + runtimeID,
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, runtimeID)
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-" + runtimeID, MatchState: "affected", FixedIn: "1.121.0"}}, now); err != nil {
		t.Fatal(err)
	}
	id := store.FindingID(wid, "GHSA-"+runtimeID)
	if err := h.store.SetAssessments(ctx, []store.Assessment{{ID: id, Priority: priority, Exposure: "lan"}}); err != nil {
		t.Fatal(err)
	}
}

// New P2 and P3 findings are not "all clear": the overview used to say
// "No known vulnerability" while the counters below showed open findings.
func TestOverviewNotClearWithNewFindings(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	addFinding(t, h, "c1", "P2")
	_, body := h.do(t, "GET", "/", nil, nil)
	if strings.Contains(body, "All clear") || strings.Contains(body, "No known vulnerability") || strings.Contains(body, "hero--alert") {
		t.Fatalf("overview claims all clear with a new P2 finding:\n%s", body)
	}
	if !strings.Contains(body, "1 update to do, none urgent") || !strings.Contains(body, "daily digest") {
		t.Error("new non-urgent finding not named in the status")
	}
	// Acknowledging it leaves "Nothing new" with correct grammar.
	if err := h.store.Acknowledge(t.Context(), store.FindingID(inventory.WorkloadID("local", inventory.KindContainer, "c1"), "GHSA-c1"), time.Now()); err != nil {
		t.Fatal(err)
	}
	_, body = h.do(t, "GET", "/", nil, nil)
	if !strings.Contains(body, "Nothing new") || !strings.Contains(body, "is still open and no longer notifies") {
		t.Errorf("acknowledged state wrong:\n%s", body)
	}
}

// The overview and the sources page name the configured advisory mode
// instead of a fixed "direct".
func TestAdvisoryModeShown(t *testing.T) {
	for _, mode := range []string{"direct", "feed", "hybrid"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, func(d *Deps) { d.Mode = mode })
			h.signIn(t)
			if _, body := h.do(t, "GET", "/", nil, nil); !strings.Contains(body, "Mode: "+mode+".") {
				t.Errorf("overview does not show mode %s", mode)
			}
			_, body := h.do(t, "GET", "/settings/sources", nil, nil)
			want := map[string]string{"direct": "Direct mode:", "feed": "Feed mode:", "hybrid": "Hybrid mode:"}[mode]
			if !strings.Contains(body, want) {
				t.Errorf("sources page does not explain mode %s", mode)
			}
		})
	}
}

// Each notice links to the page that explains it; a stale feed used to link
// to the public routes on the coverage page.
func TestNoticeLinks(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	now := time.Now()
	_ = h.store.SyncNotices(t.Context(), store.NoticeFeedStale, []store.Notice{{Key: "feed-stale", Subject: "feed", Title: "Feed is stale"}}, now)
	_ = h.store.SyncNotices(t.Context(), store.NoticeHostStale, []store.Notice{{Key: "host-stale:x", Subject: "x", Title: "Host x is not reporting"}}, now)
	_, body := h.do(t, "GET", "/", nil, nil)
	for _, want := range []string{`<a href="/settings/sources"><strong>Feed is stale`, `<a href="/systems"><strong>Host x is not reporting`} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
}

// The coverage page lists the same public routes as the blind-spot notices:
// also those of identified apps with an unknown version, once per host.
func TestCoveragePublicRoutesMatchNotices(t *testing.T) {
	var set *settings.Service
	h := newHarness(t, func(d *Deps) { set = d.Settings })
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich",
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:release", Labels: map[string]string{
			"traefik.http.routers.a.rule": "Host(`photos.example.com`)",
			"traefik.http.routers.b.rule": "Host(`photos.example.com`) && PathPrefix(`/api`)",
		}},
	}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	if err := h.store.ReplaceIdentifications(ctx, []identify.Result{{WorkloadID: wid, AppID: "immich", Confidence: identify.Exact, Note: "floating tag"}}, now); err != nil {
		t.Fatal(err)
	}
	if err := set.Update(ctx, map[string]string{settings.KeyPublicDomains: "example.com"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems/gaps", nil, nil)
	if n := strings.Count(body, `class="mono">photos.example.com</td>`); n != 1 {
		t.Errorf("public route listed %d times, want once:\n%s", n, body)
	}
	if !strings.Contains(body, "1 public route Varde cannot check") || !strings.Contains(body, "varde.version=") {
		t.Error("summary or next step for an unknown version missing")
	}
}

// "Read now" reads only an existing integration; an unknown ID used to be
// accepted and audited, and every integration was triggered.
func TestIntegrationReadNow(t *testing.T) {
	h := newHarness(t, withNetwork(t))
	csrf := h.signIn(t)
	if resp, _ := h.do(t, "POST", "/connections/integrations/nope/sync", url.Values{"csrf": {csrf}}, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("sync of unknown integration: %d", resp.StatusCode)
	}
	if err := h.store.CreateIntegration(t.Context(), store.Integration{ID: "off1", Kind: integrations.KindProxmox, Name: "Proxmox pve", Address: "192.168.1.10", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	resp, _ := h.do(t, "POST", "/connections/integrations/off1/sync", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "ok=not-running") {
		t.Errorf("sync of a switched-off integration: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// The hosts page does not send users to an agent for hosts Varde can read
// over the network (ADR 0020).
func TestHostsPageAgentlessText(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	_, body := h.do(t, "GET", "/systems", nil, nil)
	if strings.Contains(body, "report through an agent") || !strings.Contains(body, `href="/connections"`) {
		t.Error("hosts page still points to agents for further hosts")
	}
}

// A Proxmox guest Varde also reads over SSH is one host on the hosts page and
// one block in the inventory; Proxmox guests without workloads are counted,
// not shown as empty blocks.
func TestOneHostPerMachine(t *testing.T) {
	var set *settings.Service
	h := newHarness(t, func(d *Deps) { set = d.Settings })
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := set.Update(ctx, map[string]string{settings.KeyNetworks: "10.10.1.0/24"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	for _, in := range []store.Integration{
		{ID: "pve", Kind: integrations.KindProxmox, Name: "Proxmox pve", Address: "10.10.1.253", Enabled: true, CreatedAt: now},
		{ID: "dock", Kind: integrations.KindDockerSSH, Name: "Docker 10.10.1.20", Address: "10.10.1.20", Enabled: true, CreatedAt: now},
	} {
		if err := h.store.CreateIntegration(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	for _, host := range []inventory.Host{
		{ID: "pve-pve-101", Name: "docker-vm", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, OS: "QEMU VM", Addresses: []string{"10.10.1.20"}, IntegrationID: "pve", LastContact: now},
		{ID: "pve-pve-102", Name: "empty-lxc", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, OS: "LXC container", Addresses: []string{"10.10.1.21"}, IntegrationID: "pve", LastContact: now},
		{ID: "ssh-dock", Name: "docker-vm.lan", Kind: inventory.HostDocker, Source: inventory.SourceSSH, Addresses: []string{"10.10.1.20"}, IntegrationID: "dock", LastContact: now},
	} {
		if err := h.store.UpsertHost(ctx, host); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.store.ApplySnapshot(ctx, "ssh-dock", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich_server",
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems", nil, nil)
	if n := strings.Count(body, `">docker-vm</a>`); n != 1 {
		t.Errorf("docker-vm listed %d times on the hosts page", n)
	}
	if !strings.Contains(body, "Proxmox VE") || !strings.Contains(body, "Docker over SSH") || !strings.Contains(body, "Varde knows what is installed on 1 of 2 systems") {
		t.Errorf("merged evidence or counts missing:\n%s", body)
	}
	_, body = h.do(t, "GET", "/systems/apps", nil, nil)
	if strings.Contains(body, "empty-lxc") || strings.Count(body, `<section class="panel" aria-labelledby="h-`) != 1 || !strings.Contains(body, "1 further system") {
		t.Errorf("inventory shows empty host blocks or a duplicate:\n%s", body)
	}
	_, body = h.do(t, "GET", "/", nil, nil)
	if !strings.Contains(body, "Varde knows what is installed on <a href=\"/systems\">1 of 2 systems</a>") {
		t.Error("overview system count differs from the systems page")
	}
}

// Helper containers carry the same term on the inventory and coverage pages.
func TestHelperTermConsistent(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "p", Name: "socket-proxy",
		Container: &inventory.Container{ImageRef: "tecnativa/docker-socket-proxy:v0.5.0"},
	}}, now)
	_, body := h.do(t, "GET", "/systems/apps", nil, nil)
	if !strings.Contains(body, "helper, not counted") || strings.Contains(body, "not in catalog") {
		t.Error("inventory calls a helper container not in catalog")
	}
}

// Without local Docker the empty inventory points to the network page.
func TestInventoryEmptyWithoutLocalDocker(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	_, body := h.do(t, "GET", "/systems/apps", nil, nil)
	if strings.Contains(body, "socket proxy") || !strings.Contains(body, `href="/connections"`) {
		t.Error("empty inventory blames the socket proxy while local Docker is off")
	}
}

func TestNetworkDeviceCountWording(t *testing.T) {
	var set *settings.Service
	h := newHarness(t, withNetwork(t), func(d *Deps) { set = d.Settings })
	h.signIn(t)
	if err := set.Update(t.Context(), map[string]string{settings.KeyNetworks: "10.10.1.0/24"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = h.store.RecordDevices(t.Context(), []discovery.Device{{Address: "10.10.1.5", Kind: discovery.KindWeb, Label: "Web"}, {Address: "10.10.1.6", Kind: discovery.KindWeb, Label: "Web"}}, nil, time.Now())
	_, body := h.do(t, "GET", "/connections", nil, nil)
	if !strings.Contains(body, "2 addresses answered") || strings.Contains(body, "addresss") {
		t.Error("device count wording wrong")
	}
}

// A failing integration shows as not reading on the network page, and its
// notice links there.
func TestFailingIntegrationShown(t *testing.T) {
	h := newHarness(t, withNetwork(t))
	h.signIn(t)
	now := time.Now()
	if err := h.store.CreateIntegration(t.Context(), store.Integration{ID: "bad", Kind: integrations.KindProxmox, Name: "Proxmox bad", Address: "10.10.1.253", Enabled: true, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.RecordIntegrationRun(t.Context(), "bad", errors.New("401 permission denied"), nil, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/connections", nil, nil)
	if !strings.Contains(body, "not reading") || !strings.Contains(body, "count as not reporting") {
		t.Errorf("failing integration not shown:\n%s", body)
	}
	_ = h.store.SyncNotices(t.Context(), store.NoticeIntegrationFailing, []store.Notice{{Key: "integration-failing:bad", Subject: "bad", Title: "Integration Proxmox bad is not reading"}}, now)
	_, body = h.do(t, "GET", "/", nil, nil)
	if !strings.Contains(body, `<a href="/connections#integrations"><strong>Integration Proxmox bad`) {
		t.Error("integration notice does not link to the network page")
	}
}

// The host sources list must not reuse the class of the finding evidence
// grid, whose rule it would otherwise override.
func TestHostSourcesListClass(t *testing.T) {
	css, err := os.ReadFile("static/css/varde.css")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(css), ".evidence { list-style") || !strings.Contains(string(css), ".source-list {") {
		t.Error("the host sources list changes the finding evidence rule")
	}
	tpl, err := os.ReadFile("templates/hosts.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(tpl), `class="evidence"`) {
		t.Error("hosts page uses the finding evidence class")
	}
}

// The network ranges can be set on the settings page too, with the same
// validation and audit entry as on the network page; they used to be
// missing there.
func TestSettingsNetworks(t *testing.T) {
	h := newHarness(t, withNetwork(t))
	csrf := h.signIn(t)
	post := func(v string) (*http.Response, string) {
		return h.do(t, "POST", "/settings", url.Values{"csrf": {csrf}, "DISCOVERY_NETWORKS": {v}}, nil)
	}
	if resp, body := post("8.8.8.0/24"); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not a private range") {
		t.Errorf("public range accepted: %d", resp.StatusCode)
	}
	if resp, _ := post(strings.Repeat("10.0.0.0/24,", 100)); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("overlong list accepted: %d", resp.StatusCode)
	}
	if resp, _ := post("192.168.7.0/24"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	for _, page := range []string{"/settings", "/connections"} {
		if _, body := h.do(t, "GET", page, nil, nil); !strings.Contains(body, `value="192.168.7.0/24"`) {
			t.Errorf("%s does not show the saved ranges", page)
		}
	}
	log, _ := h.store.AuditLog(t.Context(), 10)
	found := false
	for _, e := range log {
		found = found || (e.Action == "network.scope" && e.Detail == "192.168.7.0/24")
	}
	if !found {
		t.Error("no network.scope audit entry for a change made in the settings")
	}
}

// On narrow screens the navigation wraps, so no page is hidden off-screen.
func TestNavWrapsOnPhones(t *testing.T) {
	css, err := os.ReadFile("static/css/varde.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".nav { order: 3; flex-basis: 100%; flex-wrap: wrap;") {
		t.Error("navigation does not wrap at phone width")
	}
}

// Drift shows on the inventory: a pulled image the container does not run
// yet, and evidence files changed inside it.
func TestInventoryDrift(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "aaaaaaaaaaaa", Name: "old", Container: &inventory.Container{
			ImageRef: "ghcr.io/immich-app/immich-server:release", ImageID: "sha256:1", PulledImageID: "sha256:2",
			ChangedFiles: []string{"/var/lib/dpkg/status"},
		}},
		{Kind: inventory.KindContainer, RuntimeID: "bbbbbbbbbbbb", Name: "current", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}},
	}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems/apps", nil, nil)
	if strings.Count(body, "newer image pulled") != 1 || !strings.Contains(body, "docker compose up -d") {
		t.Error("pulled image not shown once")
	}
	if strings.Count(body, ">changed inside<") != 1 || !strings.Contains(body, "/var/lib/dpkg/status") {
		t.Error("changed files not shown")
	}
}

// A link rule scoped to a container must leave buttons alone: ".table a"
// outranks ".btn--primary", so "Connect Proxmox" and "Install the agent"
// in the device list were drawn in the button's own background colour.
func TestTableLinksLeaveButtons(t *testing.T) {
	css, err := os.ReadFile("static/css/varde.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(css), "\n") {
		sel, _, ok := strings.Cut(line, "{")
		if !ok || !strings.Contains(line, "color:") {
			continue
		}
		for _, s := range strings.Split(sel, ",") {
			s = strings.TrimSpace(s)
			// Tables hold buttons (the device list); navigation and tabs do not.
			if strings.HasPrefix(s, ".table ") && strings.Contains(s, " a") && !strings.Contains(s, ":not(.btn)") {
				t.Errorf("%q colours every link inside it, buttons included", s)
			}
		}
	}
}
