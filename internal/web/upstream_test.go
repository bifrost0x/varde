// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/pipeline"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/upstream"
)

const (
	runDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func debPkg(name, v string) inventory.Package {
	return inventory.Package{Manager: "dpkg", Name: name, Version: v, Source: name}
}

func debAdvisory(id, cve, pkg, fixed string) store.AdvisoryRecord {
	return store.AdvisoryRecord{Source: match.SourceDistro, Vuln: advisory.Vulnerability{ID: id, Aliases: []string{cve}, Modified: time.Now(),
		Affected: []advisory.Affected{{Package: advisory.Package{Ecosystem: "Debian:12", Name: pkg},
			Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}}}}}}
}

// chefLab stores a CyberChef-like container on host "docker" (a floating
// tag, nginx serving port 8080) with a KEV in pkg, the registry's answer
// ck, and analyses it with the real pipeline. It returns the card's page.
func chefLab(t *testing.T, h *harness, ref string, kevPkg string, ck *store.UpstreamCheck) string {
	t.Helper()
	ctx, now := t.Context(), time.Now().UTC().Truncate(time.Millisecond)
	repo := strings.Split(ref, ":")[0]
	c := inventory.Container{ImageRef: ref, ImageID: "sha256:img", RepoDigests: []string{repo + "@" + runDigest},
		Ports:   []inventory.Port{{PrivatePort: 80, PublicPort: 8080, Protocol: "tcp"}},
		Runtime: &inventory.Runtime{Command: []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}}}
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "docker", Name: "docker", Kind: inventory.HostDocker, Source: inventory.SourceLocal, Arch: "x86_64", LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "docker", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "cyberchef-cyber-chef-1", Container: &c}}, now); err != nil {
		t.Fatal(err)
	}
	pkgs := []inventory.Package{debPkg("nginx", "1.22.1-9"), debPkg("openssl", "3.0.11-1~deb12u2"), debPkg("busybox", "1:1.35.0-4")}
	if err := h.store.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "sha256:img", Distro: "debian-12", Read: now, Packages: pkgs}); err != nil {
		t.Fatal(err)
	}
	recs := map[string]store.AdvisoryRecord{
		"busybox": debAdvisory("DEBIAN-CVE-2099-1", "CVE-2099-1", "busybox", "1:1.35.0-5"),
		"openssl": debAdvisory("DEBIAN-CVE-2099-2", "CVE-2099-2", "openssl", "3.0.15-1~deb12u1"),
	}
	kev := map[string]string{"busybox": "CVE-2099-1", "openssl": "CVE-2099-2"}
	for pkg, r := range recs {
		if err := h.store.ReplaceAdvisories(ctx, "os:Debian:12/"+pkg, match.SourceDistro, []store.AdvisoryRecord{r}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.store.ReplaceKEV(ctx, []store.KEVEntry{{CVE: kev[kevPkg]}}); err != nil {
		t.Fatal(err)
	}
	if ck != nil {
		key, ok := upstream.KeyOf(&c, remedy.HostPlatform("x86_64"))
		if !ok {
			t.Fatal("no key")
		}
		ck.UpstreamKey, ck.Checked = key, now
		if err := h.store.RecordUpstreamCheck(ctx, *ck); err != nil {
			t.Fatal(err)
		}
	}
	cat, err := catalog.Load(fstest.MapFS{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(cat, h.store, slog.New(slog.DiscardHandler), pipeline.Options{RegistryChecks: func() bool { return true }})
	if _, err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	id := inventory.WorkloadID("docker", inventory.KindContainer, "c1")
	_, page := h.do(t, "GET", "/apps/"+id, nil, nil)
	return page
}

func overviewCard(t *testing.T, h *harness) string {
	t.Helper()
	_, body := h.do(t, "GET", "/", nil, nil)
	i := strings.Index(body, `<article class="app app--`)
	if i < 0 {
		t.Fatalf("no card:\n%s", body)
	}
	end := strings.Index(body[i:], "</article>")
	return body[i : i+end]
}

func mustContain(t *testing.T, what, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("%s misses %q:\n%s", what, w, body)
		}
	}
}

func mustNotContain(t *testing.T, what, body string, unwanted ...string) {
	t.Helper()
	for _, w := range unwanted {
		if strings.Contains(body, w) {
			t.Errorf("%s has %q:\n%s", what, w, body)
		}
	}
}

// Card 1 of the report: a KEV in a bundled tool of CyberChef, the floating
// tag pointing to the running image. Not "update now", no newer image, and
// the reason names the component as in the image.
func TestCardCyberChefBundledKEV(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	page := chefLab(t, h, "mpepping/cyberchef:latest", "busybox", &store.UpstreamCheck{HeadDigest: runDigest})
	card := overviewCard(t, h)
	mustContain(t, "card", card, "app--soon", "Update soon", "known-exploited flaw in busybox, in the image", "No fixed image upstream yet")
	mustNotContain(t, "card", card, "Update now", "Pull a newer image", "reachable in your network", "Mitigate now")
	mustContain(t, "page", page, "none: the running image is the newest of its tag", "Snooze until a fixed image appears")
	mustNotContain(t, "page", page, "Pull a newer image")
}

// The same with the KEV in openssl, which nginx loads: urgent without a
// fix, so "mitigate now", with the guidance and still notified.
func TestCardCyberChefServedKEVMitigate(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	page := chefLab(t, h, "mpepping/cyberchef:latest", "openssl", &store.UpstreamCheck{HeadDigest: runDigest})
	card := overviewCard(t, h)
	mustContain(t, "card", card, "app--mitigate", "Mitigate now", "known-exploited flaw in openssl, served on port 8080", "No fixed image upstream yet", "Limit who can reach it")
	mustNotContain(t, "card", card, "Update now", "Pull a newer image")
	mustContain(t, "page", page, "Limit who can reach it.", "FROM mpepping/cyberchef:latest", "apt-get update &amp;&amp; apt-get upgrade -y",
		"Varde asks the registry again by itself")
	fs, err := h.store.Findings(t.Context(), store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if strings.HasSuffix(f.AppID, "/openssl") && f.Priority != "P1" {
			t.Errorf("served KEV is %s, so it would not notify at once", f.Priority)
		}
	}
}

// A newer tag whose image fixes the KEV: "update now" with the tag.
func TestCardNewerTagUpdateNow(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	cand := remedy.Candidate{Distro: "debian-12", Packages: []inventory.Package{debPkg("nginx", "1.22.1-9"), debPkg("openssl", "3.0.15-1~deb12u1"), debPkg("busybox", "1:1.35.0-4")}}
	b, err := upstream.EncodeCandidate(cand)
	if err != nil {
		t.Fatal(err)
	}
	page := chefLab(t, h, "mpepping/cyberchef:v10.19.0", "openssl",
		&store.UpstreamCheck{HeadDigest: runDigest, CandidateTag: "v10.20.0", CandidateDigest: newDigest, Candidate: b, CandidateReadAt: time.Now()})
	card := overviewCard(t, h)
	mustContain(t, "card", card, "app--now", "Update now", "Update to v10.20.0", "fixes 1 of 2 flaws in packages inside the image", "image: mpepping/cyberchef:v10.20.0")
	mustNotContain(t, "card", card, "No fixed image")
	mustContain(t, "page", page, "v10.20.0 fixes 1 of 2 flaws in the image&#39;s packages")
}

// A rebuilt image that fixes nothing: no call to update.
func TestCardNewerDigestNoEffect(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	cand := remedy.Candidate{Distro: "debian-12", Packages: []inventory.Package{debPkg("nginx", "1.22.1-9"), debPkg("openssl", "3.0.11-1~deb12u2"), debPkg("busybox", "1:1.35.0-4")}}
	b, err := upstream.EncodeCandidate(cand)
	if err != nil {
		t.Fatal(err)
	}
	chefLab(t, h, "mpepping/cyberchef:latest", "openssl", &store.UpstreamCheck{HeadDigest: newDigest, CandidateTag: "latest", CandidateDigest: newDigest, Candidate: b})
	card := overviewCard(t, h)
	mustContain(t, "card", card, "Mitigate now", "No fixed image upstream yet", "the newer image latest fixes none of the")
	mustNotContain(t, "card", card, "Update now", "Pull the rebuilt image", "Update to ")
}

// A registry that refused: unknown, with the reason, no call to update.
func TestCardRegistryRefused(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	chefLab(t, h, "mpepping/cyberchef:latest", "openssl", &store.UpstreamCheck{Error: "the registry limits requests; Varde asks again later"})
	card := overviewCard(t, h)
	mustContain(t, "card", card, "Mitigate now", "Varde cannot tell whether a fixed image exists", "the registry limits requests")
	mustNotContain(t, "card", card, "Update now", "Pull a newer image", "Update to ")
}

// A locally built image: unknown, and why.
func TestCardLocallyBuilt(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	chefLab(t, h, "cyberchef-local:dev", "openssl", nil)
	// The lab gives every image a registry digest; a local build has none.
	ctx := t.Context()
	ws, err := h.store.Workloads(ctx, store.WorkloadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	c := *ws[0].Container
	c.RepoDigests = nil
	if _, err := h.store.ApplySnapshot(ctx, "docker", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: ws[0].Name, Container: &c}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cat, _ := catalog.Load(fstest.MapFS{}, nil)
	if _, err := pipeline.New(cat, h.store, slog.New(slog.DiscardHandler), pipeline.Options{}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	card := overviewCard(t, h)
	mustContain(t, "card", card, "Varde cannot tell whether a fixed image exists", "built locally")
	mustNotContain(t, "card", card, "Update now", "Update to ")
}

// Snoozing until a fixed image appears snoozes the image findings.
func TestSnoozeUntilFixedImage(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	chefLab(t, h, "mpepping/cyberchef:latest", "openssl", &store.UpstreamCheck{HeadDigest: runDigest})
	id := inventory.WorkloadID("docker", inventory.KindContainer, "c1")
	resp, _ := h.do(t, "POST", "/apps/"+id+"/snooze-upstream", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("Location"), "ok=snoozed-upstream") {
		t.Fatalf("status %d, location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	fs, err := h.store.Findings(t.Context(), store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.State != store.StateSnoozed || !f.SnoozeUpstream {
			t.Errorf("finding %s is %s (upstream %v)", f.AppID, f.State, f.SnoozeUpstream)
		}
	}
}

// A card whose app update and fixed image differ is credited only with
// what the suggested update fixes: an urgent image flaw fixed by another
// tag keeps it from "update now".
func TestCardCreditsOnlyTheSuggestedImage(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "nas", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	c := inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", RepoDigests: []string{"ghcr.io/immich-app/immich-server@" + runDigest}}
	if _, err := h.store.ApplySnapshot(ctx, "nas", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich_server", Container: &c}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("nas", inventory.KindContainer, "c1")
	appDetail := map[string]any{"advisory_id": "GHSA-app", "match_state": "affected", "fixed_in": "1.121.0", "evidence": map[string]any{"version": "1.120.0"}}
	imgDetail := map[string]any{"advisory_id": "DEBIAN-CVE-2099-2", "match_state": "affected", "fixed_in": "3.0.15-1", "image": true, "kev": true,
		"evidence": map[string]any{"package": "Debian:12/openssl", "version": "3.0.11-1"}}
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{
		{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-app", MatchState: "affected", FixedIn: "1.121.0", Detail: appDetail},
		{WorkloadID: wid, AppID: "os:Debian:12/openssl", AdvisoryID: "DEBIAN-CVE-2099-2", MatchState: "affected", FixedIn: "3.0.15-1", Detail: imgDetail},
	}, now); err != nil {
		t.Fatal(err)
	}
	fs, err := h.store.Findings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var as []store.Assessment
	for _, f := range fs {
		prio := "P2"
		if f.AdvisoryID == "DEBIAN-CVE-2099-2" {
			prio = "P1"
		}
		as = append(as, store.Assessment{ID: f.ID, Priority: prio, Reason: "test", Exposure: "lan"})
	}
	if err := h.store.SetAssessments(ctx, as); err != nil {
		t.Fatal(err)
	}
	st := upstream.Status{Kind: upstream.UpdateAvailable, TargetTag: "v1.125.0", TargetDigest: newDigest, Source: upstream.SourceRegistry,
		Fixed: []remedy.Flaw{{AdvisoryID: "DEBIAN-CVE-2099-2", Package: "Debian:12/openssl"}}}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.ReplaceUpstreamStatus(ctx, map[string]json.RawMessage{wid: b}, now); err != nil {
		t.Fatal(err)
	}
	card := overviewCard(t, h)
	mustContain(t, "card", card, "Update to 1.121.0", "Mitigate now")
	mustNotContain(t, "card", card, "app--now")
}

// A container pinned by tag and digest gets a new pin, not a pull.
func TestCardDigestPinnedRebuild(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	cand := remedy.Candidate{Distro: "debian-12", Packages: []inventory.Package{debPkg("nginx", "1.22.1-9"), debPkg("openssl", "3.0.15-1~deb12u1"), debPkg("busybox", "1:1.35.0-4")}}
	b, err := upstream.EncodeCandidate(cand)
	if err != nil {
		t.Fatal(err)
	}
	chefLab(t, h, "mpepping/cyberchef:v10.19.0@"+runDigest, "openssl",
		&store.UpstreamCheck{HeadDigest: newDigest, CandidateTag: "v10.19.0", CandidateDigest: newDigest, Candidate: b, CandidateReadAt: time.Now()})
	card := overviewCard(t, h)
	mustContain(t, "card", card, "Update the image&#39;s digest pin", "image: mpepping/cyberchef:v10.19.0@"+newDigest)
	mustNotContain(t, "card", card, "Pull the rebuilt image")
}
