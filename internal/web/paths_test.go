// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/store"
)

// addFindings stores one affected finding per runtime ID, each on its own
// container of the local host.
func addFindings(t *testing.T, h *harness, runtimeIDs ...string) {
	t.Helper()
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	var ws []inventory.Workload
	var fs []store.FindingInput
	for _, id := range runtimeIDs {
		ws = append(ws, inventory.Workload{Kind: inventory.KindContainer, RuntimeID: id, Name: "immich_" + id,
			Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}})
		fs = append(fs, store.FindingInput{WorkloadID: inventory.WorkloadID("local", inventory.KindContainer, id), AppID: "immich", AdvisoryID: "GHSA-" + id, MatchState: "affected", FixedIn: "1.121.0"})
	}
	if _, err := h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, ws, now); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SyncFindings(ctx, fs, now); err != nil {
		t.Fatal(err)
	}
}

// placeFinding sets the path class of a finding addFinding stored.
func placeFinding(t *testing.T, h *harness, runtimeID, priority, class, reason string) string {
	t.Helper()
	id := store.FindingID(inventory.WorkloadID("local", inventory.KindContainer, runtimeID), "GHSA-"+runtimeID)
	if err := h.store.SetAssessments(t.Context(), []store.Assessment{{ID: id, Priority: priority, Exposure: "public", PathClass: class, PathReason: reason}}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAttackPathsPage(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	if _, body := h.do(t, "GET", "/findings/paths", nil, nil); !strings.Contains(body, "No attack path found") {
		t.Fatalf("empty state missing:\n%s", body)
	}
	addFindings(t, h, "c1", "c2")
	onPath := placeFinding(t, h, "c1", "P1", "path-internet", "opens an attack path from the internet")
	placeFinding(t, h, "c2", "P3", "noise", "the container publishes no port and no route leads to it")
	p := paths.Path{ID: "p1", Entry: paths.Internet, Impact: "root on nas", Target: "local", TargetName: "nas", Score: 90,
		Breaker: onPath, Cut: "Fix GHSA-c1 in Immich (update to 1.121.0)", Findings: []string{onPath},
		Steps: []paths.Step{
			{Kind: "enter", Label: "From the internet through photos.example.com to immich"},
			{Kind: "exploit", Label: "Exploit GHSA-c1 in Immich", FindingID: onPath},
			{Kind: "escape", Label: "Escape to the host: the container runs privileged"},
		}}
	if err := h.store.ReplacePaths(t.Context(), []paths.Path{p}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/findings/paths", nil, nil)
	for _, want := range []string{"root on nas", "photos.example.com", "the container runs privileged", "update to 1.121.0", "/findings/" + onPath, `aria-current="page"`} {
		if !strings.Contains(body, want) {
			t.Errorf("paths page lacks %q", want)
		}
	}
	// The finding shows the path through it and its place.
	_, body = h.do(t, "GET", "/findings/"+onPath, nil, nil)
	if !strings.Contains(body, "Attack paths through this finding") || !strings.Contains(body, "opens an attack path from the internet") {
		t.Errorf("finding page lacks its path")
	}
	// The filter separates both.
	_, body = h.do(t, "GET", "/findings?view=list&path=path", nil, nil)
	if !strings.Contains(body, "GHSA-c1") || strings.Contains(body, "GHSA-c2") {
		t.Errorf("path filter wrong")
	}
	// The overview names the top path and the noise.
	_, body = h.do(t, "GET", "/", nil, nil)
	if !strings.Contains(body, "root on nas") || !strings.Contains(body, "/findings/noise") {
		t.Errorf("overview lacks the attack paths")
	}
	// Background noise is listed with its reason.
	_, body = h.do(t, "GET", "/findings/noise", nil, nil)
	if !strings.Contains(body, "the container publishes no port and no route leads to it") || !strings.Contains(body, "GHSA-c2") || strings.Contains(body, "GHSA-c1") {
		t.Errorf("noise page wrong:\n%s", body)
	}
}

// A suppression can be lifted on the finding's page.
func TestLiftSuppression(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	addFinding(t, h, "c9", "P2")
	ctx := t.Context()
	id := store.FindingID(inventory.WorkloadID("local", inventory.KindContainer, "c9"), "GHSA-c9")
	if err := h.store.AddSuppression(ctx, store.Suppression{ID: "s9", AppID: "immich", AdvisoryID: "GHSA-c9", Reason: "test", CreatedBy: "admin", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.ApplySuppressions(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, body := h.do(t, "GET", "/findings/"+id, nil, nil); !strings.Contains(body, "Lift the suppression") {
		t.Fatal("no way to lift the suppression")
	}
	resp, _ := h.do(t, "POST", "/findings/"+id+"/unsuppress", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("lift: %d", resp.StatusCode)
	}
	if f, err := h.store.GetFinding(ctx, id); err != nil || f.State != store.StateOpen {
		t.Fatalf("after lifting: %+v %v", f, err)
	}
	if resp, _ := h.do(t, "POST", "/findings/"+id+"/unsuppress", url.Values{"csrf": {csrf}}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("lifting twice: %d", resp.StatusCode)
	}
}

// Paths are named by what they end on, and paths with one way in and one
// fix share a card instead of repeating it for every target.
func TestAttackPathsNamedByTargetAndGrouped(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	addFindings(t, h, "c1", "c2")
	first := placeFinding(t, h, "c1", "P2", "path-lan", "opens an attack path from the LAN")
	other := placeFinding(t, h, "c2", "P2", "path-lan", "opens an attack path from the LAN")
	mk := func(id, subject, breaker, cut string, steps int) paths.Path {
		p := paths.Path{ID: id, Entry: paths.LAN, Impact: "container " + subject + " on docker", Subject: subject, Where: "container on docker",
			Gain: "an attacker runs code in it", Target: "local", TargetName: "docker", Breaker: breaker, Cut: cut, Findings: []string{breaker}}
		for i := 0; i < steps; i++ {
			p.Steps = append(p.Steps, paths.Step{Kind: "pivot", Label: "step of " + subject})
		}
		return p
	}
	ps := []paths.Path{
		mk("p1", "paperless-db", first, "Update the image of paperless: it contains CVE-1 in zlib", 6),
		mk("p2", "paperless-tika", first, "Update the image of paperless: it contains CVE-1 in zlib", 4),
		mk("p3", "it-tools", other, "Update the image of it-tools: it contains CVE-2 in openssl", 2),
	}
	if err := h.store.ReplacePaths(t.Context(), ps, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/findings/paths", nil, nil)
	body = html.UnescapeString(body)
	for _, want := range []string{"paperless-db, paperless-tika", "2 targets reached through one way in", "up to 6 steps", "To paperless-tika", "container on docker · an attacker runs code in it · 2 steps", "known or likely to be exploited"} {
		if !strings.Contains(body, want) {
			t.Errorf("paths page lacks %q", want)
		}
	}
	if strings.Contains(body, "control of container") {
		t.Error("the old naming is still on the page")
	}
	if n := strings.Count(body, "Update the image of paperless"); n != 1 {
		t.Errorf("the shared fix is shown %d times, want once", n)
	}
}

// A flaw in a package of a container's image: the page names the container
// and its image, says that the fixed version is the package's and not the
// app's, and what an update does.
func TestImagePackageFindingSpeaksOfTheContainer(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "docker", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "cc", Name: "cyberchef-1",
		Container: &inventory.Container{ImageRef: "mpepping/cyberchef:latest", Labels: map[string]string{"com.docker.compose.project": "cyberchef", "com.docker.compose.service": "cyber-chef"}}}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, "cc")
	detail := match.Finding{AdvisoryID: "ALPINE-CVE-2026-1", Image: true, State: match.Affected, FixedIn: "1.2.1-r0",
		Evidence: match.Evidence{Version: "1.2.0-r1", Package: "Alpine:v3.24/brotli", RecordID: "ALPINE-CVE-2026-1"}}
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "os:Alpine:v3.24/brotli", AdvisoryID: "ALPINE-CVE-2026-1", MatchState: "affected", FixedIn: "1.2.1-r0", Detail: detail}}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/findings/"+store.FindingID(wid, "ALPINE-CVE-2026-1"), nil, nil)
	body = html.UnescapeString(body)
	for _, want := range []string{
		"cyberchef-1: ", "Affected: yes.", "mpepping/cyberchef:latest", "That is a version of the package, not of the app",
		"pull the image again and recreate the container", "closes this finding by itself", "docker compose pull 'cyber-chef'", "Package version",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("finding page lacks %q", want)
		}
	}
	for _, not := range []string{"Update <strong>cyberchef-1</strong> to", "1.2.0-r1</span> <span class=\"muted\">()"} {
		if strings.Contains(body, not) {
			t.Errorf("finding page still has %q", not)
		}
	}
}
