// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// The front page lists apps, each under what it asks for: a card with the
// one update for an app that needs one, a row that says what "nothing"
// rests on for the others. An app's own page tells how to do it.
func TestAppsFrontPage(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "photos", Name: "photos", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", Labels: map[string]string{
			"com.docker.compose.project": "immich", "com.docker.compose.service": "immich-server", "com.docker.compose.project.working_dir": "/opt/immich"}}},
		{Kind: inventory.KindContainer, RuntimeID: "web", Name: "photos-new", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.121.1"}},
		{Kind: inventory.KindContainer, RuntimeID: "x", Name: "mystery", Container: &inventory.Container{ImageRef: "someone/thing:1.0"}},
	}, now)
	photos := inventory.WorkloadID("local", inventory.KindContainer, "photos")
	_ = h.store.ReplaceIdentifications(ctx, []identify.Result{
		{WorkloadID: photos, AppID: "immich", Confidence: identify.Exact, Version: "1.120.0", Trust: identify.Confirmed},
		{WorkloadID: inventory.WorkloadID("local", inventory.KindContainer, "web"), AppID: "immich", Confidence: identify.Exact, Version: "1.121.1", Trust: identify.Confirmed},
	}, now)
	step := &match.Step{Version: "1.121.1", Fixes: 2, Total: 3}
	finding := func(id, fixed string, st *match.Step) store.FindingInput {
		return store.FindingInput{WorkloadID: photos, AppID: "immich", AdvisoryID: id, MatchState: "affected", FixedIn: fixed,
			Detail: match.Finding{AdvisoryID: id, FixedIn: fixed, Summary: "Flaw " + id, Step: st, Target: &match.Target{Version: "1.121.1", Fixes: 2, Total: 3}}}
	}
	_, _ = h.store.SyncFindings(ctx, []store.FindingInput{finding("GHSA-a", "1.120.1", step), finding("GHSA-b", "1.121.1", step), finding("GHSA-c", "", nil)}, now)
	_ = h.store.SetAssessments(ctx, []store.Assessment{
		{ID: store.FindingID(photos, "GHSA-a"), Priority: "P1", Exposure: "public"},
		{ID: store.FindingID(photos, "GHSA-b"), Priority: "P2", Exposure: "public"},
		{ID: store.FindingID(photos, "GHSA-c"), Priority: "P3", Exposure: "public"},
	})

	_, body := h.do(t, "GET", "/", nil, nil)
	text := stripTags(html.UnescapeString(body))
	for _, want := range []string{
		"1 app needs an update now",
		"Update to 1.121.1 · fixes 2 of 3 flaws",
		"image: ghcr.io/immich-app/immich-server:v1.121.1",
		"reachable from the internet",
		"Not checked (1)", "not recognised, so not compared with any advisory",
		"Nothing to do (1)", "Nothing found",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("front page lacks %q", want)
		}
	}
	for _, old := range []string{"P1 urgent", "needs a check", ">Overview<", ">Findings</a>"} {
		if strings.Contains(body, old) {
			t.Errorf("front page still says %q", old)
		}
	}
	// The card needing an update comes before the quiet rows.
	if card, rows := strings.Index(body, `class="app app--now"`), strings.Index(body, `class="approws"`); card < 0 || rows < 0 || card > rows {
		t.Errorf("order: card %d, rows %d", card, rows)
	}

	resp, body := h.do(t, "GET", "/apps/"+photos, nil, nil)
	text = stripTags(html.UnescapeString(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("app page: %d", resp.StatusCode)
	}
	for _, want := range []string{
		"What to do", "Update to 1.121.1", "change the line of the service immich-server to:",
		"image: ghcr.io/immich-app/immich-server:v1.121.1", "docker compose pull 'immich-server' && docker compose up -d 'immich-server'",
		"The flaws behind it (3)", "Flaw GHSA-a", "fixed in 1.120.1", "no fix yet",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("app page lacks %q", want)
		}
	}
	if !strings.Contains(body, `href="/findings/`+store.FindingID(photos, "GHSA-a")+`"`) {
		t.Error("a flaw does not lead to its evidence")
	}
	// An app without findings says so on its page; an unknown one is not found.
	_, body = h.do(t, "GET", "/apps/"+inventory.WorkloadID("local", inventory.KindContainer, "web"), nil, nil)
	if !strings.Contains(stripTags(body), "Nothing.") {
		t.Error("an app without findings does not say there is nothing to do")
	}
	if resp, _ := h.do(t, "GET", "/apps/nope", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown app: %d", resp.StatusCode)
	}
}
