// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// An affected Compose container gets the release tag that fixes it, the
// line to change and the commands; a tag the registry did not list is
// marked as unverified.
func TestFindingUpdate(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich_server",
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", Labels: map[string]string{
			"com.docker.compose.project": "immich", "com.docker.compose.service": "immich-server",
			"com.docker.compose.project.working_dir": "/opt/immich", "com.docker.compose.project.config_files": "/opt/immich/docker-compose.yml",
		}},
	}}, now)
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	_, _ = h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected", FixedIn: "1.120.1",
		Detail: match.Finding{AdvisoryID: "GHSA-1", Target: &match.Target{Version: "1.121.0", Fixes: 2, Total: 2}}}}, now)
	page := func() string {
		_, body := h.do(t, "GET", "/findings/"+store.FindingID(wid, "GHSA-1"), nil, nil)
		return html.UnescapeString(body)
	}
	body := page()
	for _, want := range []string{"How to update", "ghcr.io/immich-app/immich-server:v1.121.0", "has not seen this tag in the registry",
		"image: ghcr.io/immich-app/immich-server:v1.121.0", "docker compose pull 'immich-server' && docker compose up -d 'immich-server'", "/opt/immich/docker-compose.yml"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if err := h.store.RecordRepositoryTags(ctx, store.RepositoryTags{Repository: "ghcr.io/immich-app/immich-server", Tags: []string{"v1.120.0", "v1.121.0", "v1.121.1"}, Checked: now}); err != nil {
		t.Fatal(err)
	}
	if body = page(); !strings.Contains(body, "a release tag the registry lists") || !strings.Contains(body, "immich-server:v1.121.0") {
		t.Error("verified tag not shown")
	}
	// With the step of the analysis, the page names one version: in its
	// first sentence, in the image line, and with what else it fixes. The
	// fix on the running line stands before the newer major version.
	_, _ = h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected", FixedIn: "1.120.1",
		Detail: match.Finding{AdvisoryID: "GHSA-1", FixedIn: "1.120.1",
			Target: &match.Target{Version: "2.0.0", Fixes: 5, Total: 5, NewLine: true, Line: &match.Target{Version: "1.121.1", Fixes: 3, Total: 5}},
			Step:   &match.Step{Version: "1.121.1", Fixes: 3, Total: 5, Advisory: "1.120.1", All: &match.Target{Version: "2.0.0", Fixes: 5, Total: 5, NewLine: true}}}}}, now)
	body = strings.Join(strings.Fields(page()), " ")
	for _, want := range []string{"Update immich_server to 1.121.1.", "This advisory is fixed from 1.120.1 on", "fixes it together with 3 of the 5 advisories",
		"The rest need 2.0.0, a new major version that fixes all 5", "image: ghcr.io/immich-app/immich-server:v1.121.1"} {
		if !strings.Contains(stripTags(body), want) {
			t.Errorf("step: missing %q", want)
		}
	}
	if strings.Contains(body, "immich-server:v2.0.0") || strings.Contains(body, "immich-server:v1.120.1") {
		t.Error("the image line names another version than the page")
	}
	// Unverified findings get no update suggestion.
	_, _ = h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "unverified", Detail: match.Finding{AdvisoryID: "GHSA-1"}}}, now)
	if strings.Contains(page(), "How to update") {
		t.Error("suggestion for an unverified finding")
	}
}

// A version on a release line past its end of life is marked on the
// inventory, with the newest supported release.
func TestInventoryEOL(t *testing.T) {
	h := newHarness(t, withNginx(t))
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "old", Name: "web-old", Container: &inventory.Container{ImageRef: "nginx:1.29.8"}},
		{Kind: inventory.KindContainer, RuntimeID: "new", Name: "web-new", Container: &inventory.Container{ImageRef: "nginx:1.31.8"}},
	}, now)
	_ = h.store.ReplaceIdentifications(ctx, []identify.Result{
		{WorkloadID: inventory.WorkloadID("local", inventory.KindContainer, "old"), AppID: "nginx", Confidence: identify.Exact, Version: "1.29.8", Trust: identify.Confirmed},
		{WorkloadID: inventory.WorkloadID("local", inventory.KindContainer, "new"), AppID: "nginx", Confidence: identify.Exact, Version: "1.31.8", Trust: identify.Confirmed},
	}, now)
	_ = h.store.RecordEOL(ctx, "nginx", []store.EOLRelease{{Name: "1.31", Latest: "1.31.8"}, {Name: "1.29", IsEOL: true, EOLFrom: "2026-05-13", Latest: "1.29.8"}}, now)
	_, body := h.do(t, "GET", "/systems/apps", nil, nil)
	if strings.Count(body, ">end of life<") != 1 || !strings.Contains(body, "Release line 1.29 gets no more fixes since 2026-05-13; the newest supported release is 1.31.8.") {
		t.Error("end of life not shown once")
	}
}

// stripTags drops HTML tags, so a sentence reads as on the page.
func stripTags(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
