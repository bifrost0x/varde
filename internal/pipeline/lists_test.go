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
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// An image the catalog does not know is recognised through app store
// lists: one list reports (no alert), two confirm, and switching the lists
// off takes the app and its findings away again.
func TestRunWithAppLists(t *testing.T) {
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
	if err := st.UpsertHost(ctx, inventory.Host{ID: "local", Name: "n", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	ws := []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "t", Name: "tandoor", Container: &inventory.Container{ImageRef: "vabene1111/recipes:1.5.19"}},
	}
	if _, err := st.ApplySnapshot(ctx, "local", inventory.KindContainer, ws, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, "t")

	lists := []string{"unraid"}
	on := true
	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	p.ImageLookup = func() coverage.ImageLookup {
		if !on {
			return nil
		}
		return func(image string) (string, []string, bool, bool) {
			if image != "docker.io/vabene1111/recipes" {
				return "", nil, false, false
			}
			return "github.com/tandoorrecipes/recipes", lists, len(lists) >= 2, true
		}
	}
	const app = "gh-tandoorrecipes-recipes"
	run := func() Summary {
		t.Helper()
		sum, err := p.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return sum
	}
	run()
	ids, _ := st.Identifications(ctx)
	if id := ids[wid]; id.AppID != app || id.Version != "1.5.19" || id.Confidence != identify.Exact {
		t.Fatalf("recognised through one list: %+v", id)
	}

	ranges, _, err := advisory.ParseGitHubRange("< 1.5.20", "1.5.20")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceAdvisories(ctx, app, "github:tandoorrecipes/recipes", []store.AdvisoryRecord{{
		Vuln: advisory.Vulnerability{ID: "GHSA-tandoor", Modified: now,
			Affected: []advisory.Affected{{Package: advisory.Package{Name: "recipes"}, Ranges: ranges}}},
		CVSS: 8.1,
	}}, now); err != nil {
		t.Fatal(err)
	}

	// One list: visible, not confirmed, with the reason.
	if sum := run(); sum.Affected != 0 || sum.Unverified != 1 {
		t.Fatalf("one list: %+v", sum)
	}
	found, _ := st.Findings(ctx, store.FindingFilter{})
	if len(found) != 1 || found[0].MatchState != "unverified" || !strings.Contains(string(found[0].Detail), "unraid") || !strings.Contains(string(found[0].Detail), identify.LabelApp) {
		t.Fatalf("one list finding: %+v", found)
	}

	// A second list agrees: confirmed.
	lists = []string{"umbrel", "unraid"}
	if sum := run(); sum.Affected != 1 || sum.Unverified != 0 {
		t.Fatalf("two lists: %+v", sum)
	}

	// Switched off: the app is unknown again and the finding is resolved.
	on = false
	if sum := run(); sum.Affected != 0 || sum.Unverified != 0 || sum.Identified != 0 {
		t.Fatalf("lists off: %+v", sum)
	}
	ids, _ = st.Identifications(ctx)
	if id := ids[wid]; id.AppID != "" || id.Confidence != identify.None {
		t.Errorf("lists off: still identified as %+v", id)
	}
}
