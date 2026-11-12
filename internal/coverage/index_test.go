// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
)

func identifyWith(t *testing.T, l Lookups, ws []inventory.Workload) (map[string]identify.Result, *catalog.Catalog) {
	t.Helper()
	base, err := catalog.Load(fstest.MapFS{"immich.yaml": {Data: []byte(`id: immich
name: Immich
homepage: https://immich.app
images: [{match: ghcr.io/immich-app/immich-server}]
version: {scheme: semver}
advisories: {coverage: full, github_repos: [immich-app/immich]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := base.WithDerived(DeriveAppsWith(base, l, ws))
	if err != nil {
		t.Fatalf("derived entries rejected: %v", err)
	}
	out := map[string]identify.Result{}
	for _, w := range ws {
		out[w.ID] = identify.Identify(cat, w)
	}
	return out, cat
}

type rows = map[string]struct {
	repo  string
	lists []string
}

// The embedded index needs no setting: two kinds of first-party evidence
// confirm, one is a report, and the app lists add to it.
func TestEmbeddedIndex(t *testing.T) {
	index := listLookup(rows{
		"docker.io/vabene1111/recipes":     {"github.com/tandoorrecipes/recipes", []string{"hub", "readme"}},
		"docker.io/o/reported":             {"github.com/o/reported", []string{"readme"}},
		"docker.io/o/both":                 {"github.com/o/both", []string{"readme"}},
		"docker.io/o/disagree-tie":         {"github.com/o/one", []string{"readme"}},
		"docker.io/o/disagree-index":       {"github.com/o/right", []string{"hub", "readme"}},
		"docker.io/o/disagree-lists":       {"github.com/o/wrong", []string{"readme"}},
		"ghcr.io/immich-app/immich-server": {"github.com/someone/else", []string{"hub", "readme"}},
		"docker.io/o/labelled":             {"github.com/o/indexed", []string{"hub", "readme"}},
	})
	lists := listLookup(rows{
		"docker.io/o/both":           {"github.com/o/both", []string{"unraid"}},
		"docker.io/o/disagree-tie":   {"github.com/o/two", []string{"unraid"}},
		"docker.io/o/disagree-index": {"github.com/o/other", []string{"unraid"}},
		"docker.io/o/disagree-lists": {"github.com/o/listed", []string{"umbrel", "unraid"}},
		"docker.io/o/only-lists":     {"github.com/o/only-lists", []string{"unraid"}},
	})
	ws := []inventory.Workload{
		cw("confirmed", "vabene1111/recipes:1.5", nil),
		cw("reported", "o/reported:1", nil),
		cw("both", "o/both:1", nil),
		cw("tie", "o/disagree-tie:1", nil),
		cw("index-wins", "o/disagree-index:1", nil),
		cw("lists-win", "o/disagree-lists:1", nil),
		cw("catalog", "ghcr.io/immich-app/immich-server:v3", nil),
		cw("only-lists", "o/only-lists:1", nil),
		cw("label", "o/labelled:1", map[string]string{identify.LabelOCISource: "https://gitlab.com/o/elsewhere"}),
	}

	// With every setting off: the index alone.
	got, cat := identifyWith(t, Lookups{Index: index}, ws)
	if r := got["confirmed"]; r.AppID != "gh-tandoorrecipes-recipes" || r.Derived || !r.Confidence.Notifiable() {
		t.Errorf("two kinds of evidence: %+v", r)
	}
	if app, ok := cat.App("gh-tandoorrecipes-recipes"); !ok || app.Derivation == nil || app.Derivation.Basis != catalog.BasisIndex ||
		len(app.Derivation.Evidence) != 2 || len(app.Derivation.Lists) != 0 {
		t.Errorf("derivation: %+v", app)
	}
	if r := got["reported"]; r.AppID != "gh-o-reported" || !r.Derived {
		t.Errorf("one kind of evidence: app %q, derived %v", r.AppID, r.Derived)
	}
	if r := got["both"]; r.AppID != "gh-o-both" || !r.Derived {
		t.Errorf("one kind, lists off: app %q, derived %v", r.AppID, r.Derived)
	}
	if r := got["catalog"]; r.AppID != "immich" {
		t.Errorf("a reviewed entry must win over the index: %q", r.AppID)
	}
	if r := got["only-lists"]; r.AppID != "" {
		t.Errorf("recognised without index or lists: %q", r.AppID)
	}
	if r := got["label"]; r.AppID != "" {
		t.Errorf("a source label naming another place must overrule the index: %q", r.AppID)
	}

	// With the app lists on, evidence from both adds up.
	got, cat = identifyWith(t, Lookups{Index: index, Lists: lists}, ws)
	if r := got["both"]; r.AppID != "gh-o-both" || r.Derived {
		t.Errorf("the project's README and an app list agree: app %q, derived %v", r.AppID, r.Derived)
	}
	if app, ok := cat.App("gh-o-both"); !ok || app.Derivation.Basis != catalog.BasisIndex || len(app.Derivation.Evidence) != 1 || len(app.Derivation.Lists) != 1 {
		t.Errorf("combined derivation: %+v", app.Derivation)
	}
	if r := got["tie"]; r.AppID != "" {
		t.Errorf("index and lists disagree with equal evidence: recognised as %q", r.AppID)
	}
	if r := got["index-wins"]; r.AppID != "gh-o-right" || r.Derived {
		t.Errorf("index with more evidence: %+v", r)
	}
	if r := got["lists-win"]; r.AppID != "gh-o-listed" || r.Derived {
		t.Errorf("lists with more evidence: %+v", r)
	}
	if r := got["only-lists"]; r.AppID != "gh-o-only-lists" || !r.Derived {
		t.Errorf("one list alone: app %q, derived %v", r.AppID, r.Derived)
	}
}
