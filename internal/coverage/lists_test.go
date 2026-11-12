// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
)

// listLookup is a lookup over a fixed table, as the server builds it.
func listLookup(rows map[string]struct {
	repo  string
	lists []string
}) ImageLookup {
	return func(image string) (string, []string, bool, bool) {
		r, ok := rows[image]
		return r.repo, r.lists, len(r.lists) >= 2, ok
	}
}

func cw(id, ref string, imageLabels map[string]string) inventory.Workload {
	return inventory.Workload{ID: id, Kind: inventory.KindContainer, Name: id,
		Container: &inventory.Container{ImageRef: ref, ImageLabels: imageLabels}}
}

func TestDeriveAppsFromLists(t *testing.T) {
	cat, err := catalog.Load(fstest.MapFS{"immich.yaml": {Data: []byte(`id: immich
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
	lookup := listLookup(map[string]struct {
		repo  string
		lists []string
	}{
		"docker.io/vabene1111/recipes":      {"github.com/tandoorrecipes/recipes", []string{"unraid"}},
		"docker.io/mealie/mealie":           {"github.com/mealie-recipes/mealie", []string{"umbrel", "unraid"}},
		"ghcr.io/immich-app/immich-server":  {"github.com/someone/else", []string{"unraid"}},
		"docker.io/altran1502/immich-proxy": {"github.com/immich-app/immich", []string{"unraid"}},
		"docker.io/library/postgres":        {"github.com/drytrix/timetracker", []string{"unraid"}},
		"docker.io/paperless/ngx":           {"github.com/paperless-ngx/paperless-ngx", []string{"unraid"}},
		"docker.io/paperless/ngx-worker":    {"github.com/paperless-ngx/paperless-ngx", []string{"umbrel"}},
		"docker.io/o/labelled":              {"github.com/o/project", []string{"unraid"}},
		"docker.io/o/labelled-elsewhere":    {"github.com/o/project2", []string{"unraid"}},
	})
	src := func(u string) map[string]string { return map[string]string{identify.LabelOCISource: u} }
	ws := []inventory.Workload{
		cw("one-list", "vabene1111/recipes:1.5", nil),
		cw("two-lists", "mealie/mealie:v2", nil),
		cw("catalog-wins", "ghcr.io/immich-app/immich-server:v3", nil),
		cw("reviewed-repo", "altran1502/immich-proxy:v3", nil),
		cw("db", "postgres:16", nil),
		cw("namesake", "registry.lan/vabene1111/recipes:1.5", nil),
		cw("same-repo-a", "paperless/ngx:2", nil),
		cw("same-repo-b", "paperless/ngx-worker:2", nil),
		cw("label-agrees", "o/labelled:1", src("https://github.com/o/project")),
		cw("label-differs", "o/labelled-elsewhere:1", src("https://github.com/x/base-image")),
		cw("unknown", "nobody/nothing:1", nil),
	}
	got := map[string]*catalog.App{}
	for _, a := range DeriveApps(cat, lookup, ws) {
		got[a.ID] = a
	}
	want := map[string]struct {
		basis     string
		confirmed bool
		images    int
	}{
		"gh-tandoorrecipes-recipes":      {"lists", false, 1},
		"gh-mealie-recipes-mealie":       {"lists", true, 1},
		"gh-paperless-ngx-paperless-ngx": {"lists", false, 2},
		"gh-o-project":                   {"lists", true, 1}, // the publisher's label and a list agree
	}
	if len(got) != len(want) {
		t.Errorf("derived %d apps, want %d: %v", len(got), len(want), keys(got))
	}
	for id, w := range want {
		a := got[id]
		if a == nil {
			t.Errorf("%s not derived", id)
			continue
		}
		if a.Origin != catalog.OriginDerived || a.Derivation == nil || a.Derivation.Basis != w.basis || a.Derivation.Confirmed != w.confirmed || len(a.Images) != w.images {
			t.Errorf("%s: origin %s, derivation %+v, %d images", id, a.Origin, a.Derivation, len(a.Images))
		}
	}
	if a := got["gh-tandoorrecipes-recipes"]; a != nil && (len(a.Derivation.Lists) != 1 || a.Derivation.Lists[0] != "unraid" || a.Advisories.GitHubRepos[0] != "tandoorrecipes/recipes") {
		t.Errorf("tandoor: %+v %+v", a.Derivation, a.Advisories)
	}

	// The derived apps are found by their image.
	full, err := cat.WithDerived(DeriveApps(cat, lookup, ws))
	if err != nil {
		t.Fatal(err)
	}
	for ref, id := range map[string]string{"docker.io/vabene1111/recipes": "gh-tandoorrecipes-recipes", "docker.io/paperless/ngx-worker": "gh-paperless-ngx-paperless-ngx",
		"ghcr.io/immich-app/immich-server": "immich"} {
		if a, ok := full.ByImage(ref); !ok || a.ID != id {
			t.Errorf("ByImage(%s) = %v, want %s", ref, a, id)
		}
	}
	if _, ok := full.ByImage("registry.lan/vabene1111/recipes"); ok {
		t.Error("an image of the same name on another registry matched")
	}

	// Without the lists nothing of this is derived, and what was derived
	// goes away with them.
	if apps := DeriveApps(cat, nil, ws); len(apps) != 0 {
		t.Errorf("derived without lists: %v", apps)
	}
}

func keys(m map[string]*catalog.App) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The inventory's image repositories and the lists' keys have one form.
func TestListKeysMatchImageRefs(t *testing.T) {
	for _, ref := range []string{"nginx:1.27", "linuxserver/sonarr:latest", "ghcr.io/Immich-App/immich-server:v3", "lscr.io/linuxserver/plex",
		"registry.lan:5000/immich:1", "quay.io/oauth2-proxy/oauth2-proxy:v7", "docker.io/library/redis:7", "index.docker.io/foo/bar:1"} {
		r, err := imageref.Parse(ref)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if key, ok := applists.NormaliseImage(ref); !ok || key != r.Repository {
			t.Errorf("%s: list key %q, inventory repository %q", ref, key, r.Repository)
		}
	}
}

// The source label is the publisher's statement: confirmed. The path on
// GitHub's registry is a guess (packages are often named differently from
// their repository): recognised, not confirmed.
func TestDerivationBasis(t *testing.T) {
	cat, _ := catalog.Load(fstest.MapFS{}, nil)
	ws := []inventory.Workload{
		cw("ghcr", "ghcr.io/gethomepage/homepage:v0.9.10", nil),
		cw("label", "grafana/grafana:13", map[string]string{identify.LabelOCISource: "https://github.com/grafana/grafana"}),
	}
	got := map[string]*catalog.App{}
	for _, a := range DeriveApps(cat, nil, ws) {
		got[a.ID] = a
	}
	if a := got["gh-gethomepage-homepage"]; a == nil || a.Derivation == nil || a.Derivation.Basis != "ghcr" || a.Derivation.Confirmed || len(a.Images) != 1 {
		t.Errorf("ghcr: %+v", a)
	}
	if a := got["gh-grafana-grafana"]; a == nil || a.Derivation == nil || a.Derivation.Basis != "label" || !a.Derivation.Confirmed {
		t.Errorf("label: %+v", a)
	}
}
