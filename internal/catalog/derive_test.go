// SPDX-License-Identifier: Apache-2.0

package catalog

import "testing"

func TestDerive(t *testing.T) {
	for _, c := range []struct {
		source, image, id string
		ok                bool
	}{
		{"https://github.com/grafana/grafana", "docker.io/grafana/grafana", "gh-grafana-grafana", true},
		{"https://github.com/immich-app/immich/tree/abc123", "ghcr.io/immich-app/immich-server", "gh-immich-app-immich", true},
		{"https://github.com/Homarr-Labs/homarr.git", "ghcr.io/homarr-labs/homarr", "gh-homarr-labs-homarr", true},
		// An image built FROM nginx inherits nginx's source label: no match
		// between the names, so no entry.
		{"https://github.com/nginx/docker-nginx", "docker.io/someone/myapp", "", false},
		{"https://gitlab.com/x/y", "docker.io/x/y", "", false},
		{"http://github.com/x/y", "docker.io/x/y", "", false},
	} {
		app, ok := Derive(c.source, c.image)
		if ok != c.ok || (ok && (app.ID != c.id || app.Origin != OriginDerived || app.Advisories.GitHubRepos[0] == "")) {
			t.Errorf("%s / %s: %+v %v", c.source, c.image, app, ok)
		}
	}
}

func TestWithDerivedKeepsReviewedEntries(t *testing.T) {
	base, err := newCatalog(map[string]*App{"grafana": {ID: "grafana", Name: "Grafana", OCISource: []string{"https://github.com/grafana/grafana"}}})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := Derive("https://github.com/grafana/grafana", "docker.io/grafana/grafana")
	c, err := base.WithDerived([]*App{d})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.App("gh-grafana-grafana"); ok {
		t.Error("derived entry added although a reviewed one has the same source")
	}
	live := NewLive(base)
	other, _ := Derive("https://github.com/org/newapp", "ghcr.io/org/newapp")
	if err := live.SetDerived([]*App{other}); err != nil {
		t.Fatal(err)
	}
	if _, ok := live.Current().App(other.ID); !ok {
		t.Error("derived entry missing")
	}
	live.Set(base)
	if _, ok := live.Current().App(other.ID); ok {
		t.Error("derived entry survived a new base catalog")
	}
}

// An image a generated entry claims gets no derived entry: neither one
// with the same ID (the generator uses the derived ID) nor one of another
// project that would match the image.
func TestGeneratedBeatsDerived(t *testing.T) {
	base, err := BuildLayered(nil, OriginFeed, []Entry{generatedEntry("gh-x-app", "ghcr.io/x/app")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	live := NewLive(base)
	same, _ := DeriveFor("github.com/x/app", "ghcr.io/x/app", Derivation{Basis: BasisGHCR, Confirmed: true})
	other, _ := DeriveFor("github.com/y/other", "ghcr.io/x/app", Derivation{Basis: BasisLists, Lists: []string{"a", "b"}, Confirmed: true})
	label, _ := Derive("https://github.com/z/app", "ghcr.io/x/app")
	label.ID = "gh-z-app-label"
	if err := live.SetDerived([]*App{same, other, label}); err != nil {
		t.Fatal(err)
	}
	c := live.Current()
	if a, ok := c.App("gh-x-app"); !ok || a.Origin != OriginGenerated {
		t.Fatalf("gh-x-app = %+v", a)
	}
	if a, ok := c.ByImage("ghcr.io/x/app"); !ok || a.Origin != OriginGenerated {
		t.Fatalf("image = %+v", a)
	}
	for _, id := range []string{"gh-y-other", "gh-z-app-label"} {
		if a, ok := c.App(id); ok {
			t.Errorf("derived entry %s made for an image a generated entry claims: %+v", id, a)
		}
	}
	// A derived entry for two images keeps the one no generated entry
	// claims.
	two, _ := DeriveFor("github.com/y/two", "ghcr.io/x/app", Derivation{Basis: BasisGHCR, Confirmed: true})
	two.AddDerivedImage("ghcr.io/y/two", Derivation{Basis: BasisGHCR, Confirmed: true})
	if err := live.SetDerived([]*App{two}); err != nil {
		t.Fatal(err)
	}
	if a, ok := live.Current().App("gh-y-two"); !ok || len(a.Images) != 1 || a.DerivationFor("ghcr.io/x/app") != nil || a.DerivationFor("ghcr.io/y/two") == nil {
		t.Fatalf("gh-y-two = %+v", a)
	}
	if two.DerivationFor("ghcr.io/x/app") == nil {
		t.Fatal("the caller's derived entry was changed")
	}
	// A derived entry for another image still comes.
	d, _ := DeriveFor("github.com/y/free", "ghcr.io/y/free", Derivation{Basis: BasisGHCR, Confirmed: true})
	if err := live.SetDerived([]*App{d}); err != nil {
		t.Fatal(err)
	}
	if _, ok := live.Current().App("gh-y-free"); !ok {
		t.Fatal("unrelated derived entry missing")
	}
}
