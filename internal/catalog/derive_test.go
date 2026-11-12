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
