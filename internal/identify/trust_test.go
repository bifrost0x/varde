// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
)

func trustCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load(fstest.MapFS{"vw.yaml": {Data: []byte(`id: vaultwarden
name: Vaultwarden
homepage: https://github.com/dani-garcia/vaultwarden
images: [{match: vaultwarden/server}]
packages: [{manager: dpkg, name: vaultwarden, versioning: upstream}]
version: {scheme: semver}
advisories: {coverage: full, github_repos: [dani-garcia/vaultwarden]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-09
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func container(ref string, imageLabels, labels map[string]string) inventory.Workload {
	return inventory.Workload{ID: "w", Kind: inventory.KindContainer,
		Container: &inventory.Container{ImageRef: ref, ImageLabels: imageLabels, Labels: labels}}
}

func TestTrust(t *testing.T) {
	cat := trustCatalog(t)
	oci := "org.opencontainers.image.version"
	cases := []struct {
		name  string
		w     inventory.Workload
		trust Trust
		ver   string
	}{
		{"label and tag agree", container("vaultwarden/server:1.37.5", map[string]string{oci: "1.37.5"}, nil), Confirmed, "1.37.5"},
		{"minor-line tag", container("vaultwarden/server:1.37", map[string]string{oci: "1.37.5"}, nil), Confirmed, "1.37.5"},
		{"tag only", container("vaultwarden/server:1.30.0", nil, nil), Confirmed, "1.30.0"},
		{"label and tag disagree", container("vaultwarden/server:1.36.0", map[string]string{oci: "1.37.5"}, nil), Conflict, "1.37.5"},
		{"user pins over a wrong label", container("vaultwarden/server:latest", map[string]string{oci: "main"}, map[string]string{LabelVersion: "1.37.5"}), Confirmed, "1.37.5"},
		{"floating tag, no label", container("vaultwarden/server:latest", nil, nil), "", ""},
		{"endpoint only", inventory.Workload{ID: "e", Kind: inventory.KindEndpoint,
			Endpoint: &inventory.Endpoint{URL: "http://10.0.0.5/api/version", AppID: "vaultwarden", Version: "1.30.0"}}, Reported, "1.30.0"},
		{"upstream package", inventory.Workload{ID: "p", Kind: inventory.KindPackage,
			Package: &inventory.Package{Manager: "dpkg", Name: "vaultwarden", Version: "1.30.0-1"}}, Confirmed, "1.30.0"},
	}
	for _, c := range cases {
		r := Identify(cat, c.w)
		if r.Trust != c.trust || r.Version != c.ver {
			t.Errorf("%s: trust %q version %q, want %q %q (evidence %+v)", c.name, r.Trust, r.Version, c.trust, c.ver, r.Evidence)
		}
		if r.Version != "" && len(r.Evidence) == 0 {
			t.Errorf("%s: version without evidence", c.name)
		}
	}
	r := Identify(cat, container("vaultwarden/server:1.36.0", map[string]string{oci: "1.37.5"}, nil))
	if d := r.Doubt(); !strings.Contains(d, "1.36.0") || !strings.Contains(d, "1.37.5") {
		t.Errorf("conflict doubt does not name both versions: %q", d)
	}
	if r := Identify(cat, cases[0].w); r.Doubt() != "" || !strings.HasPrefix(r.PURL, "pkg:docker/vaultwarden/server@") {
		t.Errorf("confirmed: doubt %q purl %q", r.Doubt(), r.PURL)
	}
}

// An app derived from a source label is identified with its version, but
// its findings wait for the user's confirmation (varde.app).
func TestDerivedAppNeedsConfirmation(t *testing.T) {
	// One app store list is a report: the app is recognised, its findings
	// do not alert until the user confirms it or a second list agrees.
	d, ok := catalog.DeriveFromLists("github.com/tandoorrecipes/recipes", "docker.io/vabene1111/recipes", []string{"unraid"}, false)
	if !ok {
		t.Fatal("not derived")
	}
	cat, err := trustCatalog(t).WithDerived([]*catalog.App{d})
	if err != nil {
		t.Fatal(err)
	}
	w := container("vabene1111/recipes:1.5.19", nil, nil)
	r := Identify(cat, w)
	if r.AppID != d.ID || !r.Derived || r.Version != "1.5.19" || !strings.Contains(r.Doubt(), LabelApp+"="+d.ID) || !strings.Contains(r.Doubt(), "unraid") {
		t.Fatalf("derived: %+v doubt %q", r, r.Doubt())
	}
	w = container("vabene1111/recipes:1.5.19", nil, map[string]string{LabelApp: d.ID})
	if r := Identify(cat, w); r.Derived || r.Doubt() != "" {
		t.Errorf("confirmed by the user: %+v", r)
	}

	// Two lists that agree confirm the app.
	d2, _ := catalog.DeriveFromLists("github.com/mealie-recipes/mealie", "docker.io/mealie/mealie", []string{"umbrel", "unraid"}, true)
	cat, err = trustCatalog(t).WithDerived([]*catalog.App{d2})
	if err != nil {
		t.Fatal(err)
	}
	if r := Identify(cat, container("mealie/mealie:2.1.0", nil, nil)); r.AppID != d2.ID || r.Derived || r.Doubt() != "" || !r.Confidence.Notifiable() {
		t.Errorf("two lists: %+v doubt %q", r, r.Doubt())
	}

	// The publisher's own source label with a matching image name is the
	// publisher's statement: confirmed (ADR 0038; ADR 0025 asked the user).
	d3, ok := catalog.Derive("https://github.com/grafana/grafana", "docker.io/grafana/grafana")
	if !ok {
		t.Fatal("not derived")
	}
	cat, err = trustCatalog(t).WithDerived([]*catalog.App{d3})
	if err != nil {
		t.Fatal(err)
	}
	src := map[string]string{"org.opencontainers.image.source": "https://github.com/grafana/grafana"}
	if r := Identify(cat, container("grafana/grafana:13.3.0", src, nil)); r.AppID != d3.ID || r.Derived || r.Doubt() != "" || r.Version != "13.3.0" {
		t.Errorf("source label: %+v doubt %q", r, r.Doubt())
	}
}
