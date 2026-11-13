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

// A generated entry carries its project's source label. The generator
// checked its tag rule on the entry's own images only, so an image that
// the entry knows only through that label is identified as the derived
// entry would identify it: with the derived version chain, and confirmed
// only when its derivation (the publisher's label naming the project)
// confirms it. An image that may have inherited the label from its base
// image stays a report, as with the derived entry, and never alerts.
func TestGeneratedSourceLabelActsAsDerived(t *testing.T) {
	gen := `id: gh-acme-widget
name: widget
homepage: https://github.com/acme/widget
images:
  - match: ghcr.io/acme/widget
oci_source:
  - https://github.com/acme/widget
version:
  scheme: semver
  sources:
    - label: org.opencontainers.image.version
    - tag: ^v?(?P<v>\d+\.\d+\.\d+)(?:-(?:alpine|bookworm)[a-z0-9.]*)*$
advisories:
  coverage: partial
  github_repos: [acme/widget]
maintainers_of_entry: [generator]
verified: "2026-11-12"
`
	genCat, err := catalog.BuildLayered(nil, catalog.OriginBuiltin, []catalog.Entry{{Name: "gh-acme-widget.yaml", Data: gen}}, nil)
	if err != nil || len(genCat.DroppedGenerated()) != 0 {
		t.Fatalf("generated catalog: %v %v", err, genCat.DroppedGenerated())
	}
	empty, err := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err != nil {
		t.Fatal(err)
	}
	// derivedWorld is the catalog an installation has without the
	// generated entry: the entry it derives from the index, and, for an
	// image named like the project, that image tied by its label
	// (coverage.DeriveAppsWith).
	derivedWorld := func(labelImage string) *catalog.Catalog {
		d, ok := catalog.DeriveFor("github.com/acme/widget", "ghcr.io/acme/widget", catalog.Derivation{Basis: catalog.BasisIndex, Evidence: []string{"ghcr", "readme"}, Confirmed: true})
		if !ok {
			t.Fatal("not derived")
		}
		if labelImage != "" {
			d.AddDerivedImage(labelImage, catalog.Derivation{Basis: catalog.BasisLabel, Confirmed: true})
		}
		c, err := empty.WithDerived([]*catalog.App{d})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	src := map[string]string{LabelOCISource: "https://github.com/acme/widget"}

	// The entry's own image: its checked rule reads the variant tag.
	r := Identify(genCat, container("ghcr.io/acme/widget:v1.2.0-alpine", nil, nil))
	if r.AppID != "gh-acme-widget" || r.Derived || r.Version != "1.2.0" || r.Doubt() != "" {
		t.Fatalf("own image: %+v doubt %q", r, r.Doubt())
	}

	for _, c := range []struct {
		name       string
		ref        string
		labelImage string
		derived    bool
		version    string
	}{
		// Named like the project: the publisher's label confirms it, as
		// catalog.Derive does; the derived chain reads the tag, also a
		// variant the generated rule would read differently.
		{"named alike", "docker.io/acme/widget-worker:1.4.0-ls3", "docker.io/acme/widget-worker", false, "1.4.0-ls3"},
		// An unrelated image whose base image carries the label.
		{"inherited", "docker.io/someone/addon:2.0.0", "", true, "2.0.0"},
	} {
		w := container(c.ref, src, nil)
		// With the generated entry, the installation derives the label
		// image as before (coverage.DeriveAppsWith) and the derived entry
		// joins the generated one.
		genWorld := genCat
		if c.labelImage != "" {
			d, ok := catalog.Derive(src[LabelOCISource], c.labelImage)
			if !ok {
				t.Fatal("not derived")
			}
			d.AddDerivedImage(c.labelImage, *d.Derivation)
			if genWorld, err = genCat.WithDerived([]*catalog.App{d}); err != nil {
				t.Fatal(err)
			}
		}
		got, want := Identify(genWorld, w), Identify(derivedWorld(c.labelImage), w)
		if got.AppID != "gh-acme-widget" || got.Derived != c.derived || got.Version != c.version {
			t.Errorf("%s: %+v", c.name, got)
		}
		if got.AppID != want.AppID || got.Derived != want.Derived || got.Version != want.Version || got.Trust != want.Trust ||
			got.Confidence.Notifiable() != want.Confidence.Notifiable() || (got.Doubt() == "") != (want.Doubt() == "") {
			t.Errorf("%s: generated %+v, derived %+v", c.name, got, want)
		}
	}
}
