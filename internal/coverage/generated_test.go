// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"testing"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
)

// generatedEntry is a generated entry for acme/widget's image on ghcr.io
// with the given scheme and tag rule.
func generatedEntry(scheme, rule string) string {
	return `id: gh-acme-widget
name: widget
homepage: https://github.com/acme/widget
images:
  - match: ghcr.io/acme/widget
oci_source:
  - https://github.com/acme/widget
version:
  scheme: ` + scheme + `
  sources:
    - label: org.opencontainers.image.version
    - tag: '` + rule + `'
advisories:
  coverage: partial
  github_repos: [acme/widget]
maintainers_of_entry: [generator]
verified: "2026-11-12"
`
}

// installation analyses ws twice with base as the analysis does (the
// second round derives from the catalog the first one left) and returns
// the catalog in use.
func installation(t *testing.T, base *catalog.Catalog, ws []inventory.Workload) *catalog.Catalog {
	t.Helper()
	index := func(image string) (string, []string, bool, bool) {
		if image == "ghcr.io/acme/widget" {
			return "github.com/acme/widget", []string{"ghcr", "readme"}, true, true
		}
		return "", nil, false, false
	}
	live := catalog.NewLive(base)
	for range 2 {
		if err := live.SetDerived(DeriveAppsWith(live.Current(), Lookups{Index: index}, ws)); err != nil {
			t.Fatal(err)
		}
	}
	return live.Current()
}

func layered(t *testing.T, generated ...string) *catalog.Catalog {
	t.Helper()
	var es []catalog.Entry
	for _, g := range generated {
		es = append(es, catalog.Entry{Name: "gh-acme-widget.yaml", Data: g})
	}
	c, err := catalog.BuildLayered(nil, catalog.OriginBuiltin, es, nil)
	if err != nil || len(c.DroppedGenerated()) != 0 {
		t.Fatalf("catalog: %v %v", err, c.DroppedGenerated())
	}
	return c
}

func labelled(id, ref string, label bool) inventory.Workload {
	c := &inventory.Container{ImageRef: ref}
	if label {
		c.ImageLabels = map[string]string{identify.LabelOCISource: "https://github.com/acme/widget"}
	}
	return inventory.Workload{ID: id, Kind: inventory.KindContainer, Container: c}
}

// A repository named like the project that one container's source label
// ties to it is matched by name in the derived world, so its containers
// without the label are recognised too. With a generated entry for the
// project they must be recognised the same way.
func TestGeneratedEntryKeepsLabelTiedRepository(t *testing.T) {
	ws := []inventory.Workload{
		labelled("own", "ghcr.io/acme/widget:v1.2.0", false),
		labelled("with-label", "docker.io/acme/widget-worker:1.4.0", true),
		labelled("without-label", "docker.io/acme/widget-worker:1.5.0-ls2", false),
		labelled("inherited", "docker.io/someone/addon:2.0.0", true),
	}
	gen := layered(t, generatedEntry("semver", `^v?(?P<v>\d+\.\d+\.\d+)$`))
	withGen := installation(t, gen, ws)
	derived := installation(t, layered(t), ws)
	for _, w := range ws {
		got, want := identify.Identify(withGen, w), identify.Identify(derived, w)
		if got.AppID != "gh-acme-widget" || got.AppID != want.AppID || got.Version != want.Version || got.Derived != want.Derived ||
			got.Confidence.Notifiable() != want.Confidence.Notifiable() || got.Trust != want.Trust || (got.Doubt() == "") != (want.Doubt() == "") {
			t.Errorf("%s: generated %+v\nderived %+v", w.ID, got, want)
		}
	}
	// The generator's own image keeps its checked rule.
	if a, ok := withGen.App("gh-acme-widget"); !ok || a.Origin != catalog.OriginGenerated || identify.ReadsAsDerived(a, "ghcr.io/acme/widget") ||
		!identify.ReadsAsDerived(a, "docker.io/acme/widget-worker") {
		t.Fatalf("generated entry %+v", a)
	}
}

// A date-template entry reads an image it was not checked on as the
// derived entry does, under semver, and matching compares under the same
// scheme, so the findings are the derived world's.
func TestGeneratedEntryUncheckedImageScheme(t *testing.T) {
	ws := []inventory.Workload{labelled("worker", "docker.io/acme/widget-worker:1.4.0", true)}
	withGen := installation(t, layered(t, generatedEntry("calver", `^(?P<v>\d{4}\.\d{1,2}\.\d{1,2})$`)), ws)
	derived := installation(t, layered(t), ws)
	adv := []match.Advisory{{Source: "github", Vuln: advisory.Vulnerability{ID: "GHSA-1",
		Affected: []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.5.0"}}}}}}}}}
	findings := func(cat *catalog.Catalog) (identify.Result, []match.Finding) {
		r := identify.Identify(cat, ws[0])
		app, ok := cat.App(r.AppID)
		if !ok {
			t.Fatalf("no app for %+v", r)
		}
		app = identify.AppForImage(app, "docker.io/acme/widget-worker")
		return r, match.Match(match.Input{App: app, Version: r.Version, VersionSource: r.VersionSource, Doubt: r.Doubt()}, adv, match.Enrichment{})
	}
	gr, gf := findings(withGen)
	dr, df := findings(derived)
	if gr.Version != dr.Version || len(gf) != 1 || len(df) != 1 || gf[0].State != df[0].State || gf[0].State != match.Affected {
		t.Fatalf("generated %+v %+v, derived %+v %+v", gr, gf, dr, df)
	}
}
