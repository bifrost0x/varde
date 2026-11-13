// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func generatedWidget(scheme, rule, cpe string) string {
	extra := ""
	if cpe != "" {
		extra = "  cpe: ['" + cpe + "']\n"
	}
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
` + extra + `maintainers_of_entry: [generator]
verified: "2026-11-12"
`
}

// generatedSetup opens a store with one host and a pipeline whose
// catalog holds the generated entry.
func generatedSetup(t *testing.T, entry string) (*Pipeline, *store.Store, time.Time) {
	t.Helper()
	cat, err := catalog.BuildLayered(nil, catalog.OriginBuiltin, []catalog.Entry{{Name: "gh-acme-widget.yaml", Data: entry}}, nil)
	if err != nil || len(cat.DroppedGenerated()) != 0 {
		t.Fatalf("catalog: %v %v", err, cat.DroppedGenerated())
	}
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now()
	if err := st.UpsertHost(t.Context(), inventory.Host{ID: "local", Name: "n", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	return New(cat, st, slog.New(slog.DiscardHandler), Options{}), st, now
}

func storeAdvisory(ctx context.Context, t *testing.T, st *store.Store, source, id, fixed string, now time.Time) {
	t.Helper()
	ranges := []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}}
	if err := st.ReplaceAdvisories(ctx, "gh-acme-widget", source, []store.AdvisoryRecord{{
		Vuln: advisory.Vulnerability{ID: id, Modified: now, Affected: []advisory.Affected{{Ranges: ranges}}},
	}}, now); err != nil {
		t.Fatal(err)
	}
}

// findingsByWorkload maps runtime IDs to the advisories they are
// affected by or unverified for.
func findingsByWorkload(t *testing.T, st *store.Store, kind inventory.Kind, host string, ids ...string) map[string][]string {
	t.Helper()
	found, err := st.Findings(t.Context(), store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, id := range ids {
		wid := inventory.WorkloadID(host, kind, id)
		for _, f := range found {
			if f.WorkloadID == wid {
				out[id] = append(out[id], f.AdvisoryID+" "+f.MatchState)
			}
		}
	}
	return out
}

// An image the generator did not check gets the derived entry's advisory
// sources: the GitHub repository's advisories, not those NVD gives for
// the generated entry's CPE, which C5 checked for the entry's own image.
func TestUncheckedImageWithoutGeneratedCPE(t *testing.T) {
	ctx := t.Context()
	p, st, now := generatedSetup(t, generatedWidget("semver", `^v?(?P<v>\d+\.\d+\.\d+)$`, "cpe:2.3:a:acme:widget"))
	src := map[string]string{identify.LabelOCISource: "https://github.com/acme/widget"}
	ws := []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "own", Container: &inventory.Container{ImageRef: "ghcr.io/acme/widget:v1.2.0"}},
		{Kind: inventory.KindContainer, RuntimeID: "labelled", Container: &inventory.Container{ImageRef: "docker.io/acme/widget-worker:1.2.0", ImageLabels: src}},
		{Kind: inventory.KindContainer, RuntimeID: "joined", Container: &inventory.Container{ImageRef: "docker.io/acme/widget-worker:1.2.1"}},
	}
	if _, err := st.ApplySnapshot(ctx, "local", inventory.KindContainer, ws, now); err != nil {
		t.Fatal(err)
	}
	storeAdvisory(ctx, t, st, "github:acme/widget", "GHSA-repo", "1.3.0", now)
	storeAdvisory(ctx, t, st, "nvd:cpe:2.3:a:acme:widget", "CVE-2026-1", "1.3.0", now)
	for range 2 { // the second run derives from the catalog the first left
		if _, err := p.Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := findingsByWorkload(t, st, inventory.KindContainer, "local", "own", "labelled", "joined")
	if len(got["own"]) != 2 {
		t.Errorf("own image: %v", got["own"])
	}
	for _, id := range []string{"labelled", "joined"} {
		if len(got[id]) != 1 || got[id][0] != "GHSA-repo affected" {
			t.Errorf("%s: %v", id, got[id])
		}
	}
}

// A manual entry names the generated app itself: it is read as the entry
// is, here under its date scheme, as identify reads its version.
func TestManualWorkloadOfGeneratedEntry(t *testing.T) {
	ctx := t.Context()
	p, st, now := generatedSetup(t, generatedWidget("calver", `^(?P<v>\d{4}\.\d{1,2}\.\d{1,2})$`, ""))
	if _, err := st.AddManual(ctx, inventory.Workload{HostID: "local", Kind: inventory.KindManual, RuntimeID: "m", Name: "widget",
		Manual: &inventory.Manual{AppID: "gh-acme-widget", Version: "2026.1.5"}}, now); err != nil {
		t.Fatal(err)
	}
	// "3.0.0" is no date: under the entry's scheme the range cannot be
	// read, so the finding is unverified; under semver it would vanish.
	storeAdvisory(ctx, t, st, "github:acme/widget", "GHSA-old", "3.0.0", now)
	if _, err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	got := findingsByWorkload(t, st, inventory.KindManual, "local", "m")
	if len(got["m"]) != 1 || got["m"][0] != "GHSA-old unverified" {
		t.Fatalf("manual: %v", got["m"])
	}
}
