// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/internal/catalog"
)

// Gate holds the minimum numbers a change must keep. They are the measured
// baseline, raised whenever recognition improves; a change that lowers one
// fails the build.
type Gate struct {
	Precision       float64 `yaml:"precision"`
	Recall          float64 `yaml:"recall"`
	VersionAccuracy float64 `yaml:"version_accuracy"`
	VersionCoverage float64 `yaml:"version_coverage"`
	MatchPrecision  float64 `yaml:"match_precision"`
	MatchRecall     float64 `yaml:"match_recall"`
	// Maxima: wrong versions, duplicated or falsely merged machines and
	// wrong trust levels are errors, not trade-offs.
	MaxVersionWrong  int `yaml:"max_version_wrong"`
	MaxDuplicates    int `yaml:"max_duplicates"`
	MaxFalseMerges   int `yaml:"max_false_merges"`
	MaxTrustWrong    int `yaml:"max_trust_wrong"`
	MaxRelationWrong int `yaml:"max_relation_wrong"`
}

// TestCorpus runs the evaluation and fails on a regression. With
// EVAL_REPORT=<file> it also writes the report as Markdown.
func TestCorpus(t *testing.T) {
	c, err := Load("testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(catalogdata.FS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Run(c, cat)
	if err != nil {
		t.Fatal(err)
	}
	report := Markdown(r, len(c.Containers), len(c.Topologies), len(c.Packages), len(c.Matching.Cases)+len(c.Distro.Cases))
	t.Log("\n" + report)
	if p := os.Getenv("EVAL_REPORT"); p != "" {
		if err := os.WriteFile(p, []byte(report), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("testdata/gate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var g Gate
	if err := yaml.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	k := r.Counts
	check := func(name string, got, min float64) {
		if got+1e-9 < min {
			t.Errorf("%s fell to %.3f (gate %.3f)", name, got, min)
		}
	}
	check("precision", k.Precision(), g.Precision)
	check("recall", k.Recall(), g.Recall)
	check("version accuracy", k.VersionAccuracy(), g.VersionAccuracy)
	check("version coverage", k.VersionCoverage(), g.VersionCoverage)
	check("match precision", k.MatchPrecision(), g.MatchPrecision)
	check("match recall", k.MatchRecall(), g.MatchRecall)
	for _, m := range []struct {
		name     string
		got, max int
	}{
		{"wrong versions", k.VersionWrong, g.MaxVersionWrong},
		{"duplicated machines", k.Duplicates, g.MaxDuplicates},
		{"false merges", k.FalseMerges, g.MaxFalseMerges},
		{"wrong trust levels", k.TrustWrong, g.MaxTrustWrong},
		{"wrong parent links", k.RelationsWrong, g.MaxRelationWrong},
	} {
		if m.got > m.max {
			t.Errorf("%s: %d (gate %d)", m.name, m.got, m.max)
		}
	}
}

// Markdown renders a report.
func Markdown(r Report, containers, topologies, packages, matching int) string {
	k := r.Counts
	var b strings.Builder
	fmt.Fprintf(&b, "| Measure | Value | Counts |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| App precision | %.3f | %d correct, %d wrong |\n", k.Precision(), k.AppTP, k.AppFP)
	fmt.Fprintf(&b, "| App recall | %.3f | %d missed |\n", k.Recall(), k.AppFN)
	fmt.Fprintf(&b, "| Version accuracy | %.3f | %d correct, %d wrong, %d missed |\n", k.VersionAccuracy(), k.VersionCorrect, k.VersionWrong, k.VersionMissed)
	fmt.Fprintf(&b, "| Version coverage | %.3f | %d of %d app cases; %d where nothing states the version |\n", k.VersionCoverage(), k.VersionCorrect, k.AppCases, k.Unresolved)
	fmt.Fprintf(&b, "| Machines | %d of %d topologies | %d duplicates, %d false merges |\n", k.TopologyCorrect, k.TopologyTotal, k.Duplicates, k.FalseMerges)
	fmt.Fprintf(&b, "| Relations | %d of %d parent links | %d wrong |\n", k.RelationsTotal-k.RelationsWrong, k.RelationsTotal, k.RelationsWrong)
	fmt.Fprintf(&b, "| Advisory precision | %.3f | %d correct, %d false |\n", k.MatchPrecision(), k.MatchTP, k.MatchFP)
	fmt.Fprintf(&b, "| Advisory recall | %.3f | %d missed |\n", k.MatchRecall(), k.MatchFN)
	fmt.Fprintf(&b, "\nCorpus: %d containers, %d topologies, %d package lists, %d matching cases.\n", containers, topologies, packages, matching)
	if len(r.Failures) > 0 {
		fmt.Fprintf(&b, "\n| Case | Measure | Got | Truth |\n|---|---|---|---|\n")
		for _, f := range r.Failures {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", f.Case, f.Kind, f.Got, f.Want)
		}
	}
	return b.String()
}

// The harness must see errors: wrong truths produce failures in every
// measure. Without this, a broken harness would report perfect numbers.
func TestHarnessDetectsErrors(t *testing.T) {
	cat, err := catalog.Load(catalogdata.FS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &Corpus{
		Containers: []ContainerCase{
			{Name: "wrong version", Image: "vaultwarden/server:1.30.0", Truth: Truth{App: "vaultwarden", Version: "1.31.0", Basis: "tag"}},
			{Name: "wrong app", Image: "vaultwarden/server:1.30.0", Truth: Truth{App: "jellyfin", Version: "1.30.0", Basis: "tag"}},
			{Name: "claimed version", Image: "vaultwarden/server:1.30.0", Truth: Truth{App: "vaultwarden", Basis: "none"}},
			{Name: "missed app", Image: "example.org/x/y:1", Truth: Truth{App: "vaultwarden", Version: "1.0.0", Basis: "tag"}},
		},
		Topologies: []TopologyCase{{
			Name: "expects a merge that cannot happen", Scope: "10.0.0.0/24",
			Hosts:  []TopologyHost{{ID: "a", Source: "ssh", Addresses: []string{"10.0.0.1"}}, {ID: "b", Source: "ssh", Addresses: []string{"10.0.0.2"}}},
			Groups: [][]string{{"a", "b"}},
		}, {
			Name: "expects a parent that is not there", Scope: "10.0.0.0/24",
			Hosts:   []TopologyHost{{ID: "n", Source: "proxmox", Kind: "bare-metal"}, {ID: "g", Source: "proxmox", Kind: "proxmox-guest"}},
			Groups:  [][]string{{"n"}, {"g"}},
			Parents: map[string]string{"g": "n"},
		}, {
			Name: "expects two machines that do merge", Scope: "10.0.0.0/24",
			Hosts:  []TopologyHost{{ID: "c", Source: "ssh", Addresses: []string{"10.0.0.3"}}, {ID: "d", Source: "proxmox", Addresses: []string{"10.0.0.3"}}},
			Groups: [][]string{{"c"}, {"d"}},
		}},
	}
	c.Matching.Advisories = map[string][]MatchAdvisory{"vaultwarden": {{ID: "GHSA-x", Fixed: "1.33.0"}}}
	c.Matching.Cases = []MatchCase{
		{Name: "expects a finding that is not there", App: "vaultwarden", Version: "1.40.0", Trust: "confirmed", Expect: []string{"GHSA-x"}},
		{Name: "expects none but there is one", App: "vaultwarden", Version: "1.30.0", Trust: "confirmed"},
	}
	r, err := Run(c, cat)
	if err != nil {
		t.Fatal(err)
	}
	k := r.Counts
	if k.VersionWrong < 2 || k.AppFP < 1 || k.AppFN < 2 || k.Duplicates < 1 || k.FalseMerges < 1 || k.MatchFP < 1 || k.MatchFN < 1 || k.RelationsWrong < 1 {
		t.Errorf("harness missed injected errors: %+v", k)
	}
}

// withoutCase lists catalog apps that have no corpus case yet. It may only
// shrink: a new catalog entry needs a case in the same change.
var withoutCase = map[string]bool{
	// Registry reads failed on 2026-11-09 (Docker Hub rate limit, image
	// not found under that name); to be recorded.
	"authentik": true, "linkwarden": true, "netbird": true, "portainer-ee": true,
	// Added on 2026-11-12 after the first real installation showed the
	// databases as unchecked helpers. The entries were written without
	// access to the registries, so no image could be recorded; this is the
	// one time the list grew. Their identification is pinned in
	// catalog/catalog_test.go. To be recorded with the entries' review.
	"postgresql": true, "redis": true, "valkey": true, "mariadb": true, "mysql": true, "mongodb": true,
	"memcached": true, "cyberchef": true,
}

func TestEveryCatalogAppHasACase(t *testing.T) {
	c, err := Load("testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(catalogdata.FS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, cs := range c.Containers {
		covered[cs.Truth.App] = true
	}
	for _, pc := range c.Packages {
		for _, tr := range pc.Truth {
			covered[tr.App] = true
		}
	}
	for _, mc := range c.Matching.Cases {
		covered[mc.App] = true
	}
	for _, dc := range c.Distro.Cases {
		if app, _, ok := cat.ByPackage(dc.Package.Manager, dc.Package.Name); ok {
			covered[app.ID] = true
		}
	}
	for _, app := range cat.Apps() {
		switch {
		case !covered[app.ID] && !withoutCase[app.ID]:
			t.Errorf("catalog app %s has no corpus case; add one to internal/eval/testdata/corpus", app.ID)
		case covered[app.ID] && withoutCase[app.ID]:
			t.Errorf("catalog app %s has a case now; remove it from withoutCase", app.ID)
		}
	}
}

// The corpus built into the binary is the one in testdata.
func TestContainerCasesBuiltIn(t *testing.T) {
	c, err := Load("testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ContainerCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || !reflect.DeepEqual(got, c.Containers) {
		t.Fatalf("built-in cases (%d) differ from the corpus (%d)", len(got), len(c.Containers))
	}
}
