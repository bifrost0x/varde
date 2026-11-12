// SPDX-License-Identifier: Apache-2.0

package match

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/version"
)

func app(scheme version.Scheme, filters ...catalog.PackageFilter) *catalog.App {
	return &catalog.App{ID: "app", Version: catalog.VersionSpec{Scheme: scheme}, Advisories: catalog.Advisories{Packages: filters}}
}

func ghsa(id string, aliases []string, vuln, patched string) Advisory {
	ranges, versions, err := advisory.ParseGitHubRange(vuln, patched)
	if err != nil {
		panic(err)
	}
	return Advisory{Source: "github", CVSS: 7.5, Vuln: advisory.Vulnerability{
		ID: id, Aliases: aliases, Summary: "summary " + id,
		Affected:   []advisory.Affected{{Package: advisory.Package{Name: "app"}, Ranges: ranges, Versions: versions}},
		References: []advisory.Reference{{Type: "ADVISORY", URL: "https://example.test/" + id}},
	}}
}

func one(t *testing.T, fs []Finding) Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %v", len(fs), fs)
	}
	return fs[0]
}

func TestRangeEvaluation(t *testing.T) {
	a := app(version.SemVer)
	adv := []Advisory{ghsa("GHSA-1", nil, ">= 3.0.0, <= 3.7.15", "3.7.16")}
	cases := []struct {
		version string
		state   State
		fixed   string
	}{
		{"2.11.9", "", ""},
		{"3.0.0", Affected, "3.7.16"},
		{"3.7.15", Affected, "3.7.16"},
		{"3.7.16", "", ""},
		{"3.7.15-rc.1", Affected, "3.7.16"},
		{"4.0.0", "", ""},
	}
	for _, c := range cases {
		fs := Match(Input{App: a, Version: c.version}, adv, Enrichment{})
		if c.state == "" {
			if len(fs) != 0 {
				t.Errorf("%s: unexpected %v", c.version, fs)
			}
			continue
		}
		f := one(t, fs)
		if f.State != c.state || f.FixedIn != c.fixed {
			t.Errorf("%s: %s fixed=%s, want %s fixed=%s", c.version, f.State, f.FixedIn, c.state, c.fixed)
		}
		if f.Evidence.Range != ">= 3.0.0, <= 3.7.15, < 3.7.16" || f.Evidence.Source != "github" || f.URL == "" {
			t.Errorf("evidence: %+v url=%q", f.Evidence, f.URL)
		}
	}
}

func TestBranches(t *testing.T) {
	a := app(version.SemVer)
	adv := []Advisory{ghsa("GHSA-nc", nil, ">= 32.0.0, >= 33.0.0, >= 34.0.0", "32.0.12, 33.0.6, 34.0.1")}
	for v, want := range map[string]string{"32.0.11": "32.0.12", "33.0.3": "33.0.6", "34.0.0": "34.0.1", "33.0.6": "", "31.0.9": "", "34.0.1": ""} {
		fs := Match(Input{App: a, Version: v}, adv, Enrichment{})
		switch {
		case want == "" && len(fs) != 0:
			t.Errorf("%s: unexpected %v", v, fs)
		case want != "" && (len(fs) != 1 || fs[0].FixedIn != want || fs[0].State != Affected):
			t.Errorf("%s: %v, want fixed %s", v, fs, want)
		}
	}
}

func TestUncertainty(t *testing.T) {
	semver := app(version.SemVer)

	f := one(t, Match(Input{App: semver}, []Advisory{ghsa("GHSA-u", nil, "< 2.0.0", "2.0.0")}, Enrichment{}))
	if f.State != Unverified || f.Evidence.Reason != "running version unknown" {
		t.Errorf("unknown version: %+v", f)
	}

	// Pi-hole: component versions vs calver image releases.
	calver := app(version.CalVer)
	f = one(t, Match(Input{App: calver, Version: "2026.4.1"}, []Advisory{ghsa("GHSA-pi", nil, "< 6.1.0", "6.1.0")}, Enrichment{}))
	if f.State != Unverified {
		t.Errorf("incomparable scheme: %+v", f)
	}

	// Ambiguous bare version: exact version affected, gap unverified.
	amb := []Advisory{ghsa("GHSA-amb", nil, "v3.2.2", "v3.2.4")}
	if f := one(t, Match(Input{App: semver, Version: "3.2.2"}, amb, Enrichment{})); f.State != Affected || f.FixedIn != "3.2.4" {
		t.Errorf("exact: %+v", f)
	}
	if f := one(t, Match(Input{App: semver, Version: "3.2.3"}, amb, Enrichment{})); f.State != Unverified || f.FixedIn != "3.2.4" {
		t.Errorf("gap: %+v", f)
	}
	if fs := Match(Input{App: semver, Version: "3.2.4"}, amb, Enrichment{}); len(fs) != 0 {
		t.Errorf("patched: %v", fs)
	}

	git := Advisory{Source: "osv", Vuln: advisory.Vulnerability{ID: "OSV-git", Affected: []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeGit, Events: []advisory.Event{{Introduced: "abc"}}}}}}}}
	if f := one(t, Match(Input{App: semver, Version: "1.0.0"}, []Advisory{git}, Enrichment{})); f.State != Unverified {
		t.Errorf("git range: %+v", f)
	}

	unparsed := Advisory{Source: "github:o/r", Vuln: advisory.Vulnerability{ID: "GHSA-np", Affected: []advisory.Affected{{Package: advisory.Package{Name: "app"}}}}}
	if f := one(t, Match(Input{App: semver, Version: "1.0.0"}, []Advisory{unparsed}, Enrichment{})); f.State != Unverified || f.Evidence.Reason != "affected versions not machine-readable" {
		t.Errorf("unparsed range: %+v", f)
	}

	none := Advisory{Source: "nvd", Vuln: advisory.Vulnerability{ID: "CVE-2026-1"}}
	if f := one(t, Match(Input{App: semver, Version: "1.0.0"}, []Advisory{none}, Enrichment{})); f.State != Unverified {
		t.Errorf("no ranges: %+v", f)
	}
}

func TestVersionsList(t *testing.T) {
	a := app(version.SemVer)
	adv := Advisory{Source: "osv", Vuln: advisory.Vulnerability{ID: "OSV-1", Affected: []advisory.Affected{{Versions: []string{"1.2.3", "1.2.4"}}}}}
	if f := one(t, Match(Input{App: a, Version: "v1.2.4"}, []Advisory{adv}, Enrichment{})); f.State != Affected {
		t.Errorf("listed version: %+v", f)
	}
	if fs := Match(Input{App: a, Version: "1.2.5"}, []Advisory{adv}, Enrichment{}); len(fs) != 0 {
		t.Errorf("unlisted version: %v", fs)
	}
}

func TestWithdrawnAndAliasDedupe(t *testing.T) {
	a := app(version.SemVer)
	now := time.Now()
	withdrawn := ghsa("GHSA-w", nil, "< 9.0.0", "9.0.0")
	withdrawn.Vuln.Withdrawn = &now
	if fs := Match(Input{App: a, Version: "1.0.0"}, []Advisory{withdrawn}, Enrichment{}); len(fs) != 0 {
		t.Errorf("withdrawn: %v", fs)
	}

	gh := ghsa("GHSA-x", []string{"CVE-2026-100"}, "< 1.5.0", "1.5.0")
	nvdRanges, _, _ := advisory.ParseGitHubRange("< 2.0.0", "")
	nvd := Advisory{Source: "nvd", CVSS: 9.8, Vuln: advisory.Vulnerability{ID: "CVE-2026-100", Affected: []advisory.Affected{{Ranges: nvdRanges}}}}

	// GitHub says fixed in 1.5.0; NVD's broader CPE range must not win.
	if fs := Match(Input{App: a, Version: "1.6.0"}, []Advisory{nvd, gh}, Enrichment{}); len(fs) != 0 {
		t.Errorf("definitive project data overridden by NVD: %v", fs)
	}
	f := one(t, Match(Input{App: a, Version: "1.4.0"}, []Advisory{nvd, gh}, Enrichment{
		KEV: map[string]bool{"CVE-2026-100": true}, EPSS: map[string]float64{"CVE-2026-100": 0.42},
	}))
	if f.AdvisoryID != "GHSA-x" || len(f.Sources) != 2 || f.Aliases[0] != "CVE-2026-100" || !f.KEV || f.EPSS != 0.42 || f.CVSS != 7.5 || f.FixedIn != "1.5.0" {
		t.Errorf("deduped finding: %+v", f)
	}
}

func TestPackageFilter(t *testing.T) {
	a := app(version.SemVer, catalog.PackageFilter{Ecosystem: "nextcloud", Name: "Server"}, catalog.PackageFilter{Name: "Nextcloud Server"})
	mk := func(entries ...advisory.Affected) Advisory {
		return Advisory{Source: "github", Vuln: advisory.Vulnerability{ID: "GHSA-p", Affected: entries}}
	}
	rng, _, _ := advisory.ParseGitHubRange("< 30.0.5", "30.0.5")
	deck := advisory.Affected{Package: advisory.Package{Ecosystem: "nextcloud", Name: "Deck"}, Ranges: rng}
	server := advisory.Affected{Package: advisory.Package{Ecosystem: "nextcloud", Name: "server"}, Ranges: rng}
	enterprise := advisory.Affected{Package: advisory.Package{Ecosystem: "nextcloud enterprise", Name: "Server"}, Ranges: rng}
	unnamed := advisory.Affected{Ranges: rng}

	if fs := Match(Input{App: a, Version: "30.0.1"}, []Advisory{mk(deck)}, Enrichment{}); len(fs) != 0 {
		t.Errorf("other product: %v", fs)
	}
	if fs := Match(Input{App: a, Version: "30.0.1"}, []Advisory{mk(enterprise)}, Enrichment{}); len(fs) != 0 {
		t.Errorf("enterprise-only entry: %v", fs)
	}
	if f := one(t, Match(Input{App: a, Version: "30.0.1"}, []Advisory{mk(deck, server)}, Enrichment{})); f.Evidence.Package != "nextcloud/server" {
		t.Errorf("server entry: %+v", f)
	}
	if fs := Match(Input{App: a, Version: "30.0.1"}, []Advisory{mk(deck, unnamed)}, Enrichment{}); len(fs) != 0 {
		t.Errorf("unnamed entry next to a named other product: %v", fs)
	}
	if fs := Match(Input{App: a, Version: "30.0.1"}, []Advisory{mk(unnamed)}, Enrichment{}); len(fs) != 1 {
		t.Errorf("advisory without any package name: %v", fs)
	}
}

func BenchmarkMatch(b *testing.B) {
	a := app(version.SemVer)
	var advs []Advisory
	for i := range 300 {
		advs = append(advs, ghsa("GHSA-"+string(rune('a'+i%26))+string(rune('a'+i/26)), nil, ">= 1.0.0, < 2.0.0", "2.0.0"))
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = Match(Input{App: a, Version: "1.5.0"}, advs, Enrichment{})
	}
}

// A version that is only reported or disputed never yields affected.
func TestDoubtfulVersionIsUnverified(t *testing.T) {
	app := &catalog.App{ID: "vw", Version: catalog.VersionSpec{Scheme: version.SemVer}}
	advs := []Advisory{{Source: "github", Vuln: advisory.Vulnerability{ID: "GHSA-1", Affected: []advisory.Affected{{
		Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.33.0"}}}},
	}}}}}
	if f := Match(Input{App: app, Version: "1.30.0"}, advs, Enrichment{}); len(f) != 1 || f[0].State != Affected {
		t.Fatalf("confirmed: %+v", f)
	}
	f := Match(Input{App: app, Version: "1.30.0", Doubt: "version only reported by the endpoint"}, advs, Enrichment{})
	if len(f) != 1 || f[0].State != Unverified {
		t.Fatalf("doubtful version: %+v", f)
	}
}
