// SPDX-License-Identifier: Apache-2.0

package match

import (
	"testing"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/version"
)

func TestTargetRequiresComparableAliasData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		affected []advisory.Affected
	}{
		{"invalid range", []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "unknown"}}}}}}},
		{"git range", []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeGit, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "abcdef"}}}}}}},
		{"invalid version", []advisory.Affected{{Versions: []string{"unknown"}}}},
		{"empty entry", []advisory.Affected{{}}},
		{"no entries", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			known := ghsa("GHSA-known", []string{"CVE-2026-99999"}, "< 2.0.0", "2.0.0")
			unknown := Advisory{Source: "osv", Vuln: advisory.Vulnerability{
				ID: "OSV-unknown", Aliases: []string{"CVE-2026-99999"}, Affected: tc.affected,
			}}
			tg := targetOf(t, Match(Input{App: app(version.SemVer), Version: "1.0.0"}, []Advisory{known, unknown}, Enrichment{}))
			if tg == nil || tg.Fixes != 0 || tg.Version != "" || tg.Total != 1 {
				t.Fatalf("uncertain alias must not count as a confirmed fix: %+v", tg)
			}
		})
	}
}

func TestTargetDistinguishesMissingAndIrrelevantAliasData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		affected []advisory.Affected
		fixes    int
	}{
		{"missing data", nil, 0},
		{"other package", []advisory.Affected{{Package: advisory.Package{Name: "other"}}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := app(version.SemVer, catalog.PackageFilter{Name: "app"})
			known := ghsa("GHSA-known", []string{"CVE-2026-99999"}, "< 2.0.0", "2.0.0")
			alias := Advisory{Source: "osv", Vuln: advisory.Vulnerability{
				ID: "OSV-alias", Aliases: []string{"CVE-2026-99999"}, Affected: tc.affected,
			}}
			tg := targetOf(t, Match(Input{App: a, Version: "1.0.0"}, []Advisory{known, alias}, Enrichment{}))
			if tg == nil || tg.Fixes != tc.fixes {
				t.Fatalf("target %+v, want %d confirmed fixes", tg, tc.fixes)
			}
		})
	}
}

func targetOf(t *testing.T, fs []Finding) *Target {
	t.Helper()
	var tg *Target
	for _, f := range fs {
		if f.State != Affected {
			if f.Target != nil {
				t.Errorf("%s: unverified finding carries a target", f.AdvisoryID)
			}
			continue
		}
		if f.Target == nil {
			t.Fatalf("%s: affected finding without target", f.AdvisoryID)
		}
		if tg != nil && *tg != *f.Target {
			t.Fatalf("targets differ between findings: %+v vs %+v", tg, f.Target)
		}
		tg = f.Target
	}
	return tg
}

func TestTargetCoversAllAdvisories(t *testing.T) {
	a := app(version.SemVer)
	adv := []Advisory{
		ghsa("GHSA-a", nil, "< 1.4.3", "1.4.3"),
		ghsa("GHSA-b", nil, "< 1.4.7", "1.4.7"),
		ghsa("GHSA-c", nil, "< 1.4.5", "1.4.5"),
	}
	tg := targetOf(t, Match(Input{App: a, Version: "1.4.1"}, adv, Enrichment{}))
	if tg.Version != "1.4.7" || tg.Fixes != 3 || tg.Total != 3 || tg.NewLine || tg.Line != nil {
		t.Fatalf("target %+v, want 1.4.7 fixing 3 of 3", tg)
	}
}

func TestTargetPrefersRunningLine(t *testing.T) {
	a := app(version.SemVer)
	adv := []Advisory{
		// Fixed on both lines: the 1.x backport must win over 2.0.1.
		ghsa("GHSA-a", nil, ">= 1.0.0, >= 2.0.0", "1.9.4, 2.0.1"),
		ghsa("GHSA-b", nil, "< 1.9.2", "1.9.2"),
	}
	tg := targetOf(t, Match(Input{App: a, Version: "1.9.0"}, adv, Enrichment{}))
	if tg.Version != "1.9.4" || tg.Fixes != 2 || tg.NewLine {
		t.Fatalf("target %+v, want 1.9.4 on the running line", tg)
	}
}

func TestTargetNewMajorWithLineAlternative(t *testing.T) {
	a := app(version.SemVer)
	adv := []Advisory{
		ghsa("GHSA-a", nil, "< 1.9.4", "1.9.4"),
		// Only fixed in 2.x: the full fix leaves the line.
		ghsa("GHSA-b", nil, "< 2.1.0", "2.1.0"),
	}
	tg := targetOf(t, Match(Input{App: a, Version: "1.9.0"}, adv, Enrichment{}))
	if tg.Version != "2.1.0" || tg.Fixes != 2 || !tg.NewLine {
		t.Fatalf("target %+v, want 2.1.0 as a new major", tg)
	}
	if tg.Line == nil || tg.Line.Version != "1.9.4" || tg.Line.Fixes != 1 {
		t.Fatalf("line alternative %+v, want 1.9.4 fixing 1", tg.Line)
	}
}

func TestTargetZeroMajorMinorIsLine(t *testing.T) {
	a := app(version.SemVer)
	adv := []Advisory{ghsa("GHSA-a", nil, "< 0.9.0", "0.9.0")}
	tg := targetOf(t, Match(Input{App: a, Version: "0.8.3"}, adv, Enrichment{}))
	if tg.Version != "0.9.0" || !tg.NewLine {
		t.Fatalf("target %+v, want 0.9.0 flagged as leaving the 0.8 line", tg)
	}
}

func TestTargetWithoutFix(t *testing.T) {
	a := app(version.SemVer)
	adv := []Advisory{
		ghsa("GHSA-a", nil, "< 1.4.3", "1.4.3"),
		ghsa("GHSA-b", nil, ">= 1.0.0", ""),
	}
	tg := targetOf(t, Match(Input{App: a, Version: "1.4.1"}, adv, Enrichment{}))
	if tg.Version != "1.4.3" || tg.Fixes != 1 || tg.Total != 2 {
		t.Fatalf("target %+v, want 1.4.3 fixing 1 of 2", tg)
	}
	tg = targetOf(t, Match(Input{App: a, Version: "1.4.1"}, adv[1:], Enrichment{}))
	if tg.Version != "" || tg.Fixes != 0 || tg.Total != 1 {
		t.Fatalf("target %+v, want no version", tg)
	}
}

func TestTargetNotForUnknownVersion(t *testing.T) {
	a := app(version.SemVer)
	adv := []Advisory{ghsa("GHSA-a", nil, "< 1.4.3", "1.4.3")}
	if tg := targetOf(t, Match(Input{App: a}, adv, Enrichment{})); tg != nil {
		t.Fatalf("target %+v for an unknown version", tg)
	}
}

func TestSameLine(t *testing.T) {
	p := version.MustParse
	cases := []struct {
		s    version.Scheme
		a, b string
		want bool
	}{
		{version.SemVer, "1.4.2", "1.9.0", true},
		{version.SemVer, "1.4.2", "2.0.0", false},
		{version.SemVer, "0.8.1", "0.8.9", true},
		{version.SemVer, "0.8.1", "0.9.0", false},
		{version.CalVer, "2024.12.1", "2025.1.0", true},
	}
	for _, c := range cases {
		if got := p(c.s, c.a).SameLine(p(c.s, c.b)); got != c.want {
			t.Errorf("%s vs %s: %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// With the releases of the image known, the target is a release that
// exists: a fixed version that was never published gives way to the next
// one that was, and a fix newer than the list stays as the advisory names
// it.
func TestTargetIsAnExistingRelease(t *testing.T) {
	a := app(version.SemVer)
	advs := []Advisory{
		ghsa("GHSA-1", nil, "< 1.2.3", "1.2.3"), // 1.2.3 was never tagged
		ghsa("GHSA-2", nil, "< 1.2.1", "1.2.1"),
	}
	in := Input{App: a, Version: "1.2.0", Releases: []string{"1.3.0", "1.2.4", "1.2.4-rc1", "1.2.1", "1.2.0", "1.1.0"}}
	fs := Match(in, advs, Enrichment{})
	if len(fs) != 2 || fs[0].Target == nil {
		t.Fatalf("findings: %v", fs)
	}
	if tg := fs[0].Target; tg.Version != "1.2.4" || tg.Fixes != 2 || tg.NewLine {
		t.Errorf("target = %+v, want 1.2.4 fixing both", tg)
	}
	// What the advisory itself says stays what it says.
	if fs[0].FixedIn != "1.2.3" {
		t.Errorf("fixed in = %q", fs[0].FixedIn)
	}

	// Without a list, and with a list that ends below the fix, the
	// advisory's version stands.
	for _, rel := range [][]string{nil, {"1.2.1", "1.2.0"}} {
		in.Releases = rel
		if tg := Match(in, advs, Enrichment{})[0].Target; tg == nil || tg.Version != "1.2.3" {
			t.Errorf("releases %v: target = %+v, want 1.2.3", rel, tg)
		}
	}

	// A pre-release is an update only for a running pre-release.
	in.Version, in.Releases = "1.2.0-rc1", []string{"1.3.0", "1.2.4-rc1"}
	if tg := Match(in, advs, Enrichment{})[0].Target; tg == nil || tg.Version != "1.2.4-rc1" {
		t.Errorf("pre-release target = %+v", tg)
	}
}

// One version per finding: the fix on the running line when the line
// fixes this finding, the newer line otherwise, and the finding's own fix
// when the target does not reach it.
func TestStep(t *testing.T) {
	line := &Target{Version: "1.27.3", Fixes: 96, Total: 152}
	tg := &Target{Version: "28.3.0", Fixes: 151, Total: 152, NewLine: true, Line: line}
	cases := []struct {
		name    string
		fixedIn string
		target  *Target
		want    Step
	}{
		{"line fixes it", "1.26.3", tg, Step{Version: "1.27.3", Fixes: 96, Total: 152, Advisory: "1.26.3",
			All: &Target{Version: "28.3.0", Fixes: 151, Total: 152, NewLine: true}}},
		{"only the new line fixes it", "28.0.0", tg, Step{Version: "28.3.0", Fixes: 151, Total: 152, NewLine: true, Advisory: "28.0.0"}},
		{"the fix is the target", "1.2.4", &Target{Version: "1.2.4", Fixes: 2, Total: 2}, Step{Version: "1.2.4", Fixes: 2, Total: 2}},
		{"no target", "1.2.4", nil, Step{Version: "1.2.4", Fixes: 1, Total: 1}},
		{"target below its fix", "3.0.0", &Target{Version: "2.5.0", Fixes: 4, Total: 5}, Step{Version: "3.0.0", Fixes: 1, Total: 5}},
	}
	for _, c := range cases {
		got := step(version.SemVer, c.fixedIn, c.target, nil)
		if got == nil {
			t.Errorf("%s: no step", c.name)
			continue
		}
		gotAll, wantAll := got.All, c.want.All
		got.All, c.want.All = nil, nil
		if *got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, *got, c.want)
		}
		if (gotAll == nil) != (wantAll == nil) || (gotAll != nil && *gotAll != *wantAll) {
			t.Errorf("%s: all = %+v, want %+v", c.name, gotAll, wantAll)
		}
	}
	if s := step(version.SemVer, "", tg, nil); s != nil {
		t.Errorf("a finding nothing fixes got a step: %+v", s)
	}
	// Through Match: every affected finding of a version carries it.
	a := app(version.SemVer)
	fs := Match(Input{App: a, Version: "1.2.0"}, []Advisory{ghsa("GHSA-1", nil, "< 1.2.3", "1.2.3"), ghsa("GHSA-2", nil, "< 1.2.1", "1.2.1")}, Enrichment{})
	for _, f := range fs {
		if f.Step == nil || f.Step.Version != "1.2.3" || f.Step.Fixes != 2 {
			t.Errorf("%s: step %+v", f.AdvisoryID, f.Step)
		}
	}
	if fs[1].Step.Advisory != "1.2.1" || fs[0].Step.Advisory != "" {
		t.Errorf("advisory versions: %q %q", fs[0].Step.Advisory, fs[1].Step.Advisory)
	}
}

// A flaw fixed in 1.1.0 and affected again from 1.2.0 to 2.0.0: an update
// chosen for the other findings that lies in the second range is not this
// finding's update, although it is above its fixed version.
func TestStepStaysOutOfALaterAffectedRange(t *testing.T) {
	a := app(version.SemVer)
	twice := Advisory{Source: "github", CVSS: 7.5, Vuln: advisory.Vulnerability{ID: "GHSA-twice",
		Affected: []advisory.Affected{{Package: advisory.Package{Name: "app"}, Ranges: []advisory.Range{
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.1.0"}}},
			{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "1.2.0"}, {Fixed: "2.0.0"}}},
		}}}}}
	advs := []Advisory{twice, ghsa("GHSA-b", nil, "< 1.2.1", "1.2.1"), ghsa("GHSA-c", nil, "< 1.2.1", "1.2.1")}
	var got Finding
	for _, f := range Match(Input{App: a, Version: "1.0.0"}, advs, Enrichment{}) {
		if f.AdvisoryID == "GHSA-twice" {
			got = f
		}
	}
	if got.Step == nil || got.FixedIn != "1.1.0" {
		t.Fatalf("finding: fixed %q step %+v", got.FixedIn, got.Step)
	}
	// 2.0.0 fixes all three; on the running line 1.2.1 fixes the two
	// others, but this flaw affects it again.
	tg := got.Target
	if tg == nil || tg.Version != "2.0.0" || tg.Fixes != 3 || tg.Line == nil || tg.Line.Version != "1.2.1" || tg.Line.Fixes != 2 {
		t.Fatalf("target = %+v (line %+v), want 2.0.0 fixing 3 with 1.2.1 on the line", tg, tg.Line)
	}
	if got.Step.Version == "1.2.1" {
		t.Fatalf("the step names a version the flaw affects: %+v", got.Step)
	}
	if got.Step.Version != "2.0.0" || !got.Step.NewLine || got.Step.Fixes != 3 {
		t.Errorf("step = %+v, want 2.0.0 on the new line", got.Step)
	}
	// The two others stay on the line, where their fix is.
	for _, f := range Match(Input{App: a, Version: "1.0.0"}, advs, Enrichment{}) {
		if f.AdvisoryID != "GHSA-twice" && (f.Step == nil || f.Step.Version != "1.2.1") {
			t.Errorf("%s: step %+v, want 1.2.1", f.AdvisoryID, f.Step)
		}
	}
}
