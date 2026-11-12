// SPDX-License-Identifier: Apache-2.0

package match

import (
	"testing"

	"github.com/bifrost0x/varde/internal/version"
)

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
