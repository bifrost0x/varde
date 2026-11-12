// SPDX-License-Identifier: Apache-2.0

package version

import (
	"errors"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	cases := []struct {
		scheme Scheme
		in     string
		want   string
	}{
		{SemVer, "1.2.3", "1.2.3"},
		{SemVer, "v1.120.0", "1.120.0"},
		{SemVer, "V2.0", "2.0"},
		{SemVer, "4.0.11.2680", "4.0.11.2680"},
		{SemVer, "1.0.0-rc.1", "1.0.0-rc.1"},
		{SemVer, "1.0.0-beta-2", "1.0.0-beta-2"},
		{SemVer, "1.0.0+build.5", "1.0.0"},
		{SemVer, "1.0.0-alpha+001", "1.0.0-alpha"},
		{SemVer, "0.107.55", "0.107.55"},
		{SemVer, "01.02.03", "1.2.3"},
		{SemVer, "7", "7"},
		{CalVer, "2026.11.1", "2026.11.1"},
		{CalVer, "2024.10", "2024.10"},
		{CalVer, "2025.1.0b3", ""}, // see TestParseInvalid
	}
	for _, c := range cases {
		if c.want == "" {
			continue
		}
		v, err := Parse(c.scheme, c.in)
		if err != nil {
			t.Errorf("Parse(%s, %q): %v", c.scheme, c.in, err)
			continue
		}
		if v.String() != c.want || v.Raw() != c.in || v.Scheme() != c.scheme {
			t.Errorf("Parse(%s, %q) = %q (raw %q)", c.scheme, c.in, v.String(), v.Raw())
		}
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []struct {
		scheme Scheme
		in     string
	}{
		{SemVer, ""},
		{SemVer, "latest"},
		{SemVer, "main"},
		{SemVer, "1..2"},
		{SemVer, "1.2.3.4.5.6"},
		{SemVer, "1.2.x"},
		{SemVer, "1.2.3-"},
		{SemVer, "1.2.3-a..b"},
		{SemVer, "1.2.3+"},
		{SemVer, "1.2.3-ä"},
		{SemVer, "-1.2"},
		{SemVer, "v"},
		{SemVer, "1.2.3 "},
		{SemVer, "99999999999999999999.1"},
		{SemVer, strings.Repeat("1.", 100) + "1"},
		{CalVer, "1.2.3"},
		{CalVer, "2026"},
		{CalVer, "2026.13.1"},
		{CalVer, "2026.0.1"},
		{CalVer, "202.1.1"},
		{CalVer, "2025.1.0b3"},
		{"pep440", "1.0"},
	}
	for _, c := range cases {
		if _, err := Parse(c.scheme, c.in); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%s, %q): err=%v, want ErrInvalid", c.scheme, c.in, err)
		}
	}
}

func TestCompareOrder(t *testing.T) {
	// Strictly ascending under semver precedence.
	ordered := []string{
		"0.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0",
		"1.10.0", "1.120.0", "2.0.0", "4.0.11.2680", "4.0.11.2681", "4.1",
	}
	for i := range ordered {
		for j := range ordered {
			a, b := MustParse(SemVer, ordered[i]), MustParse(SemVer, ordered[j])
			got, ok := a.Compare(b)
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if !ok || got != want {
				t.Errorf("Compare(%s, %s) = %d,%v want %d", ordered[i], ordered[j], got, ok, want)
			}
		}
	}
}

func TestCompareEquivalence(t *testing.T) {
	for _, pair := range [][2]string{{"1.2", "1.2.0"}, {"v1.2.3", "1.2.3"}, {"1.2.3+a", "1.2.3+b"}, {"1.2.3", "1.2.3.0"}} {
		c, ok := MustParse(SemVer, pair[0]).Compare(MustParse(SemVer, pair[1]))
		if !ok || c != 0 {
			t.Errorf("%s vs %s: %d,%v", pair[0], pair[1], c, ok)
		}
	}
	c, ok := MustParse(CalVer, "2026.9.0").Compare(MustParse(CalVer, "2026.11.0"))
	if !ok || c != -1 {
		t.Errorf("calver month order: %d,%v", c, ok)
	}
}

func TestCompareIncomparable(t *testing.T) {
	if _, ok := MustParse(SemVer, "2026.1.0").Compare(MustParse(CalVer, "2026.1.0")); ok {
		t.Error("cross-scheme comparison reported ok")
	}
	if _, ok := (Version{}).Compare(MustParse(SemVer, "1.0")); ok {
		t.Error("zero value comparison reported ok")
	}
}

// TestCompareProperties checks antisymmetry, reflexivity and transitivity
// on random versions; a sort must also be consistent.
func TestCompareProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test data
	vs := make([]Version, 300)
	for i := range vs {
		vs[i] = MustParse(SemVer, randomVersion(r))
	}
	for _, a := range vs {
		if c, _ := a.Compare(a); c != 0 { //nolint:gocritic // reflexivity check
			t.Fatalf("not reflexive: %s", a)
		}
		for _, b := range vs {
			ab, _ := a.Compare(b)
			ba, _ := b.Compare(a)
			if ab != -ba {
				t.Fatalf("not antisymmetric: %s %s", a, b)
			}
		}
	}
	for i := 0; i < 20000; i++ {
		a, b, c := vs[r.IntN(len(vs))], vs[r.IntN(len(vs))], vs[r.IntN(len(vs))]
		ab, _ := a.Compare(b)
		bc, _ := b.Compare(c)
		ac, _ := a.Compare(c)
		if ab <= 0 && bc <= 0 && ac > 0 {
			t.Fatalf("not transitive: %s <= %s <= %s but %s > %s", a, b, c, a, c)
		}
	}
	sort.SliceStable(vs, func(i, j int) bool { c, _ := vs[i].Compare(vs[j]); return c < 0 })
	for i := 1; i < len(vs); i++ {
		if c, _ := vs[i-1].Compare(vs[i]); c > 0 {
			t.Fatalf("sort inconsistent at %d: %s > %s", i, vs[i-1], vs[i])
		}
	}
}

func randomVersion(r *rand.Rand) string {
	n := 1 + r.IntN(4)
	parts := make([]string, n)
	for i := range parts {
		parts[i] = []string{"0", "1", "2", "10", "11"}[r.IntN(5)]
	}
	s := strings.Join(parts, ".")
	if r.IntN(3) == 0 {
		pre := []string{"alpha", "beta", "rc", "1", "2", "alpha.1", "rc.10", "x-y"}
		s += "-" + pre[r.IntN(len(pre))]
	}
	return s
}

func TestIsFloating(t *testing.T) {
	for _, tag := range []string{"latest", "LATEST", "stable", "release", "main", "nightly", "develop", "latest-alpine", "stable-arm64", "", "edge", "pr", "alpine"} {
		if !IsFloating(tag) {
			t.Errorf("%q should be floating", tag)
		}
	}
	for _, tag := range []string{"1.2.3", "v1.120.0", "2026.11.1", "4.0.11.2680-ls262", "30", "release-4.0.11.2680"} {
		if IsFloating(tag) {
			t.Errorf("%q should not be floating", tag)
		}
	}
}

func TestNormaliseLSIO(t *testing.T) {
	cases := map[string]string{
		"4.0.11.2680-ls262": "4.0.11.2680",
		"v1.32.0-ls5":       "v1.32.0",
		"Linuxserver.io version:- 4.0.11.2680-ls262 Build-date:- 2024-11-02T05:41:35+00:00": "4.0.11.2680",
		"Linuxserver.io version: 1.2.3-ls12 Build-date: 2024":                               "1.2.3",
		"1.2.3":            "1.2.3",
		"12.4ubu2604-ls58": "12.4",
		"Linuxserver.io version:- 12.4ubu2604-ls58 Build-date:- 2026": "12.4",
	}
	for in, want := range cases {
		got, ok := Normalise(NormaliserLSIO, in)
		if !ok || got != want {
			t.Errorf("Normalise(lsio, %q) = %q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := Normalise("bogus", "1"); ok {
		t.Error("unknown normaliser accepted")
	}
	if s, ok := Normalise("", "x"); !ok || s != "x" {
		t.Error("empty normaliser must be identity")
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"1.2.3", "v1.0.0-rc.1+b", "2026.11.1", "4.0.11.2680", "1..", "-", "+", "v", "1.2.3-a.b.c.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, scheme := range []Scheme{SemVer, CalVer} {
			v, err := Parse(scheme, s)
			if err != nil {
				continue
			}
			if c, ok := v.Compare(v); !ok || c != 0 { //nolint:gocritic // reflexivity check
				t.Fatalf("not reflexive: %q", s)
			}
			// The canonical form must parse to an equivalent version.
			w, err := Parse(scheme, v.String())
			if err != nil {
				t.Fatalf("canonical form %q of %q does not parse: %v", v.String(), s, err)
			}
			if c, ok := v.Compare(w); !ok || c != 0 {
				t.Fatalf("canonical form %q of %q not equivalent", v.String(), s)
			}
		}
	})
}

func FuzzCompare(f *testing.F) {
	f.Add("1.2.3", "1.2.3-rc.1")
	f.Add("1.0", "1.0.0")
	f.Add("1.0.0-alpha.1", "1.0.0-alpha.beta")
	f.Fuzz(func(t *testing.T, a, b string) {
		va, errA := Parse(SemVer, a)
		vb, errB := Parse(SemVer, b)
		if errA != nil || errB != nil {
			return
		}
		ab, ok1 := va.Compare(vb)
		ba, ok2 := vb.Compare(va)
		if !ok1 || !ok2 || ab != -ba {
			t.Fatalf("antisymmetry violated for %q %q: %d %d", a, b, ab, ba)
		}
	})
}

func FuzzNormaliseLSIO(f *testing.F) {
	f.Add("Linuxserver.io version:- 4.0.11.2680-ls262 Build-date:- 2024")
	f.Add("1.2.3-ls1")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Normalise(NormaliserLSIO, s)
	})
}

func TestIsDevelopment(t *testing.T) {
	for _, tag := range []string{"main", "nightly", "dev", "nightly-alpine", "Edge"} {
		if !IsDevelopment(tag) {
			t.Errorf("%q should be development", tag)
		}
	}
	for _, tag := range []string{"latest", "stable", "release", "1.2.3", "dev-1.2.3", "", "lts"} {
		if IsDevelopment(tag) {
			t.Errorf("%q should not be development", tag)
		}
	}
}
