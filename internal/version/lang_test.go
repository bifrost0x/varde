// SPDX-License-Identifier: Apache-2.0

package version

import (
	"strings"
	"testing"
)

type compareFunc func(a, b string) (int, bool)

var langSchemes = map[string]compareFunc{
	"pep440":   ComparePEP440,
	"maven":    CompareMaven,
	"rubygems": CompareRubyGems,
	"nuget":    CompareNuGet,
	"composer": CompareComposer,
	"cargo":    CompareCargo,
}

type langCase struct {
	a, b string
	want int
}

// checkPairs checks each case and its reverse.
func checkPairs(t *testing.T, name string, f compareFunc, cases []langCase) {
	t.Helper()
	for _, c := range cases {
		got, ok := f(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("%s %q vs %q: %d (ok %v), want %d", name, c.a, c.b, got, ok, c.want)
		}
		got, ok = f(c.b, c.a)
		if !ok || got != -c.want {
			t.Errorf("%s %q vs %q (reversed): %d (ok %v), want %d", name, c.b, c.a, got, ok, -c.want)
		}
	}
}

// checkOrder checks that list is strictly ascending, over all pairs.
func checkOrder(t *testing.T, name string, f compareFunc, list []string) {
	t.Helper()
	for i := range list {
		for j := range list {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got, ok := f(list[i], list[j]); !ok || got != want {
				t.Errorf("%s %q vs %q: %d (ok %v), want %d", name, list[i], list[j], got, ok, want)
			}
		}
	}
}

// checkInvalid checks that every bad version is rejected on either side.
func checkInvalid(t *testing.T, name string, f compareFunc, valid string, bad []string) {
	t.Helper()
	if _, ok := f(valid, valid); !ok {
		t.Fatalf("%s: reference %q rejected", name, valid)
	}
	for _, s := range bad {
		if c, ok := f(s, valid); ok {
			t.Errorf("%s %q vs %q: accepted (%d), want ok=false", name, s, valid, c)
		}
		if c, ok := f(valid, s); ok {
			t.Errorf("%s %q vs %q: accepted (%d), want ok=false", name, valid, s, c)
		}
	}
}

// The ordering list is the one from pypa/packaging's test suite.
func TestComparePEP440(t *testing.T) {
	checkOrder(t, "pep440", ComparePEP440, []string{
		"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12",
		"1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456", "1.0b2.post345", "1.0b2-346",
		"1.0c1.dev456", "1.0c1", "1.0rc2", "1.0c3", "1.0",
		"1.0.post456.dev34", "1.0.post456", "1.1.dev1",
		"1.2+123abc", "1.2+123abc456", "1.2+abc", "1.2+abc123", "1.2+abc123def",
		"1.2+1234.abc", "1.2+123456", "1.2.r32+123456", "1.2.rev33+123456",
		"1!1.0b2.post345.dev456", "1!1.0",
	})
	checkPairs(t, "pep440", ComparePEP440, []langCase{
		{"1.0", "1.0.0", 0},
		{"1.0", "1.0.0.0.0", 0},
		{"1.0", "v1.0", 0},
		{" 1.0\n", "1.0", 0},
		{"0!1.0", "1.0", 0},
		{"1.0a1", "1.0alpha1", 0},
		{"1.0a1", "1.0-a-1", 0},
		{"1.0a1", "1.0.ALPHA.1", 0},
		{"1.0b1", "1.0_beta_1", 0},
		{"1.0rc1", "1.0c1", 0},
		{"1.0rc1", "1.0pre1", 0},
		{"1.0rc1", "1.0-preview.1", 0},
		{"1.0a", "1.0a0", 0},
		{"1.0.post1", "1.0-1", 0},
		{"1.0.post1", "1.0rev1", 0},
		{"1.0.post1", "1.0.r1", 0},
		{"1.0.post1", "1.0-post-1", 0},
		{"1.0.post", "1.0.post0", 0},
		{"1.0.dev", "1.0.dev0", 0},
		{"1.0.DEV1", "1.0.dev1", 0},
		{"1.0+ubuntu-1", "1.0+ubuntu.1", 0},
		{"1.0+ubuntu_1", "1.0+UBUNTU.1", 0},
		{"1.0+01", "1.0+1", 0},
		{"1.0.dev0", "1.0a0", -1},
		{"1.0a1.dev1", "1.0a1", -1},
		{"1.0.post1.dev1", "1.0.post1", -1},
		{"1.0.post1.dev1", "1.0", 1},
		{"1.0", "1.0+local", -1},
		{"1.0+abc", "1.0+abc.1", -1},
		{"1.0+9", "1.0+10", -1},
		{"1.9", "1.10", -1},
		{"2.0", "1.99999999999999999999999999", 1},
		{"1!0.1", "2.0", 1},
		{"2.31.0", "2.32.0", -1},
		{"3.2.25", "4.0a1", -1},
		{"41.0.4", "41.0.5", -1},
		{"0.0.0", "0", 0},
	})
	checkInvalid(t, "pep440", ComparePEP440, "1.0", []string{
		"", "  ", "abc", "1.0-", "1.0+", "1..0", ".1", "1.0 a1", "1.0+abc!", "1.0+a..b",
		"1.0.post1.post2", "1.0a1a2", "1.0-dev-dev", "vv1.0", "1.0.foo", "1.0.*",
		strings.Repeat("1", maxLangLength+1),
	})
}

func TestCompareMaven(t *testing.T) {
	// Qualifier order from Maven's ComparableVersionTest.
	checkOrder(t, "maven", CompareMaven, []string{
		"1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123",
		"1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp",
		"1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot", "1-1", "1-2", "1-123",
	})
	checkOrder(t, "maven", CompareMaven, []string{
		"1.0-alpha-1", "1.0-beta-1", "1.0-M1", "1.0-RC1", "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.0-1", "1.0.1",
	})
	checkPairs(t, "maven", CompareMaven, []langCase{
		{"1", "1.0", 0},
		{"1", "1.0.0", 0},
		{"1", "1-0", 0},
		{"1.0.RELEASE", "1.0", 0},
		{"5.3.20.RELEASE", "5.3.20", 0},
		{"2.0.0.Final", "2.0.0", 0},
		{"1.0-ga", "1.0", 0},
		{"1.0-final", "1", 0},
		{"1.0-cr1", "1.0-rc1", 0},
		{"1.0a1", "1.0-alpha-1", 0},
		{"1.0-b2", "1.0-beta2", 0},
		{"1.0-m3", "1.0-milestone-3", 0},
		{"1.0-ALPHA1", "1.0-alpha1", 0},
		{"1.0..1", "1.0.0.1", 0},
		{"1.01", "1.1", 0},
		{"1.0-alpha-1", "1.0", -1},
		{"1.0", "1.0-sp1", -1},
		{"31.1-jre", "32.0-jre", -1},
		{"32.0-android", "32.0-jre", -1},
		{"32.0.1-jre", "32.0-jre", 1},
		{"5.3.9", "5.3.10", -1},
		{"2.12.7.1", "2.12.7", 1},
		{"2.13.4.2", "2.13.4", 1},
		{"2.17.0", "2.17.1", -1},
		{"2.0.0-M1", "2.0.0", -1},
		{"9.4.50.v20221201", "9.4.51.v20230217", -1},
		{"1.2.3-1", "1.2.3", 1},
		{"1.0-SNAPSHOT", "1.0-RC1", 1},
		{"1.0.1", "1.0-sp", 1},
		{"1.0-xyz", "1.0-sp", 1},
		{"12345678901234567890", "12345678901234567891", -1},
	})
	checkInvalid(t, "maven", CompareMaven, "1.0", []string{
		"", " ", "1.0 beta", "1.0\x00", "1.0\tb", strings.Repeat("1.", 129),
	})
}

func TestCompareRubyGems(t *testing.T) {
	checkOrder(t, "rubygems", CompareRubyGems, []string{
		"0.9", "1.0.0.a", "1.0.0.a9", "1.0.0.a10", "1.0.0.b", "1.0.0.beta", "1.0.0.pre",
		"1.0.0.rc1", "1.0.0.rc2", "1.0.0.rc10", "1.0.0", "1.0.0.1", "1.0.1", "1.9.3", "1.10",
	})
	checkPairs(t, "rubygems", CompareRubyGems, []langCase{
		{"1", "1.0", 0},
		{"1.0", "1.0.0", 0},
		{"1.0.0.a", "1.0.a", 0},
		{"1.2b3", "1.2.b3", 0},
		{"1.2.b3", "1.2.b.3", 0},
		{"2.0.0.a.0", "2.0.0.a", 0},
		{" 1.0 ", "1.0", 0},
		{"1.0.0-1", "1.0.0", -1},
		{"1.0.0-1", "1.0.0.pre.1", 0},
		{"1.0.A", "1.0.a", -1},
		{"1.0.a", "1", -1},
		{"5.2.4.3", "5.2.4", 1},
		{"7.0.8.1", "7.0.8", 1},
		{"6.1.7.6", "7.0.0", -1},
		{"7.1.0.rc1", "7.0.8.4", 1},
		{"1.13.10", "1.13.9", 1},
		{"1.0.01", "1.0.1", 0},
	})
	checkInvalid(t, "rubygems", CompareRubyGems, "1.0", []string{
		"", "a1", "1..0", "1.0-", "1.0 a", "1.0_1", ".1", "1.", "1.0+b",
		strings.Repeat("1.", 129),
	})
}

func TestCompareNuGet(t *testing.T) {
	// SemVer 2 precedence example, then NuGet specifics.
	checkOrder(t, "nuget", CompareNuGet, []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.0.1-beta", "1.0.0.1", "1.0.1",
	})
	checkPairs(t, "nuget", CompareNuGet, []langCase{
		{"1", "1.0", 0},
		{"1.0", "1.0.0", 0},
		{"1.0.0", "1.0.0.0", 0},
		{"1.0.0-alpha", "1.0.0-ALPHA", 0},
		{"1.0.0+build.5", "1.0.0", 0},
		{"1.0.0-rc.1+sha.abc", "1.0.0-rc.1", 0},
		{"01.0", "1.0", 0},
		{"4.0.0.1", "4.0.0", 1},
		{"6.0.0-preview.7.21377.19", "6.0.0-rc.1.21451.13", -1},
		{"13.0.1", "12.0.3", 1},
		{"4.7.2", "4.7.10", -1},
		{"1.0.0-beta1", "1.0.0-beta2", -1},
	})
	checkInvalid(t, "nuget", CompareNuGet, "1.0.0", []string{
		"", "1.0.0.0.0", "v1.0", "1.0.0-", "1.0.0-a..b", "1.0.0+", "1.0.0-al_pha", "1..0", "a",
	})
}

func TestCompareComposer(t *testing.T) {
	checkOrder(t, "composer", CompareComposer, []string{
		"2.0.0-alpha", "2.0.0-alpha2", "2.0.0-beta", "2.0.0-beta1", "2.0.0-beta1.1", "2.0.0-beta2",
		"2.0.0-beta10", "2.0.0-RC1", "2.0.0", "2.0.0-p1", "2.0.0-patch2", "2.0.0.1", "2.0.1",
	})
	checkPairs(t, "composer", CompareComposer, []langCase{
		{"v1.0.0", "1.0.0", 0},
		{"1.0", "1.0.0.0", 0},
		{"1.0.0-a1", "1.0.0-alpha1", 0},
		{"1.0.0-b2", "1.0.0-beta2", 0},
		{"1.0.0-RC1", "1.0.0-rc.1", 0},
		{"1.0.0RC1", "1.0.0-RC1", 0},
		{"1.0.0.RC1", "1.0.0-RC1", 0},
		{"1.0.0-pl1", "1.0.0-patch1", 0},
		{"1.0.0-stable", "1.0.0", 0},
		{"1.0.0+build", "1.0.0", 0},
		{"5.4.10", "5.4.9", 1},
		{"10.48.4", "9.52.16", 1},
		{"1.0.0-beta.2", "1.0.0-beta-2", 0},
	})
	checkInvalid(t, "composer", CompareComposer, "1.0.0", []string{
		"", "dev-main", "dev-master", "1.x-dev", "2.0.0-dev", "1.0.x-dev", "1.0.0-beta1-dev",
		"1.0.0.0.0", "1.0.0-foo", "1.0.0 as 2.0", "1.x", "v", "*",
	})
}

func TestCompareCargo(t *testing.T) {
	// The precedence example from the SemVer 2 specification, section 11.
	checkOrder(t, "cargo", CompareCargo, []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.9.0", "1.10.0", "1.11.0", "2.0.0",
	})
	checkPairs(t, "cargo", CompareCargo, []langCase{
		{"1.0.0+build", "1.0.0", 0},
		{"1.0.0-rc.1+build.1", "1.0.0-rc.1+build.2", 0},
		{"1.0.0-Alpha", "1.0.0-alpha", -1},
		{"1.0.0-1a", "1.0.0-1", 1},
		{"0.3.21", "0.3.3", 1},
		{"1.28.0", "1.29.1", -1},
		{"0.0.0", "0.0.1", -1},
	})
	checkInvalid(t, "cargo", CompareCargo, "1.0.0", []string{
		"", "1", "1.0", "01.0.0", "1.00.0", "1.0.0-01", "v1.0.0", "1.0.0-", "1.0.0.0",
		"1.0.0-a..b", "1.0.0+", "1.0.0-a_b",
	})
	if c, ok := CompareCargo(" 1.0.0 ", "1.0.0"); !ok || c != 0 {
		t.Errorf("cargo: surrounding whitespace not trimmed: %d %v", c, ok)
	}
}

// TestCompareLangLimits checks the length cap and hostile input on every
// scheme: no panic, ok=false beyond the cap, antisymmetry on what parses.
func TestCompareLangLimits(t *testing.T) {
	long := strings.Repeat("1", maxLangLength+1)
	atCap := strings.Repeat("9", maxLangLength)
	hostile := []string{
		strings.Repeat("-", maxLangLength), strings.Repeat(".", maxLangLength),
		strings.Repeat("a1", maxLangLength/2), strings.Repeat("1.", maxLangLength/2),
		strings.Repeat("1-", maxLangLength/2), "\xff\xfe", "ä1.0", "1.0 ",
	}
	for name, f := range langSchemes {
		if _, ok := f(long, "1.0.0"); ok {
			t.Errorf("%s: input over %d bytes accepted", name, maxLangLength)
		}
		if _, ok := f("1.0.0", long); ok {
			t.Errorf("%s: input over %d bytes accepted", name, maxLangLength)
		}
		for _, h := range append(hostile, atCap, "1.0.0") {
			x, okx := f(h, "1.0.0")
			y, oky := f("1.0.0", h)
			if okx != oky || x != -y {
				t.Errorf("%s %q: not antisymmetric: %d/%v vs %d/%v", name, h, x, okx, y, oky)
			}
		}
	}
	if c, ok := ComparePEP440(atCap, "1.0"); !ok || c != 1 {
		t.Errorf("pep440: %d-digit release: %d %v", maxLangLength, c, ok)
	}
}

func FuzzCompareLang(f *testing.F) {
	for _, s := range []string{"1.0", "1.0a1", "1.0-alpha-1", "1.0.0-rc.1+b", "v2.0.0-beta2", "1!2.0.post1.dev3+l.1", "1-sp-1"} {
		f.Add(s, "1.0.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		for name, cmp := range langSchemes {
			x, okx := cmp(a, b)
			y, oky := cmp(b, a)
			if okx != oky || x != -y {
				t.Fatalf("%s %q vs %q: %d/%v, reversed %d/%v", name, a, b, x, okx, y, oky)
			}
			if okx && x != -1 && x != 0 && x != 1 {
				t.Fatalf("%s %q vs %q: result %d", name, a, b, x)
			}
		}
	})
}
