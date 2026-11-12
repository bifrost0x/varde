// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

// Cases follow Debian Policy 5.6.12 and the dpkg test suite: "~" before the
// end, epochs first, revisions last.
func TestCompareDpkg(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0a", -1},
		{"1:0.1", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"2.30-12", "2.30-12+deb12u1", -1},
		{"1.22.1-9", "1.22.1-9+deb12u1", -1},
		{"1.2.10", "1.2.9", 1},
		{"1.0.0", "1.0", 1},
		{"001.0", "1.0", 0},
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1},
		{"1.0+dfsg-1", "1.0-1", 1},
	} {
		if got := CompareDpkg(c.a, c.b); got != c.want {
			t.Errorf("dpkg %s vs %s: %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareDpkg(c.b, c.a); got != -c.want {
			t.Errorf("dpkg %s vs %s (reversed): %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

// Cases from rpm's rpmvercmp tests.
func TestCompareRPM(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p10", -1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10.1", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0^", "1.0", 1},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0^git1", "1.01", -1},
		{"1:1.0", "2.0", 1},
		{"2.15.0-13.fc42", "2.15.0-14.fc42", -1},
		{"1.0a", "1.0.1", -1},
	} {
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("rpm %s vs %s: %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareRPM(c.b, c.a); got != -c.want {
			t.Errorf("rpm %s vs %s (reversed): %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareAPK(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3-r0", "1.2.3-r1", -1},
		{"1.2.3_rc1", "1.2.3", -1},
		{"1.2.3_alpha1", "1.2.3_beta1", -1},
		{"1.2.3_p1", "1.2.3", 1},
		{"1.2.10", "1.2.9", 1},
		{"1.2a", "1.2", 1},
		{"3.7.0-r0", "3.7.0-r0", 0},
		{"1.2", "1.2.1", -1},
	} {
		got, ok := CompareAPK(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("apk %s vs %s: %d %v, want %d", c.a, c.b, got, ok, c.want)
		}
		if got, _ := CompareAPK(c.b, c.a); got != -c.want {
			t.Errorf("apk %s vs %s (reversed): %d, want %d", c.b, c.a, got, -c.want)
		}
	}
	if _, ok := CompareAPK("1.2.3-foo", "1.0"); ok {
		t.Error("invalid apk version accepted")
	}
}
