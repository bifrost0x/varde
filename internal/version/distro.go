// SPDX-License-Identifier: Apache-2.0

package version

import (
	"regexp"
	"strconv"
	"strings"
)

// Distribution package versions follow their package manager's rules, not
// semantic versioning: "1:2.4.57-2+deb12u1" (dpkg), "2.15.0-13.fc42" (rpm),
// "3.7.0-r0" (apk). Distribution security data states fixed versions in
// these forms, so they must be compared with these rules (ADR 0022).

// CompareDpkg compares two Debian package versions as dpkg does (Debian
// Policy 5.6.12): epoch numerically, then upstream version and revision
// with "~" sorting before everything, even the end of the string.
func CompareDpkg(a, b string) int {
	ea, ua, ra := splitDpkg(a)
	eb, ub, rb := splitDpkg(b)
	if ea != eb {
		return sign(ea < eb)
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDpkg(v string) (epoch uint64, upstream, revision string) {
	v = strings.TrimSpace(v)
	if e, rest, ok := strings.Cut(v, ":"); ok {
		if n, err := strconv.ParseUint(e, 10, 64); err == nil {
			epoch, v = n, rest
		}
	}
	upstream = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	}
	return epoch, upstream, revision
}

// dpkgOrder is dpkg's order(): digits 0, letters their value, "~" below
// the end of the string, other characters above all letters.
func dpkgOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func isDigit(s string, i int) bool { return i < len(s) && s[i] >= '0' && s[i] <= '9' }

// verrevcmp is dpkg's comparison of an upstream version or a revision.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a, i)) || (j < len(b) && !isDigit(b, j)) {
			ac, bc := dpkgOrder(a, i), dpkgOrder(b, j)
			if ac != bc {
				return sign(ac < bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for isDigit(a, i) && isDigit(b, j) {
			if firstDiff == 0 && a[i] != b[j] {
				firstDiff = sign(a[i] < b[j])
			}
			i++
			j++
		}
		if isDigit(a, i) {
			return 1
		}
		if isDigit(b, j) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// CompareRPM compares two RPM versions "[epoch:]version[-release]" as rpm
// does (rpmvercmp for version and release, epoch numerically).
func CompareRPM(a, b string) int {
	ea, va, ra := splitRPM(a)
	eb, vb, rb := splitRPM(b)
	if ea != eb {
		return sign(ea < eb)
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	if ra == "" || rb == "" {
		// A version without release matches any release of it.
		return 0
	}
	return rpmvercmp(ra, rb)
}

func splitRPM(v string) (epoch uint64, version, release string) {
	v = strings.TrimSpace(v)
	if e, rest, ok := strings.Cut(v, ":"); ok {
		if n, err := strconv.ParseUint(e, 10, 64); err == nil {
			epoch, v = n, rest
		}
	}
	version = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		version, release = v[:i], v[i+1:]
	}
	return epoch, version, release
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// rpmvercmp follows rpm's segment comparison: alphanumeric segments,
// numeric ones compared as numbers and newer than alphabetic ones, "~"
// older and "^" newer than the end of the string.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ta, tb := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if ta || tb {
			if !ta {
				return 1
			}
			if !tb {
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		ca, cb := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if ca || cb {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case !ca:
				return 1
			case !cb:
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		num := isDigit(a, i)
		si, sj := i, j
		for i < len(a) && (num == isDigit(a, i)) && isAlnum(a[i]) {
			i++
		}
		for j < len(b) && (num == isDigit(b, j)) && isAlnum(b[j]) {
			j++
		}
		sa, sb := a[si:i], b[sj:j]
		if sb == "" {
			// Segments of different types: numeric is newer.
			if num {
				return 1
			}
			return -1
		}
		if num {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				return sign(len(sa) < len(sb))
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		return 1
	}
	return -1
}

// apkVersion is the grammar of Alpine package versions:
// numbers[letter](_suffix[n])*[~hash][-rN].
var apkVersion = regexp.MustCompile(`^(\d+(?:\.\d+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:~[0-9a-f]+)?(?:-r(\d+))?$`)

var apkSuffix = regexp.MustCompile(`_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)`)

// apkSuffixRank orders suffixes as apk-tools does: pre-release suffixes
// before the release, post-release ones after it.
var apkSuffixRank = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

// CompareAPK compares two Alpine package versions; ok is false when one is
// not a valid apk version.
func CompareAPK(a, b string) (int, bool) {
	ma, mb := apkVersion.FindStringSubmatch(strings.TrimSpace(a)), apkVersion.FindStringSubmatch(strings.TrimSpace(b))
	if ma == nil || mb == nil {
		return 0, false
	}
	na, nb := strings.Split(ma[1], "."), strings.Split(mb[1], ".")
	for k := 0; k < len(na) || k < len(nb); k++ {
		if k >= len(na) {
			return -1, true
		}
		if k >= len(nb) {
			return 1, true
		}
		x, _ := strconv.ParseUint(na[k], 10, 64)
		y, _ := strconv.ParseUint(nb[k], 10, 64)
		if x != y {
			return sign(x < y), true
		}
	}
	if ma[2] != mb[2] {
		return sign(ma[2] < mb[2]), true
	}
	sa, sb := apkSuffix.FindAllStringSubmatch(ma[3], -1), apkSuffix.FindAllStringSubmatch(mb[3], -1)
	for k := 0; k < len(sa) || k < len(sb); k++ {
		var ra, rb int
		var xa, xb uint64
		if k < len(sa) {
			ra = apkSuffixRank[sa[k][1]]
			xa, _ = strconv.ParseUint(sa[k][2], 10, 64)
		}
		if k < len(sb) {
			rb = apkSuffixRank[sb[k][1]]
			xb, _ = strconv.ParseUint(sb[k][2], 10, 64)
		}
		if ra != rb {
			return sign(ra < rb), true
		}
		if xa != xb {
			return sign(xa < xb), true
		}
	}
	x, _ := strconv.ParseUint(ma[4], 10, 64)
	y, _ := strconv.ParseUint(mb[4], 10, 64)
	if x != y {
		return sign(x < y), true
	}
	return 0, true
}
