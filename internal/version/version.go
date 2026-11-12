// SPDX-License-Identifier: Apache-2.0

// Package version parses and compares app versions.
//
// Two schemes are supported. "semver" is tolerant dotted numeric: one to
// five numeric components (so 4-part versions like 4.0.11.2680 work),
// optional pre-release and build metadata, an optional leading "v".
// "calver" uses the same grammar but requires a four-digit year as the
// first component (2026.11.1). Missing trailing components compare as zero.
//
// Comparison is a total preorder and never panics: versions that are equal
// apart from build metadata or trailing zero components compare as 0.
package version

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Scheme names a versioning scheme.
type Scheme string

// Supported schemes.
const (
	SemVer Scheme = "semver"
	CalVer Scheme = "calver"
)

// Valid reports whether s is a supported scheme.
func (s Scheme) Valid() bool { return s == SemVer || s == CalVer }

const (
	maxComponents = 5
	maxLength     = 128
	maxDigits     = 18 // fits uint64 without overflow
)

// ErrInvalid wraps every parse failure.
var ErrInvalid = errors.New("invalid version")

// Version is a parsed version. The zero value is not a valid version.
type Version struct {
	scheme Scheme
	nums   []uint64
	pre    []ident
	raw    string
}

type ident struct {
	numeric bool
	num     uint64
	str     string
}

// Parse parses s under scheme.
func Parse(scheme Scheme, s string) (Version, error) {
	if !scheme.Valid() {
		return Version{}, fmt.Errorf("%w: unknown scheme %q", ErrInvalid, scheme)
	}
	raw := s
	if len(s) == 0 || len(s) > maxLength {
		return Version{}, fmt.Errorf("%w: length %d", ErrInvalid, len(s))
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !validIdents(s[i+1:]) {
			return Version{}, fmt.Errorf("%w: build metadata in %q", ErrInvalid, raw)
		}
		s = s[:i]
	}
	core, preStr, hasPre := strings.Cut(s, "-")

	parts := strings.Split(core, ".")
	if len(parts) > maxComponents {
		return Version{}, fmt.Errorf("%w: more than %d components in %q", ErrInvalid, maxComponents, raw)
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := parseNum(p)
		if !ok {
			return Version{}, fmt.Errorf("%w: component %q in %q", ErrInvalid, p, raw)
		}
		nums[i] = n
	}

	var pre []ident
	if hasPre {
		if !validIdents(preStr) {
			return Version{}, fmt.Errorf("%w: pre-release in %q", ErrInvalid, raw)
		}
		for _, p := range strings.Split(preStr, ".") {
			if n, ok := parseNum(p); ok {
				pre = append(pre, ident{numeric: true, num: n})
			} else {
				pre = append(pre, ident{str: p})
			}
		}
	}

	if scheme == CalVer {
		if len(parts[0]) != 4 || nums[0] < 1990 || nums[0] > 2999 || len(nums) < 2 || nums[1] < 1 || nums[1] > 12 {
			return Version{}, fmt.Errorf("%w: %q is not YYYY.M[.x]", ErrInvalid, raw)
		}
	}
	return Version{scheme: scheme, nums: nums, pre: pre, raw: raw}, nil
}

// MustParse is Parse for tests and constants; it panics on error.
func MustParse(scheme Scheme, s string) Version {
	v, err := Parse(scheme, s)
	if err != nil {
		panic(err)
	}
	return v
}

// Scheme returns the version's scheme.
func (v Version) Scheme() Scheme { return v.scheme }

// IsZero reports whether v is the zero value.
func (v Version) IsZero() bool { return v.nums == nil }

// Components returns the number of numeric components.
func (v Version) Components() int { return len(v.nums) }

// Prerelease reports whether v has a pre-release part.
func (v Version) Prerelease() bool { return len(v.pre) > 0 }

// String returns the canonical form: numeric components joined by dots,
// pre-release appended, no "v", no build metadata.
func (v Version) String() string {
	var b strings.Builder
	for i, n := range v.nums {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(n, 10))
	}
	for i, p := range v.pre {
		if i == 0 {
			b.WriteByte('-')
		} else {
			b.WriteByte('.')
		}
		if p.numeric {
			b.WriteString(strconv.FormatUint(p.num, 10))
		} else {
			b.WriteString(p.str)
		}
	}
	return b.String()
}

// SameLine reports whether o is on v's release line. Under SemVer the line is
// the major version, or major and minor for 0.x where minor releases may
// break. CalVer numbers carry no compatibility promise, so every release of
// the same scheme counts as the same line.
func (v Version) SameLine(o Version) bool {
	if v.IsZero() || o.IsZero() || v.scheme != o.scheme {
		return false
	}
	if v.scheme == CalVer {
		return true
	}
	if at(v.nums, 0) != at(o.nums, 0) {
		return false
	}
	return at(v.nums, 0) != 0 || at(v.nums, 1) == at(o.nums, 1)
}

// Raw returns the input as given to Parse.
func (v Version) Raw() string { return v.raw }

// Compare returns -1, 0 or +1. ok is false when the versions use different
// schemes or one of them is the zero value; such versions are incomparable.
func (v Version) Compare(o Version) (cmp int, ok bool) {
	if v.IsZero() || o.IsZero() || v.scheme != o.scheme {
		return 0, false
	}
	for i := 0; i < len(v.nums) || i < len(o.nums); i++ {
		a, b := at(v.nums, i), at(o.nums, i)
		if a != b {
			return sign(a < b), true
		}
	}
	// A version without pre-release ranks above any pre-release of it.
	switch {
	case len(v.pre) == 0 && len(o.pre) == 0:
		return 0, true
	case len(v.pre) == 0:
		return 1, true
	case len(o.pre) == 0:
		return -1, true
	}
	for i := 0; i < len(v.pre) && i < len(o.pre); i++ {
		if c := compareIdent(v.pre[i], o.pre[i]); c != 0 {
			return c, true
		}
	}
	switch {
	case len(v.pre) < len(o.pre):
		return -1, true
	case len(v.pre) > len(o.pre):
		return 1, true
	}
	return 0, true
}

func compareIdent(a, b ident) int {
	switch {
	case a.numeric && b.numeric:
		if a.num == b.num {
			return 0
		}
		return sign(a.num < b.num)
	case a.numeric:
		return -1 // numeric identifiers rank below alphanumeric ones
	case b.numeric:
		return 1
	}
	return strings.Compare(a.str, b.str)
}

func at(s []uint64, i int) uint64 {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func sign(less bool) int {
	if less {
		return -1
	}
	return 1
}

func parseNum(s string) (uint64, bool) {
	if s == "" || len(s) > maxDigits {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func validIdents(s string) bool {
	if s == "" {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' {
				return false
			}
		}
	}
	return true
}
