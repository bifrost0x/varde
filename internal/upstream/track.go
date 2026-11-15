// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"regexp"
	"strconv"
	"strings"
)

// A version tag is read as prefix, version and the rest: "v1.2.3",
// "1.27.4-alpine3.20", "4.0.15.2941-ls276", "3.4.1-cuda". The rest holds the
// image variant and, where there is one, the pre-release.
var tagRe = regexp.MustCompile(`^([A-Za-z]*[-_]?)?(\d+(?:\.\d+){0,3})([-+_.].*)?$`)

// preRelease are the words that mark a pre-release in a tag's rest.
var preRelease = regexp.MustCompile(`(?i)^(rc|alpha|beta|pre|preview|dev|canary|nightly|snapshot|unstable|test)\d*$`)

// digits are the numbers in a variant: "alpine3.20" and "alpine3.21" are
// one variant on two base releases, "ls275" and "ls276" two builds.
var digits = regexp.MustCompile(`\d+`)

// tagVersion is a tag read for comparison.
type tagVersion struct {
	prefix  string
	nums    []int
	variant string // the variant with its numbers replaced: its class
	build   []int  // the numbers of the variant, a build or base release
	pre     bool
	preNums []int
}

// parseTag reads a version tag; ok is false for floating and other tags.
func parseTag(tag string) (tagVersion, bool) {
	m := tagRe.FindStringSubmatch(tag)
	if m == nil {
		return tagVersion{}, false
	}
	v := tagVersion{prefix: m[1]}
	for _, n := range strings.Split(m[2], ".") {
		i, err := strconv.Atoi(n)
		if err != nil {
			return tagVersion{}, false
		}
		v.nums = append(v.nums, i)
	}
	var variant []string
	afterPre := false
	for _, seg := range strings.FieldsFunc(m[3], func(r rune) bool { return r == '-' || r == '+' || r == '_' || r == '.' }) {
		switch {
		case preRelease.MatchString(seg):
			v.pre, afterPre = true, true
			v.preNums = append(v.preNums, numbers(seg)...)
			continue
		case afterPre && allDigits(seg):
			// "rc.2": the number belongs to the pre-release.
			v.preNums = append(v.preNums, numbers(seg)...)
			continue
		}
		afterPre = false
		variant = append(variant, seg)
	}
	joined := strings.ToLower(strings.Join(variant, "-"))
	v.variant = digits.ReplaceAllString(joined, "#")
	v.build = numbers(joined)
	// A rest that is only numbers ("1.2.3.4" read as 1.2.3 and ".4") is
	// part of the version.
	if v.variant != "" && strings.Trim(v.variant, "#-") == "" && !v.pre {
		return tagVersion{}, false
	}
	return v, true
}

func allDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func numbers(s string) []int {
	var out []int
	for _, d := range digits.FindAllString(s, -1) {
		if i, err := strconv.Atoi(d); err == nil {
			out = append(out, i)
		}
	}
	return out
}

// compareInts compares number lists; a missing number counts as zero.
func compareInts(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// compare orders two tags of one track: version, then a release before its
// pre-releases, then the build or base release of the variant.
func (v tagVersion) compare(o tagVersion) int {
	if c := compareInts(v.nums, o.nums); c != 0 {
		return c
	}
	switch {
	case v.pre && !o.pre:
		return -1
	case !v.pre && o.pre:
		return 1
	case v.pre && o.pre:
		if c := compareInts(v.preNums, o.preNums); c != 0 {
			return c
		}
	}
	return compareInts(v.build, o.build)
}

// sameLine reports whether o stays on v's release line: the same major
// version, and the same minor while the major is 0 (semantic versioning
// makes 0.x minors breaking).
func (v tagVersion) sameLine(o tagVersion) bool {
	if len(v.nums) == 0 || len(o.nums) == 0 || v.nums[0] != o.nums[0] {
		return false
	}
	if v.nums[0] == 0 {
		return len(v.nums) > 1 && len(o.nums) > 1 && v.nums[1] == o.nums[1]
	}
	return true
}

// Track returns the newest tag among tags that is newer than running and
// on its track: the same prefix and image variant ("-alpine" stays
// "-alpine", "-cuda" stays "-cuda"), the same major version unless
// crossMajor is set, and no pre-release unless running is one. ok is false
// when running is not a version tag (a floating tag has no track); newest
// is empty when nothing newer is on the track.
func Track(running string, tags []string, crossMajor bool) (newest string, ok bool) {
	run, ok := parseTag(running)
	if !ok || len(run.nums) == 1 {
		return "", false
	}
	var best tagVersion
	for _, t := range tags {
		c, ok := parseTag(t)
		if !ok || c.prefix != run.prefix || c.variant != run.variant || len(c.nums) != len(run.nums) {
			continue
		}
		if c.pre && !run.pre {
			continue
		}
		if !crossMajor && !run.sameLine(c) {
			continue
		}
		if c.compare(run) <= 0 {
			continue
		}
		if newest == "" || c.compare(best) > 0 {
			newest, best = t, c
		}
	}
	return newest, true
}

// Floating reports whether a tag names no version ("latest", "release",
// "stable") and may move to a rebuilt image at any time. A major-only tag
// such as "v3" counts as floating too: it moves with every release.
func Floating(tag string) bool {
	v, ok := parseTag(tag)
	return !ok || len(v.nums) == 1
}
