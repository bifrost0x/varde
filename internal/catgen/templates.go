// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"regexp"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/version"
)

// variantTail is the suffix of base-image variants ("-alpine3.20",
// "-bookworm-slim"), copied from the reviewed entries
// (catalog/apps/cyberchef.yaml) so generated rules read tags the same way.
const variantTail = `(?:-(?:alpine|bookworm|bullseye|trixie|noble|jammy|focal|oraclelinux|oracle|debian|slim|ubi|nanoserver|windowsservercore)[a-z0-9.]*)*$`

// minReleaseTags is how many tags of a rule must name a GitHub release
// before the rule is taken to read the project's release stream.
const minReleaseTags = 3

// Template is one of the fixed tag rules a generated entry may carry. A
// generated entry never gets a free-form regular expression.
type Template struct {
	// Pattern is the anchored regular expression with the named group v.
	Pattern string
	Scheme  version.Scheme

	re *regexp.Regexp
}

var templates = []Template{
	newTemplate(`^v?(?P<v>\d+\.\d+\.\d+)`+variantTail, version.SemVer),
	newTemplate(`^(?P<v>\d+\.\d+\.\d+)`+variantTail, version.SemVer),
	newTemplate(`^v?(?P<v>\d+\.\d+)`+variantTail, version.SemVer),
	newTemplate(`^(?P<v>\d{4}\.\d{1,2}\.\d{1,2})$`, version.CalVer),
}

func newTemplate(pattern string, scheme version.Scheme) Template {
	return Template{Pattern: pattern, Scheme: scheme, re: regexp.MustCompile(pattern)}
}

// Templates returns the fixed set of tag rules. Each one after the first
// two is narrower than or disjoint from the ones before it.
func Templates() []Template { return append([]Template(nil), templates...) }

// Version returns the version the template reads from a tag.
func (t Template) Version(tag string) (string, bool) {
	if t.re == nil {
		return "", false
	}
	return extract([]*regexp.Regexp{t.re}, tag)
}

// extract reads the version from a tag with the first rule that matches,
// as the catalog's extraction chain does.
func extract(rules []*regexp.Regexp, tag string) (string, bool) {
	for _, re := range rules {
		if m := re.FindStringSubmatch(tag); m != nil {
			return m[re.SubexpIndex("v")], true
		}
	}
	return "", false
}

var (
	floatingNames = map[string]bool{
		"latest": true, "stable": true, "edge": true, "nightly": true, "dev": true, "develop": true,
		"main": true, "master": true, "beta": true, "alpha": true, "rc": true, "testing": true, "unstable": true,
	}
	commitTag = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
)

// Floating reports a tag that moves between images or names a pre-release
// or a commit: a rule that matches one reads versions that are not
// releases.
func Floating(tag string) bool {
	t := strings.ToLower(tag)
	if floatingNames[t] || commitTag.MatchString(t) || strings.HasPrefix(t, "sha-") {
		return true
	}
	for _, s := range []string{"-rc", "-beta", "-alpha", "-dev"} {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}

// stream is what a tag rule makes of one image's tag list.
type stream struct {
	// matched are the tags the rule reads a version from.
	matched []string
	// released counts matched tags whose version is a GitHub release.
	released int
	// floating are matched tags that float.
	floating []string
	// newest is the matched tag with the highest version, newestVersion
	// that version; empty when no matched tag parses under the scheme.
	newest        string
	newestVersion version.Version
}

// passes is the tag part of C3: enough release tags, nothing floating, a
// newest tag. Whether that tag resolves is asked separately.
func (s stream) passes() bool {
	return s.released >= minReleaseTags && len(s.floating) == 0 && s.newest != ""
}

// releaseSet holds the versions of the GitHub releases (tag without a
// leading "v"); drafts are not published and do not count.
func releaseSet(rels []Release) map[string]bool {
	out := map[string]bool{}
	for _, r := range rels {
		if !r.Draft {
			out[stripV(r.Tag)] = true
		}
	}
	return out
}

func stripV(tag string) string {
	if strings.HasPrefix(tag, "v") || strings.HasPrefix(tag, "V") {
		return tag[1:]
	}
	return tag
}

// evaluate applies a tag rule to a tag list.
func evaluate(rules []*regexp.Regexp, scheme version.Scheme, tags []string, releases map[string]bool) stream {
	var s stream
	sorted := append([]string(nil), tags...)
	sort.Strings(sorted)
	for _, tag := range sorted {
		v, ok := extract(rules, tag)
		if !ok {
			continue
		}
		s.matched = append(s.matched, tag)
		if releases[stripV(v)] {
			s.released++
		}
		if Floating(tag) {
			s.floating = append(s.floating, tag)
		}
		pv, err := version.Parse(scheme, v)
		if err != nil {
			continue
		}
		// Of tags with the same version the shortest wins ("v1.2.3" over
		// "v1.2.3-alpine"), so the digest asked for is the plain image.
		c, _ := pv.Compare(s.newestVersion)
		if s.newest == "" || c > 0 || (c == 0 && len(tag) < len(s.newest)) {
			s.newest, s.newestVersion = tag, pv
		}
	}
	return s
}

// pickTemplate returns the narrowest template that passes the tag part of
// C3 for every tag list: the one matching the fewest tags in total. On a
// tie the later template wins, as it is the more specific one ("X.Y.Z"
// over "v?X.Y.Z" for tags without "v", the date template for date tags).
// The streams are in the order of the lists.
func pickTemplate(tagLists [][]string, releases map[string]bool) (Template, []stream, bool) {
	var best Template
	var bestStreams []stream
	bestCount := -1
	for _, t := range templates {
		streams := make([]stream, 0, len(tagLists))
		count := 0
		ok := true
		for _, tags := range tagLists {
			s := evaluate([]*regexp.Regexp{t.re}, t.Scheme, tags, releases)
			if !s.passes() {
				ok = false
				break
			}
			streams = append(streams, s)
			count += len(s.matched)
		}
		if ok && (bestCount < 0 || count <= bestCount) {
			best, bestStreams, bestCount = t, streams, count
		}
	}
	return best, bestStreams, bestCount >= 0
}
