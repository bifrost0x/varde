// SPDX-License-Identifier: Apache-2.0

package version

import (
	"regexp"
	"strings"
)

// Language package versions follow their registry's rules. OSV states
// affected ranges for PyPI, Maven, RubyGems, NuGet, Packagist and crates.io
// in these forms, so they are compared with these rules. Every comparison
// returns ok=false for a version that is not valid in its scheme.
//
// Numbers are compared as digit strings, never converted, so arbitrarily
// long components neither overflow nor fail. Inputs are capped at
// maxLangLength bytes; together with the linear-time regexp engine this
// bounds the work done on hostile input.

const maxLangLength = 256

// langInput trims s and rejects empty or oversized input.
func langInput(s string) (string, bool) {
	if len(s) > maxLangLength {
		return "", false
	}
	s = strings.TrimSpace(s)
	return s, s != ""
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareDigits compares two non-negative decimal digit strings by value.
func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) < len(b))
	}
	return strings.Compare(a, b)
}

// compareNumList compares dotted numeric components; missing ones count as
// zero, so trailing zeros are insignificant.
func compareNumList(a, b []string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := "0", "0"
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := compareDigits(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// compareSemVerPre compares SemVer 2 pre-release identifiers: numeric ones
// by value and below alphanumeric ones, alphanumeric ones in ASCII order
// (case-insensitive when fold is set), a shorter prefix first. Both lists
// must be non-empty; a release without pre-release is handled by the caller.
func compareSemVerPre(a, b []string, fold bool) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		xn, yn := allDigits(x), allDigits(y)
		var c int
		switch {
		case xn && yn:
			c = compareDigits(x, y)
		case xn:
			c = -1
		case yn:
			c = 1
		case fold:
			c = strings.Compare(strings.ToLower(x), strings.ToLower(y))
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	if len(a) != len(b) {
		return sign(len(a) < len(b))
	}
	return 0
}

// splitNonEmpty splits s on dots, returning nil for an empty s.
func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ".")
}

// --- PyPI ---------------------------------------------------------------

// pep440Re is the PEP 440 grammar including the permitted alternate
// spellings (Appendix B of the spec), applied to lowercased input.
var pep440Re = regexp.MustCompile(`^v?` +
	`(?:([0-9]+)!)?` + // epoch
	`([0-9]+(?:\.[0-9]+)*)` + // release
	`(?:[-_.]?(alpha|beta|preview|pre|rc|a|b|c)[-_.]?([0-9]+)?)?` + // pre
	`(?:-([0-9]+)|[-_.]?(post|rev|r)[-_.]?([0-9]+)?)?` + // post
	`(?:[-_.]?(dev)[-_.]?([0-9]+)?)?` + // dev
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`) // local

type pep440 struct {
	epoch   string
	release []string
	preRank int // 0 dev-only release, 1 a, 2 b, 3 rc, 4 none
	preNum  string
	post    bool
	postNum string
	dev     bool
	devNum  string
	local   []string
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func parsePEP440(s string) (pep440, bool) {
	s, ok := langInput(s)
	if !ok {
		return pep440{}, false
	}
	m := pep440Re.FindStringSubmatch(strings.ToLower(s))
	if m == nil {
		return pep440{}, false
	}
	v := pep440{epoch: orZero(m[1]), release: strings.Split(m[2], ".")}
	switch m[3] {
	case "a", "alpha":
		v.preRank = 1
	case "b", "beta":
		v.preRank = 2
	case "rc", "c", "pre", "preview":
		v.preRank = 3
	default:
		v.preRank = 4
	}
	v.preNum = orZero(m[4])
	switch {
	case m[5] != "":
		v.post, v.postNum = true, m[5]
	case m[6] != "":
		v.post, v.postNum = true, orZero(m[7])
	}
	if m[8] != "" {
		v.dev, v.devNum = true, orZero(m[9])
	}
	// A dev release of a final release (1.0.dev0) sorts before all its
	// pre-releases (1.0a1); one of a pre- or post-release stays with it.
	if v.preRank == 4 && !v.post && v.dev {
		v.preRank = 0
	}
	if m[10] != "" {
		v.local = strings.FieldsFunc(m[10], func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	}
	return v, true
}

// ComparePEP440 compares two Python package versions as PEP 440 orders
// them: epoch, release (trailing zeros insignificant), pre-release, post-
// release, development release and local version label. Alternate
// spellings ("1.0-alpha.1", "1.0-1", "1.0.rev2", "v1.0") are normalised
// as the spec permits; ok is false for any other input.
func ComparePEP440(a, b string) (cmp int, ok bool) {
	x, ok := parsePEP440(a)
	if !ok {
		return 0, false
	}
	y, ok := parsePEP440(b)
	if !ok {
		return 0, false
	}
	if c := compareDigits(x.epoch, y.epoch); c != 0 {
		return c, true
	}
	if c := compareNumList(x.release, y.release); c != 0 {
		return c, true
	}
	if x.preRank != y.preRank {
		return sign(x.preRank < y.preRank), true
	}
	if x.preRank >= 1 && x.preRank <= 3 {
		if c := compareDigits(x.preNum, y.preNum); c != 0 {
			return c, true
		}
	}
	if x.post != y.post {
		return sign(!x.post), true
	}
	if c := compareDigits(x.postNum, y.postNum); x.post && c != 0 {
		return c, true
	}
	if x.dev != y.dev {
		return sign(x.dev), true
	}
	if c := compareDigits(x.devNum, y.devNum); x.dev && c != 0 {
		return c, true
	}
	return comparePEP440Local(x.local, y.local), true
}

// comparePEP440Local orders local labels: none first, then segment by
// segment with numeric segments above alphanumeric ones, numeric by value,
// alphanumeric lexically, and a shorter prefix first.
func comparePEP440Local(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		xn, yn := allDigits(x), allDigits(y)
		var c int
		switch {
		case xn && yn:
			c = compareDigits(x, y)
		case xn:
			c = 1
		case yn:
			c = -1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	if len(a) != len(b) {
		return sign(len(a) < len(b))
	}
	return 0
}

// --- Maven --------------------------------------------------------------

// mavenToken is one token of a Maven version: its separator prefix ('.' or
// '-'), whether it is numeric, and its value (digits without leading zeros,
// or a lowercase qualifier with aliases resolved).
type mavenToken struct {
	prefix byte
	num    bool
	val    string
}

func (t mavenToken) null() bool { return t.val == "" }

// mavenQualifiers are the qualifiers ordered before all others.
var mavenQualifiers = map[string]int{"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4, "": 5, "sp": 6}

func mavenNewToken(prefix byte, s string, followedByDigit bool) mavenToken {
	if s == "" {
		return mavenToken{prefix: prefix, num: true} // empty tokens are 0
	}
	if allDigits(s) {
		return mavenToken{prefix: prefix, num: true, val: strings.TrimLeft(s, "0")}
	}
	if followedByDigit {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	return mavenToken{prefix: prefix, val: s}
}

func parseMaven(s string) ([]mavenToken, bool) {
	s, ok := langInput(s)
	if !ok {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] == 0x7f {
			return nil, false
		}
	}
	s = strings.ToLower(s)
	var toks []mavenToken
	prefix, start := byte('.'), 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' || c == '-' {
			toks = append(toks, mavenNewToken(prefix, s[start:i], false))
			prefix, start = c, i+1
			continue
		}
		// A transition between digits and characters acts as a hyphen.
		if i > start && isDigit(s, i) != isDigit(s, i-1) {
			toks = append(toks, mavenNewToken(prefix, s[start:i], isDigit(s, i)))
			prefix, start = '-', i
		}
	}
	toks = append(toks, mavenNewToken(prefix, s[start:], false))

	// Trim trailing null tokens, then repeat before each remaining hyphen
	// from end to start. The first token always stays.
	for i := len(toks) - 1; i > 0; {
		if toks[i].null() {
			toks = append(toks[:i], toks[i+1:]...)
			i--
			continue
		}
		for i > 0 && toks[i].prefix != '-' {
			i--
		}
		i--
	}
	return toks, true
}

func compareMavenQualifier(a, b string) int {
	ra, oka := mavenQualifiers[a]
	rb, okb := mavenQualifiers[b]
	switch {
	case oka && okb:
		if ra == rb {
			return 0
		}
		return sign(ra < rb)
	case oka:
		return -1
	case okb:
		return 1
	}
	return strings.Compare(a, b)
}

// mavenRank is the order of tokens with different prefixes:
// ".qualifier" = "-qualifier" < "-number" < ".number".
func mavenRank(t mavenToken) int {
	switch {
	case !t.num:
		return 0
	case t.prefix == '-':
		return 1
	}
	return 2
}

func compareMavenToken(a, b mavenToken) int {
	if a.prefix == b.prefix || (!a.num && !b.num) {
		switch {
		case a.num && b.num:
			return compareDigits(a.val, b.val)
		case a.num:
			return 1
		case b.num:
			return -1
		}
		return compareMavenQualifier(a.val, b.val)
	}
	ra, rb := mavenRank(a), mavenRank(b)
	if ra == rb {
		return 0
	}
	return sign(ra < rb)
}

// mavenPad is the null token that stands in for a missing one: 0 after
// '.', the empty qualifier after '-'.
func mavenPad(prefix byte) mavenToken {
	return mavenToken{prefix: prefix, num: prefix == '.'}
}

// CompareMaven compares two Maven versions by the Maven version order
// specification (the POM reference, as implemented by ComparableVersion):
// tokens split on '.', '-' and digit/letter transitions, trailing null
// tokens trimmed, qualifiers ordered alpha < beta < milestone < rc = cr <
// snapshot < "" = ga = final = release < sp < any other (lexically).
// ok is false for empty input or input containing whitespace or control
// characters.
func CompareMaven(a, b string) (cmp int, ok bool) {
	x, ok := parseMaven(a)
	if !ok {
		return 0, false
	}
	y, ok := parseMaven(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < len(x) || i < len(y); i++ {
		var l, r mavenToken
		switch {
		case i >= len(x):
			r = y[i]
			l = mavenPad(r.prefix)
		case i >= len(y):
			l = x[i]
			r = mavenPad(l.prefix)
		default:
			l, r = x[i], y[i]
		}
		if c := compareMavenToken(l, r); c != 0 {
			return c, true
		}
	}
	return 0, true
}

// --- RubyGems -----------------------------------------------------------

// gemRe is Gem::Version's accepted pattern (without the empty version,
// which RubyGems reads as "0" but carries no information here).
var gemRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// gemSegments splits like Gem::Version#segments: runs of digits or letters,
// "-" read as ".pre.", then drops trailing zeros of the numeric and of the
// string part separately as canonical_segments does.
func gemSegments(s string) []string {
	s = strings.ReplaceAll(s, "-", ".pre.")
	var segs []string
	for i := 0; i < len(s); {
		if !isAlnum(s[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(s) && isAlnum(s[j]) && isDigit(s, j) == isDigit(s, i) {
			j++
		}
		segs = append(segs, s[i:j])
		i = j
	}
	firstStr := len(segs)
	for i, g := range segs {
		if !allDigits(g) {
			firstStr = i
			break
		}
	}
	trim := func(p []string) []string {
		for len(p) > 0 && allDigits(p[len(p)-1]) && strings.Trim(p[len(p)-1], "0") == "" {
			p = p[:len(p)-1]
		}
		return p
	}
	nums := trim(append([]string(nil), segs[:firstStr]...))
	strs := trim(segs[firstStr:])
	return append(nums, strs...)
}

// CompareRubyGems compares two gem versions as Gem::Version#<=> does:
// segments of digits or letters compared pairwise (missing ones are 0),
// numeric segments by value and above string segments, strings in byte
// order. Any letter makes a pre-release, which sorts before the release.
func CompareRubyGems(a, b string) (cmp int, ok bool) {
	x, okx := langInput(a)
	y, oky := langInput(b)
	if !okx || !oky || !gemRe.MatchString(x) || !gemRe.MatchString(y) {
		return 0, false
	}
	sx, sy := gemSegments(x), gemSegments(y)
	for i := 0; i < len(sx) || i < len(sy); i++ {
		l, r := "0", "0"
		if i < len(sx) {
			l = sx[i]
		}
		if i < len(sy) {
			r = sy[i]
		}
		ln, rn := allDigits(l), allDigits(r)
		var c int
		switch {
		case ln && rn:
			c = compareDigits(l, r)
		case ln:
			c = 1
		case rn:
			c = -1
		default:
			c = strings.Compare(l, r)
		}
		if c != 0 {
			return c, true
		}
	}
	return 0, true
}

// --- NuGet --------------------------------------------------------------

var nugetRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+){0,3})` +
	`(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?` +
	`(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// CompareNuGet compares two NuGet versions: up to four numeric parts
// (1.0 = 1.0.0 = 1.0.0.0), then SemVer 2 pre-release precedence with
// case-insensitive labels. Build metadata is validated and ignored.
func CompareNuGet(a, b string) (cmp int, ok bool) {
	x, okx := langInput(a)
	y, oky := langInput(b)
	if !okx || !oky {
		return 0, false
	}
	mx, my := nugetRe.FindStringSubmatch(x), nugetRe.FindStringSubmatch(y)
	if mx == nil || my == nil {
		return 0, false
	}
	return compareRelease(strings.Split(mx[1], "."), strings.Split(my[1], "."),
		splitNonEmpty(mx[2]), splitNonEmpty(my[2]), true), true
}

// compareRelease compares numeric parts, then pre-release identifiers; a
// version without pre-release ranks above any pre-release of it.
func compareRelease(na, nb, pa, pb []string, fold bool) int {
	if c := compareNumList(na, nb); c != 0 {
		return c
	}
	switch {
	case len(pa) == 0 && len(pb) == 0:
		return 0
	case len(pa) == 0:
		return 1
	case len(pb) == 0:
		return -1
	}
	return compareSemVerPre(pa, pb, fold)
}

// --- Packagist ----------------------------------------------------------

// composerRe is Composer's classical version grammar (VersionParser) for
// lowercased input with the "-dev" suffix already excluded.
var composerRe = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+){0,3})` +
	`(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p|dev)((?:[.-]?[0-9]+)*))?` +
	`(?:\+[0-9a-z.-]+)?$`)

// composerStability orders Composer stability flags.
var composerStability = map[string]int{
	"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "": 4, "stable": 4, "patch": 5, "pl": 5, "p": 5,
}

// CompareComposer compares two Composer (Packagist) versions: up to four
// numeric parts, then the stability flag dev < alpha < beta < RC < stable <
// patch with its optional numbers. Branch versions ("dev-main") and
// versions ending in "dev" ("1.x-dev", "2.0.0-dev") name a moving branch
// head, so ok is false for them.
func CompareComposer(a, b string) (cmp int, ok bool) {
	x, okx := parseComposer(a)
	y, oky := parseComposer(b)
	if !okx || !oky {
		return 0, false
	}
	if c := compareNumList(strings.Split(x[1], "."), strings.Split(y[1], ".")); c != 0 {
		return c, true
	}
	sx, sy := composerStability[x[2]], composerStability[y[2]]
	if sx != sy {
		return sign(sx < sy), true
	}
	return compareNumSeq(composerNums(x[3]), composerNums(y[3])), true
}

func parseComposer(s string) ([]string, bool) {
	s, ok := langInput(s)
	if !ok {
		return nil, false
	}
	s = strings.ToLower(s)
	if base, _, _ := strings.Cut(s, "+"); strings.HasPrefix(s, "dev-") || strings.HasSuffix(base, "dev") {
		return nil, false
	}
	m := composerRe.FindStringSubmatch(s)
	return m, m != nil
}

func composerNums(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' })
}

// compareNumSeq compares numeric sequences element by element with a
// shorter prefix first, so "beta" < "beta1" < "beta1.1" < "beta2".
func compareNumSeq(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareDigits(a[i], b[i]); c != 0 {
			return c
		}
	}
	if len(a) != len(b) {
		return sign(len(a) < len(b))
	}
	return 0
}

// --- crates.io ----------------------------------------------------------

const semverNum = `(?:0|[1-9][0-9]*)`

var cargoRe = regexp.MustCompile(`^(` + semverNum + `\.` + semverNum + `\.` + semverNum + `)` +
	`(?:-((?:` + semverNum + `|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:` + semverNum + `|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?` +
	`(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// CompareCargo compares two crates.io versions by SemVer 2 precedence:
// exactly three numeric parts without leading zeros, pre-release
// identifiers compared numerically or in ASCII order, build metadata
// validated and ignored.
func CompareCargo(a, b string) (cmp int, ok bool) {
	x, okx := langInput(a)
	y, oky := langInput(b)
	if !okx || !oky {
		return 0, false
	}
	mx, my := cargoRe.FindStringSubmatch(x), cargoRe.FindStringSubmatch(y)
	if mx == nil || my == nil {
		return 0, false
	}
	return compareRelease(strings.Split(mx[1], "."), strings.Split(my[1], "."),
		splitNonEmpty(mx[2]), splitNonEmpty(my[2]), false), true
}
