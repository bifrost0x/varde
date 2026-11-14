// SPDX-License-Identifier: Apache-2.0

// Package match evaluates an app version against advisories. It is pure:
// the same inputs always give the same findings.
//
// Precision first (ADR 0008): a finding is "affected" only when the running
// version falls inside a range that parses under the app's version scheme
// and was not reconstructed from ambiguous data. Everything uncertain is
// "unverified" with a reason; "not affected" produces no finding.
package match

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/version"
)

// State of a finding.
type State string

// States.
const (
	Affected   State = "affected"
	Unverified State = "unverified"
	// notAffected is internal; such results are dropped.
	notAffected State = "not_affected"
)

// Advisory is a stored advisory with ingest-time metadata.
type Advisory struct {
	Source        string
	Vuln          advisory.Vulnerability
	CVSS          float64 // 0 when unknown
	SeverityLabel string
}

// Enrichment holds exploitation data keyed by CVE.
type Enrichment struct {
	KEV  map[string]bool
	EPSS map[string]float64
}

// Input describes the running app.
type Input struct {
	App           *catalog.App
	Version       string // canonical; empty when unknown
	VersionSource string
	// Doubt, when set, says why the version is not confirmed; affected
	// results then become unverified with this reason (ADR 0023).
	Doubt string
	// Distro, when set, is a distribution package: it is matched against
	// the distribution's records with the package manager's version order
	// instead of upstream ranges (ADR 0028).
	Distro *distro.Package
}

// Finding is one advisory (alias group) that applies to the input.
type Finding struct {
	AdvisoryID string   `json:"advisory_id"`
	Aliases    []string `json:"aliases,omitempty"`
	Sources    []string `json:"sources"`
	State      State    `json:"match_state"`
	FixedIn    string   `json:"fixed_in,omitempty"`
	// Image marks a finding in a package of a container's image: an
	// updated image fixes it, not a package update on the host (ADR 0033).
	Image         bool    `json:"image,omitempty"`
	Summary       string  `json:"summary,omitempty"`
	URL           string  `json:"url,omitempty"`
	CVSS          float64 `json:"cvss,omitempty"`
	SeverityLabel string  `json:"severity,omitempty"`
	// Vector is the CVSS v3 vector; its attack vector tells whether the
	// flaw is reachable over the network (attack paths, ADR 0034).
	Vector   string   `json:"cvss_vector,omitempty"`
	KEV      bool     `json:"kev"`
	EPSS     float64  `json:"epss,omitempty"`
	Evidence Evidence `json:"evidence"`
	// Target is the update that fixes the affected findings of this app
	// version together; it is the same on every affected finding of a run.
	Target *Target `json:"target,omitempty"`
}

// Evidence records why a finding exists.
type Evidence struct {
	Source        string `json:"source"`
	RecordID      string `json:"record_id"`
	Package       string `json:"package,omitempty"`
	Range         string `json:"range,omitempty"`
	Version       string `json:"version,omitempty"`
	VersionSource string `json:"version_source,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// sourceRank prefers project-published data over aggregated CVE data.
var sourceRank = map[string]int{"github": 0, "osv": 1, "feed": 1, "nvd": 2}

// rank orders sources; a source may carry a key suffix ("github:org/repo").
func rank(source string) int {
	if i := strings.IndexByte(source, ':'); i >= 0 {
		source = source[:i]
	}
	if r, ok := sourceRank[source]; ok {
		return r
	}
	return 3
}

// Match returns findings for in, ordered by advisory ID.
func Match(in Input, advs []Advisory, enr Enrichment) []Finding {
	var running version.Version
	var versionErr string
	switch {
	case in.App == nil:
		return nil
	case in.Distro != nil:
		return matchDistro(in, advs, enr)
	case in.Version == "":
		versionErr = "running version unknown"
	default:
		v, err := version.Parse(in.App.Version.Scheme, in.Version)
		if err != nil {
			versionErr = "running version not parseable as " + string(in.App.Version.Scheme)
		} else {
			running = v
		}
	}

	var findings []Finding
	var affected [][]Advisory // alias groups of affected findings, by finding index
	var affectedIdx []int
	for _, group := range groupByAlias(advs) {
		var best *evaluation
		for i := range group {
			a := &group[i]
			e := evaluate(in, a, running, versionErr)
			if e == nil {
				continue // not relevant for this app (package filter)
			}
			if e.state == Affected && in.Doubt != "" {
				e.state, e.reason = Unverified, "the version is in the affected range, but "+in.Doubt
			}
			if best == nil || better(e, best) {
				best = e
			}
		}
		if best == nil || best.state == notAffected {
			continue
		}
		if best.state == Affected {
			affected = append(affected, group)
			affectedIdx = append(affectedIdx, len(findings))
		}
		findings = append(findings, finding(in, group, best, enr))
	}
	if t := target(in.App, running, affected); t != nil {
		for _, i := range affectedIdx {
			findings[i].Target = t
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].AdvisoryID < findings[j].AdvisoryID })
	return findings
}

type evaluation struct {
	adv     *Advisory
	state   State
	fixedIn string
	pkg     string
	rng     string
	reason  string
}

// better orders evaluations: definitive results before unverified ones,
// then by source rank.
func better(a, b *evaluation) bool {
	da, db := a.state != Unverified, b.state != Unverified
	if da != db {
		return da
	}
	if rank(a.adv.Source) != rank(b.adv.Source) {
		return rank(a.adv.Source) < rank(b.adv.Source)
	}
	return a.adv.Vuln.ID < b.adv.Vuln.ID
}

func evaluate(in Input, a *Advisory, running version.Version, versionErr string) *evaluation {
	entries, other := relevantEntries(in.App, a.Vuln.Affected)
	if entries == nil {
		return nil
	}
	if other != "" {
		// Every package the advisory names is another project's. Its
		// ranges still decide whether it can apply at all, but neither
		// "affected" nor the version that fixes that package is a
		// statement about this app.
		e := evaluateEntries(in, a, entries, running, versionErr)
		if e.state == Affected {
			e.state = Unverified
			e.reason = "the advisory names " + other + ", not " + appName(in.App) + "; check whether that is part of what runs here"
			e.fixedIn = ""
		}
		return e
	}
	return evaluateEntries(in, a, entries, running, versionErr)
}

// appName is the app's name for a sentence, its id when it has none.
func appName(app *catalog.App) string {
	if app.Name != "" {
		return app.Name
	}
	return app.ID
}

func evaluateEntries(in Input, a *Advisory, entries []advisory.Affected, running version.Version, versionErr string) *evaluation {
	e := &evaluation{adv: a, state: notAffected}
	if len(entries) == 0 {
		e.state, e.reason = Unverified, "advisory lists no affected versions"
		return e
	}
	if versionErr != "" {
		e.state, e.reason = Unverified, versionErr
		e.pkg, e.rng = describeEntry(entries[0])
		return e
	}

	scheme := in.App.Version.Scheme
	var uncertain []string
	for _, aff := range entries {
		pkg, rng := describeEntry(aff)
		if len(aff.Ranges) == 0 && len(aff.Versions) == 0 {
			// Upstream range could not be mapped (see ParseGitHubRange).
			uncertain = append(uncertain, "affected versions not machine-readable")
			if e.pkg == "" {
				e.pkg = pkg
			}
			continue
		}
		for _, raw := range aff.Versions {
			v, err := version.Parse(scheme, raw)
			if err != nil {
				uncertain = append(uncertain, "version "+raw+" not comparable")
				continue
			}
			if c, ok := running.Compare(v); ok && c == 0 {
				return &evaluation{adv: a, state: Affected, pkg: pkg, rng: rng, fixedIn: lowestFixed(scheme, running, aff)}
			}
		}
		for _, r := range aff.Ranges {
			if r.Type == advisory.RangeGit {
				uncertain = append(uncertain, "git commit range")
				continue
			}
			in, ok, why := inRange(scheme, running, r)
			switch {
			case !ok:
				uncertain = append(uncertain, why)
			case in && r.Inferred():
				uncertain = append(uncertain, "upstream range is ambiguous ("+rng+")")
				e.pkg, e.rng = pkg, rng
				e.fixedIn = lowestFixed(scheme, running, aff)
			case in:
				return &evaluation{adv: a, state: Affected, pkg: pkg, rng: rng, fixedIn: lowestFixed(scheme, running, aff)}
			}
		}
		if e.pkg == "" {
			e.pkg, e.rng = pkg, rng
		}
	}
	if len(uncertain) > 0 {
		e.state, e.reason = Unverified, strings.Join(dedupe(uncertain), "; ")
	}
	return e
}

// relevantEntries applies the app's package filter, or, for an app without
// one, leaves out the packages of other projects. It returns nil when the
// advisory concerns only other products of the same repository. other is
// set when the entries are kept although each names another project: what
// they say about the app is then in doubt.
func relevantEntries(app *catalog.App, entries []advisory.Affected) (relevant []advisory.Affected, other string) {
	filters := app.Advisories.Packages
	if len(filters) == 0 {
		if len(entries) == 0 {
			return []advisory.Affected{}, ""
		}
		// Without a list of its own packages, an entry is left out only
		// when its name proves another project (foreign.go).
		return ownEntries(app, entries)
	}
	named := false
	for _, e := range entries {
		if strings.TrimSpace(e.Package.Name) != "" {
			named = true
			break
		}
	}
	var out []advisory.Affected
	for _, e := range entries {
		name := strings.TrimSpace(e.Package.Name)
		if name == "" {
			if !named {
				out = append(out, e)
			}
			continue
		}
		for _, f := range filters {
			if f.Matches(e.Package.Ecosystem, name) {
				out = append(out, e)
				break
			}
		}
	}
	return out, ""
}

// inRange evaluates OSV range events. ok is false when an event version is
// not comparable under the scheme.
func inRange(scheme version.Scheme, v version.Version, r advisory.Range) (in, ok bool, why string) {
	pts := make([]point, 0, len(r.Events))
	for _, ev := range r.Events {
		kind, raw := eventKind(ev)
		if kind == "" {
			continue
		}
		if kind == "introduced" && raw == "0" {
			pts = append(pts, point{kind: kind, zero: true})
			continue
		}
		pv, err := version.Parse(scheme, raw)
		if err != nil {
			return false, false, "range version " + raw + " not comparable"
		}
		pts = append(pts, point{kind: kind, ver: pv})
	}
	sort.SliceStable(pts, func(i, j int) bool {
		a, b := pts[i], pts[j]
		if a.zero != b.zero {
			return a.zero
		}
		c, _ := a.ver.Compare(b.ver)
		if c != 0 {
			return c < 0
		}
		// At equal versions an introduction precedes a fix.
		return a.kind == "introduced" && b.kind != "introduced"
	})
	open := false
	var start point
	for _, p := range pts {
		switch p.kind {
		case "introduced":
			if !open {
				open, start = true, p
			}
		case "fixed", "limit":
			if open {
				if geq(v, start) && less(v, p.ver) {
					return true, true, ""
				}
				open = false
			}
		case "last_affected":
			if open {
				if geq(v, start) && !less(p.ver, v) {
					return true, true, ""
				}
				open = false
			}
		}
	}
	if open && geq(v, start) {
		return true, true, ""
	}
	return false, true, ""
}

func eventKind(ev advisory.Event) (string, string) {
	switch {
	case ev.Introduced != "":
		return "introduced", ev.Introduced
	case ev.Fixed != "":
		return "fixed", ev.Fixed
	case ev.LastAffected != "":
		return "last_affected", ev.LastAffected
	case ev.Limit != "":
		return "limit", ev.Limit
	}
	return "", ""
}

// point is a parsed range event; zero marks introduced "0" (all versions).
type point struct {
	kind string
	ver  version.Version
	zero bool
}

func geq(v version.Version, p point) bool {
	if p.zero {
		return true
	}
	c, _ := v.Compare(p.ver)
	return c >= 0
}

func less(a, b version.Version) bool {
	c, _ := a.Compare(b)
	return c < 0
}

// lowestFixed returns the smallest fixed version above the running one.
func lowestFixed(scheme version.Scheme, running version.Version, aff advisory.Affected) string {
	var best version.Version
	var bestRaw string
	for _, r := range aff.Ranges {
		for _, ev := range r.Events {
			if ev.Fixed == "" {
				continue
			}
			fv, err := version.Parse(scheme, ev.Fixed)
			if err != nil {
				continue
			}
			if c, ok := fv.Compare(running); !ok || c <= 0 {
				continue
			}
			if bestRaw == "" || less(fv, best) {
				best, bestRaw = fv, fv.String()
			}
		}
	}
	return bestRaw
}

func describeEntry(a advisory.Affected) (pkg, rng string) {
	pkg = strings.Trim(a.Package.Ecosystem+"/"+a.Package.Name, "/")
	var parts []string
	for _, r := range a.Ranges {
		var evs []string
		for _, ev := range r.Events {
			kind, raw := eventKind(ev)
			switch kind {
			case "introduced":
				if raw != "0" {
					evs = append(evs, ">= "+raw)
				}
			case "fixed":
				evs = append(evs, "< "+raw)
			case "last_affected":
				evs = append(evs, "<= "+raw)
			case "limit":
				evs = append(evs, "limit "+raw)
			}
		}
		if len(evs) == 0 {
			evs = []string{"all versions"}
		}
		parts = append(parts, strings.Join(evs, ", "))
	}
	if len(a.Versions) > 0 {
		parts = append(parts, "= "+strings.Join(a.Versions, " | "))
	}
	return pkg, strings.Join(parts, " || ")
}

func finding(in Input, group []Advisory, best *evaluation, enr Enrichment) Finding {
	f := Finding{
		AdvisoryID:    best.adv.Vuln.ID,
		State:         best.state,
		FixedIn:       best.fixedIn,
		Summary:       best.adv.Vuln.Summary,
		URL:           best.adv.Vuln.URL(),
		CVSS:          best.adv.CVSS,
		SeverityLabel: best.adv.SeverityLabel,
		Evidence: Evidence{
			Source: best.adv.Source, RecordID: best.adv.Vuln.ID, Package: best.pkg, Range: best.rng,
			Version: in.Version, VersionSource: in.VersionSource, Reason: best.reason,
		},
	}
	ids := map[string]bool{}
	sources := map[string]bool{}
	for _, a := range group {
		sources[a.Source] = true
		for _, id := range recordIDs(a) {
			ids[id] = true
		}
		if f.Summary == "" {
			f.Summary = a.Vuln.Summary
		}
		if f.URL == "" {
			f.URL = a.Vuln.URL()
		}
		if a.CVSS > f.CVSS && best.adv.CVSS == 0 {
			f.CVSS = a.CVSS
		}
		if f.SeverityLabel == "" {
			f.SeverityLabel = a.SeverityLabel
		}
	}
	f.Vector = cvssVector(*best.adv)
	for i := 0; f.Vector == "" && i < len(group); i++ {
		f.Vector = cvssVector(group[i])
	}
	delete(ids, f.AdvisoryID)
	for id := range ids {
		f.Aliases = append(f.Aliases, id)
	}
	sort.Strings(f.Aliases)
	for s := range sources {
		f.Sources = append(f.Sources, s)
	}
	sort.Strings(f.Sources)
	for _, id := range append([]string{f.AdvisoryID}, f.Aliases...) {
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		if enr.KEV[id] {
			f.KEV = true
		}
		if s := enr.EPSS[id]; s > f.EPSS {
			f.EPSS = s
		}
	}
	return f
}

// recordIDs are the identifiers of an advisory: its ID and aliases, and
// for a per-CVE distribution record the CVE it names as upstream. Notices
// listing several CVEs are not stored, so this never merges two CVEs
// (ADR 0028).
func recordIDs(a Advisory) []string {
	ids := append([]string{a.Vuln.ID}, a.Vuln.Aliases...)
	if distro.PerCVE(a.Vuln.ID) {
		ids = append(ids, a.Vuln.Upstream...)
	}
	return ids
}

// groupByAlias merges advisories that share any identifier (union-find).
func groupByAlias(advs []Advisory) [][]Advisory {
	parent := make([]int, len(advs))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	owner := map[string]int{}
	for i, a := range advs {
		if a.Vuln.Withdrawn != nil {
			continue
		}
		for _, id := range recordIDs(a) {
			if j, ok := owner[id]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[id] = i
			}
		}
	}
	groups := map[int][]Advisory{}
	var roots []int
	for i, a := range advs {
		if a.Vuln.Withdrawn != nil {
			continue
		}
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], a)
	}
	out := make([][]Advisory, 0, len(roots))
	for _, r := range roots {
		out = append(out, groups[r])
	}
	return out
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// String renders a finding for logs.
func (f Finding) String() string {
	return fmt.Sprintf("%s %s fixed_in=%s", f.AdvisoryID, f.State, f.FixedIn)
}

// cvssVector returns an advisory's CVSS v3 vector, empty when it has none.
func cvssVector(a Advisory) string {
	for _, sev := range a.Vuln.Severity {
		if sev.Type == "CVSS_V3" && strings.HasPrefix(sev.Score, "CVSS:3") {
			return sev.Score
		}
	}
	return ""
}
