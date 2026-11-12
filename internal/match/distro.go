// SPDX-License-Identifier: Apache-2.0

package match

import (
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/version"
)

// SourceDistro is the source name of distribution security records.
const SourceDistro = "distro"

// matchDistro matches a distribution package. Distributions backport fixes
// without changing the upstream version, so upstream ranges cannot decide:
// the distribution's own record for the package in this release does,
// compared in the package manager's order (ADR 0028). An advisory without
// such a record stays unverified, as before.
func matchDistro(in Input, advs []Advisory, enr Enrichment) []Finding {
	var findings []Finding
	for _, group := range groupByAlias(expandNotices(advs)) {
		var best *evaluation
		for i := range group {
			a := &group[i]
			if a.Source != SourceDistro {
				continue
			}
			e := evaluateDistro(in.Distro, a)
			// Several notices can cover one CVE: module streams on the RPM
			// distributions, a fix and its follow-up on Debian (DLA-3942-1,
			// then DLA-3942-2 with a later fixed version). One that finds
			// the package affected wins: the follow-up names the version
			// that fixes the CVE, as the distribution's tracker does.
			if e != nil && preferDistro(e, best) {
				best = e
			}
		}
		if best == nil {
			// Upstream data only: not comparable with a distribution
			// version.
			for i := range group {
				a := &group[i]
				if a.Source == SourceDistro {
					continue
				}
				e := evaluate(in, a, version.Version{}, "distribution package: "+in.Distro.Ecosystem+" has no record of this advisory for "+in.Distro.Name+", and upstream ranges do not apply to backported packages")
				if e != nil && (best == nil || better(e, best)) {
					best = e
				}
			}
		}
		if best == nil || best.state == notAffected {
			continue
		}
		if best.state == Affected && in.Doubt != "" {
			best.state, best.reason = Unverified, "the version is in the affected range, but "+in.Doubt
		}
		f := finding(in, group, best, enr)
		f.Evidence.Version = in.Distro.Version
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].AdvisoryID < findings[j].AdvisoryID })
	return findings
}

// preferDistro reports whether e replaces best: an affected result wins,
// otherwise the usual order applies.
func preferDistro(e, best *evaluation) bool {
	switch {
	case best == nil:
		return true
	case e.state == Affected && best.state != Affected:
		return true
	case e.state != Affected && best.state == Affected:
		return false
	}
	return better(e, best)
}

// expandNotices turns a distribution notice covering several CVEs
// ("ALSA-2025:3261") into one record per CVE, named by the CVE, so each CVE
// keeps its own finding and joins its other advisories. The notice is kept
// as a reference, not as an alias: a shared alias would merge the CVEs.
func expandNotices(advs []Advisory) []Advisory {
	out := make([]Advisory, 0, len(advs))
	for _, a := range advs {
		if a.Source != SourceDistro || distro.PerCVE(a.Vuln.ID) || len(a.Vuln.Upstream) == 0 {
			out = append(out, a)
			continue
		}
		for _, cve := range a.Vuln.Upstream {
			if !strings.HasPrefix(cve, "CVE-") {
				continue
			}
			c := a
			c.Vuln.ID, c.Vuln.Aliases, c.Vuln.Upstream = cve, nil, nil
			c.Vuln.References = append([]advisory.Reference{{Type: "ADVISORY", URL: noticeURL(a)}}, a.Vuln.References...)
			out = append(out, c)
		}
	}
	return out
}

// noticeURL is the page of a notice on osv.dev.
func noticeURL(a Advisory) string { return "https://osv.dev/vulnerability/" + a.Vuln.ID }

// evaluateDistro evaluates the entries of a distribution record for the
// package; nil when the record has none for it.
func evaluateDistro(p *distro.Package, a *Advisory) *evaluation {
	var entries []advisory.Affected
	for _, aff := range a.Vuln.Affected {
		if distro.SameRelease(aff.Package.Ecosystem, p.Ecosystem, time.Now()) && aff.Package.Name == p.Name {
			entries = append(entries, aff)
		}
	}
	if len(entries) == 0 {
		return nil
	}
	e := &evaluation{adv: a, state: notAffected, pkg: p.Ecosystem + "/" + p.Name}
	var uncertain []string
	for _, aff := range entries {
		_, e.rng = describeEntry(aff)
		for _, v := range aff.Versions {
			if c, ok := distro.Compare(p.Ecosystem, p.Version, v); ok && c == 0 {
				e.state, e.fixedIn = Affected, distroFixed(p, aff)
				return e
			}
		}
		for _, r := range aff.Ranges {
			if r.Type != advisory.RangeEcosystem && (r.Type != advisory.RangeSemver || !distro.Language(p.Ecosystem)) {
				uncertain = append(uncertain, "range type "+r.Type+" not comparable")
				continue
			}
			in, ok := distroInRange(p, r)
			switch {
			case !ok:
				uncertain = append(uncertain, "range version not comparable with "+p.Version)
			case in:
				e.state, e.fixedIn = Affected, distroFixed(p, aff)
				if e.fixedIn == "" {
					e.reason = p.Ecosystem + " has not fixed this yet"
					if u, _ := aff.EcosystemSpecific["urgency"].(string); u == "unimportant" {
						// Debian rates it negligible for this package (for
						// example code that is not built); it stays visible
						// but does not alert.
						e.state, e.reason = Unverified, p.Ecosystem+" rates this unimportant for "+p.Name+" and does not fix it"
					}
				}
				return e
			}
		}
	}
	if len(uncertain) > 0 {
		e.state, e.reason = Unverified, strings.Join(dedupe(uncertain), "; ")
	}
	return e
}

// distroInRange evaluates one ECOSYSTEM range of OSV events: the events
// are ordered by version, and the last one at or below the installed
// version decides (introduced: affected; fixed, limit: not; last_affected:
// affected only at that version).
func distroInRange(p *distro.Package, r advisory.Range) (in, ok bool) {
	type ev struct {
		kind, raw string
		zero      bool
	}
	var evs []ev
	for _, e := range r.Events {
		kind, raw := eventKind(e)
		if kind == "" {
			continue
		}
		if kind == "introduced" && raw == "0" {
			evs = append(evs, ev{kind: kind, zero: true})
			continue
		}
		if _, ok := distro.Compare(p.Ecosystem, raw, raw); !ok {
			return false, false
		}
		evs = append(evs, ev{kind: kind, raw: raw})
	}
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].zero != evs[j].zero {
			return evs[i].zero
		}
		c, _ := distro.Compare(p.Ecosystem, evs[i].raw, evs[j].raw)
		return c < 0
	})
	affected := false
	for _, e := range evs {
		if e.zero {
			affected = true
			continue
		}
		c, ok := distro.Compare(p.Ecosystem, p.Version, e.raw)
		if !ok {
			return false, false
		}
		switch e.kind {
		case "introduced":
			if c >= 0 {
				affected = true
			}
		case "fixed", "limit":
			if c >= 0 {
				affected = false
			}
		case "last_affected":
			if c > 0 {
				affected = false
			}
		}
	}
	return affected, true
}

// distroFixed is the lowest fixed version above the installed one, empty
// when the distribution has not fixed it.
func distroFixed(p *distro.Package, aff advisory.Affected) string {
	best := ""
	for _, r := range aff.Ranges {
		for _, ev := range r.Events {
			if ev.Fixed == "" {
				continue
			}
			if c, ok := distro.Compare(p.Ecosystem, ev.Fixed, p.Version); !ok || c <= 0 {
				continue
			}
			if c, ok := distro.Compare(p.Ecosystem, ev.Fixed, best); best == "" || (ok && c < 0) {
				best = ev.Fixed
			}
		}
	}
	return best
}
