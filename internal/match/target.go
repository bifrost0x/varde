// SPDX-License-Identifier: Apache-2.0

package match

import (
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/version"
)

// Target is the smallest update that fixes the affected findings of one app
// version together, so users see one version to install instead of one per
// advisory.
type Target struct {
	// Version fixes Fixes of the Total affected advisories. It is empty when
	// no published version fixes any of them.
	Version string `json:"version,omitempty"`
	Fixes   int    `json:"fixes"`
	Total   int    `json:"total"`
	// NewLine is set when Version leaves the running release line (a new
	// major version under SemVer), which usually needs upgrade steps.
	NewLine bool `json:"new_line,omitempty"`
	// Line is the best update on the running release line when Version
	// leaves it and the line fixes at least one advisory.
	Line *Target `json:"line,omitempty"`
}

// target evaluates every fixed version named by the affected advisories and
// picks the smallest one that fixes as many of them as any candidate does.
// Smallest first prefers a fix on the running release line whenever that
// line fixes everything a newer line would.
//
// releases, when known, are the versions that were released for what runs
// here (Input.Releases). A fixed version an advisory names is then replaced
// by the lowest release at or above it: projects name fixes that were never
// published in this form (a skipped patch release, an image built from the
// next one), and an update must be something that can be installed.
func target(app *catalog.App, running version.Version, groups [][]Advisory, releases []string) *Target {
	if len(groups) == 0 || running.IsZero() {
		return nil
	}
	cands := released(app, running, candidates(app, running, groups), releases)
	best := &Target{Total: len(groups)}
	var line *Target
	for _, c := range cands {
		n := 0
		for _, g := range groups {
			if !affectsAny(app, c, g) {
				n++
			}
		}
		if n > best.Fixes {
			best = &Target{Version: c.String(), Fixes: n, Total: len(groups), NewLine: !running.SameLine(c)}
		}
		if running.SameLine(c) && n > 0 && (line == nil || n > line.Fixes) {
			line = &Target{Version: c.String(), Fixes: n, Total: len(groups)}
		}
	}
	if best.NewLine && line != nil {
		best.Line = line
	}
	return best
}

// released replaces each candidate by the lowest known release at or above
// it. A candidate above every known release stays: the list may be a day
// behind the fix. Pre-releases count only for a running pre-release.
func released(app *catalog.App, running version.Version, cands []version.Version, releases []string) []version.Version {
	if len(releases) == 0 || len(cands) == 0 {
		return cands
	}
	pre := strings.Contains(running.String(), "-")
	var known []version.Version
	for _, raw := range releases {
		if strings.Contains(raw, "-") && !pre {
			continue
		}
		v, err := version.Parse(app.Version.Scheme, raw)
		if err != nil {
			continue
		}
		if c, ok := v.Compare(running); ok && c > 0 {
			known = append(known, v)
		}
	}
	if len(known) == 0 {
		return cands
	}
	sort.Slice(known, func(i, j int) bool { return less(known[i], known[j]) })
	seen := map[string]bool{}
	var out []version.Version
	for _, c := range cands {
		pick := c
		i := sort.Search(len(known), func(i int) bool {
			x, ok := known[i].Compare(c)
			return ok && x >= 0
		})
		if i < len(known) {
			pick = known[i]
		}
		if !seen[pick.String()] {
			seen[pick.String()] = true
			out = append(out, pick)
		}
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// candidates returns the fixed versions above running, ascending and unique.
func candidates(app *catalog.App, running version.Version, groups [][]Advisory) []version.Version {
	seen := map[string]bool{}
	var out []version.Version
	for _, g := range groups {
		for i := range g {
			entries, other := relevantEntries(app, g[i].Vuln.Affected)
			if other != "" {
				continue // another project's versions are no update of this app
			}
			for _, aff := range entries {
				for _, r := range aff.Ranges {
					for _, ev := range r.Events {
						if ev.Fixed == "" {
							continue
						}
						v, err := version.Parse(app.Version.Scheme, ev.Fixed)
						if err != nil || seen[v.String()] {
							continue
						}
						if c, ok := v.Compare(running); !ok || c <= 0 {
							continue
						}
						seen[v.String()] = true
						out = append(out, v)
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// affectsAny reports whether any advisory of the alias group still applies
// to v. Ambiguous ranges count as affected: a target must not be claimed to
// fix something the data cannot confirm.
func affectsAny(app *catalog.App, v version.Version, group []Advisory) bool {
	for i := range group {
		if len(group[i].Vuln.Affected) == 0 {
			// A package filter cannot establish irrelevance when the
			// advisory names no packages or versions at all.
			return true
		}
		// Use the same three-state evaluation as matching: only an
		// explicit notAffected result confirms that the update fixes it.
		if e := evaluate(Input{App: app}, &group[i], v, ""); e != nil && e.state != notAffected {
			return true
		}
	}
	return false
}
