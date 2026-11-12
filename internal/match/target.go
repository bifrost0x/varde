// SPDX-License-Identifier: Apache-2.0

package match

import (
	"sort"

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
func target(app *catalog.App, running version.Version, groups [][]Advisory) *Target {
	if len(groups) == 0 || running.IsZero() {
		return nil
	}
	cands := candidates(app, running, groups)
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

// candidates returns the fixed versions above running, ascending and unique.
func candidates(app *catalog.App, running version.Version, groups [][]Advisory) []version.Version {
	seen := map[string]bool{}
	var out []version.Version
	for _, g := range groups {
		for i := range g {
			for _, aff := range relevantEntries(app, g[i].Vuln.Affected) {
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
