// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnparsableRange is returned for range expressions Varde cannot map
// without guessing. Such advisories match as unverified, never affected.
var ErrUnparsableRange = errors.New("unparsable version range")

type constraint struct {
	op      string // ">=", ">", "<=", "<", "="
	version string
}

// ParseGitHubRange maps a GitHub advisory's vulnerable_version_range and
// patched_versions to OSV ranges and an explicit version list.
//
// GitHub defines "," as AND. Some projects use it to list one lower bound
// per release branch with one patched version each
// (">= 32.0.0, >= 33.0.0" / "32.0.12, 33.0.6"); that shape is split into
// one range per branch. A bare version with a later patched version is
// ambiguous: the bare version is listed exactly and the gap up to the patch
// becomes an inferred range (unverified, not affected).
func ParseGitHubRange(vulnerable, patched string) (ranges []Range, versions []string, err error) {
	cs, err := parseConstraints(vulnerable)
	if err != nil {
		return nil, nil, err
	}
	fixes := parsePatched(patched)

	// One lower bound per branch, one patch per branch.
	if len(cs) >= 2 && len(cs) == len(fixes) && allOps(cs, ">=") {
		for i, c := range cs {
			ranges = append(ranges, Range{Type: RangeEcosystem, Events: []Event{{Introduced: c.version}, {Fixed: fixes[i]}}})
		}
		return ranges, nil, nil
	}

	var lower, upper, exact []constraint
	for _, c := range cs {
		switch c.op {
		case ">=", ">":
			lower = append(lower, c)
		case "<", "<=":
			upper = append(upper, c)
		case "=":
			exact = append(exact, c)
		}
	}
	if len(lower) > 1 || len(upper) > 1 || (len(exact) > 0 && len(lower)+len(upper) > 0) || len(exact) > 1 {
		return nil, nil, fmt.Errorf("%w: %q", ErrUnparsableRange, vulnerable)
	}

	if len(exact) == 1 {
		v := exact[0].version
		versions = []string{v}
		if len(fixes) == 1 && fixes[0] != v {
			ranges = append(ranges, inferred(Range{Type: RangeEcosystem, Events: []Event{{Introduced: v}, {Fixed: fixes[0]}}}))
		}
		return ranges, versions, nil
	}

	r := Range{Type: RangeEcosystem}
	introduced := "0"
	if len(lower) == 1 {
		introduced = lower[0].version
		if lower[0].op == ">" {
			// OSV has no exclusive lower bound; the bound itself is
			// reported as unverified rather than affected.
			r = inferred(r)
		}
	}
	r.Events = append(r.Events, Event{Introduced: introduced})
	switch {
	case len(upper) == 1 && upper[0].op == "<":
		r.Events = append(r.Events, Event{Fixed: upper[0].version})
	case len(upper) == 1:
		r.Events = append(r.Events, Event{LastAffected: upper[0].version})
		if len(fixes) == 1 {
			// Keep the patch for "fixed in" even though the range ends at
			// last_affected.
			r.Events = append(r.Events, Event{Fixed: fixes[0]})
		}
	case len(fixes) == 1:
		r.Events = append(r.Events, Event{Fixed: fixes[0]})
	case len(fixes) > 1:
		// Several patches for one open range: which applies depends on the
		// branch, so the range is inferred.
		r = inferred(r)
		for _, f := range fixes {
			r.Events = append(r.Events, Event{Fixed: f})
		}
	}
	return []Range{r}, nil, nil
}

func inferred(r Range) Range {
	if r.DatabaseSpecific == nil {
		r.DatabaseSpecific = map[string]any{}
	}
	r.DatabaseSpecific[RangeInferred] = true
	return r
}

func allOps(cs []constraint, op string) bool {
	for _, c := range cs {
		if c.op != op {
			return false
		}
	}
	return true
}

var opReplacer = strings.NewReplacer("≤", "<=", "≥", ">=", "==", "=")

func parseConstraints(s string) ([]constraint, error) {
	s = strings.TrimSpace(opReplacer.Replace(s))
	if s == "" {
		return nil, fmt.Errorf("%w: empty", ErrUnparsableRange)
	}
	// Prose form seen in the wild: "v4.0.0-alpha1 to v4.29.2" (inclusive).
	if lo, hi, ok := strings.Cut(s, " to "); ok && !strings.Contains(s, ",") {
		l, okL := cleanVersion(lo)
		h, okH := cleanVersion(hi)
		if !okL || !okH {
			return nil, fmt.Errorf("%w: %q", ErrUnparsableRange, s)
		}
		return []constraint{{op: ">=", version: l}, {op: "<=", version: h}}, nil
	}
	var out []constraint
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		var c constraint
		for _, op := range []string{">=", "<=", ">", "<", "="} {
			if rest, ok := strings.CutPrefix(tok, op); ok {
				c.op, tok = op, strings.TrimSpace(rest)
				break
			}
		}
		if c.op == "" {
			c.op = "="
		}
		v, ok := cleanVersion(tok)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnparsableRange, s)
		}
		c.version = v
		out = append(out, c)
	}
	return out, nil
}

func parsePatched(s string) []string {
	s = strings.TrimSpace(opReplacer.Replace(s))
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		for _, op := range []string{">=", ">", "="} {
			tok = strings.TrimSpace(strings.TrimPrefix(tok, op))
		}
		if v, ok := cleanVersion(tok); ok {
			out = append(out, v)
		}
	}
	return out
}

// cleanVersion strips a leading "v" and checks the token looks like a
// version: starts with a digit, no spaces, bounded length.
func cleanVersion(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		s = s[1:]
	}
	if s == "" || len(s) > 64 || s[0] < '0' || s[0] > '9' || strings.ContainsAny(s, " \t*") {
		return "", false
	}
	return s, true
}
