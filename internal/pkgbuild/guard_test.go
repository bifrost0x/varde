// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"errors"
	"testing"
)

// The releases blob has a hard cap: force does not lift it, because a
// package that size is a builder fault, not a legitimate change.
func TestGuardReleasesCap(t *testing.T) {
	for _, tc := range []struct {
		size    int64
		refused bool
	}{{0, false}, {MaxReleasesBytes - 1, false}, {MaxReleasesBytes, false}, {MaxReleasesBytes + 1, true}, {1 << 40, true}} {
		err := GuardReleases(tc.size)
		if (err != nil) != tc.refused || (err != nil && !errors.Is(err, ErrRefused)) {
			t.Errorf("%d bytes: err = %v, want refused = %v", tc.size, err, tc.refused)
		}
	}
}

func TestGuardGeneratedDrop(t *testing.T) {
	prev := Counts{Sequence: 100, Advisories: 100, KEV: 1000, Index: 200, Generated: 1000}
	ok := Counts{Sequence: 200, Advisories: 100, KEV: 1000, Index: 200, Generated: 1000}
	with := func(n int) Counts { c := ok; c.Generated = n; return c }
	for _, tc := range []struct {
		name    string
		prev    Counts
		cur     Counts
		force   bool
		refused bool
	}{
		{"unchanged", prev, ok, false, false},
		{"grew", prev, with(5000), false, false},
		{"to 700 (30 %)", prev, with(700), false, false},
		{"to 699", prev, with(699), false, true},
		{"to 0", prev, with(0), false, true},
		{"to 0, forced", prev, with(0), true, false},
		// A baseline from before the generator has no count: no check.
		{"no earlier count", Counts{Sequence: 100, Advisories: 100, KEV: 1000, Index: 200}, with(0), false, false},
	} {
		err := Guard(Stats{Repos: 100}, tc.prev, true, tc.cur, tc.force)
		if (err != nil) != tc.refused || (err != nil && !errors.Is(err, ErrRefused)) {
			t.Errorf("%s: err = %v, want refused = %v", tc.name, err, tc.refused)
		}
	}
}
