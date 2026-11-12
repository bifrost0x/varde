// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseGitHubRange(t *testing.T) {
	ev := func(es ...Event) []Event { return es }
	cases := []struct {
		name, vuln, patched string
		ranges              []Range
		versions            []string
	}{
		{
			name: "upper bound with patch", vuln: "< 2.44.1", patched: ">= 2.44.1",
			ranges: []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "0"}, Event{Fixed: "2.44.1"})}},
		},
		{
			name: "bounded with v prefix", vuln: ">= v3.0.0, <= v3.7.15", patched: "v3.7.16",
			ranges: []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "3.0.0"}, Event{LastAffected: "3.7.15"}, Event{Fixed: "3.7.16"})}},
		},
		{
			name: "no spaces, unicode le", vuln: "≤ 2026.5.2", patched: "2026.5.3",
			ranges: []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "0"}, Event{LastAffected: "2026.5.2"}, Event{Fixed: "2026.5.3"})}},
		},
		{
			name: "patched None", vuln: "<= v3.1.0", patched: "None",
			ranges: []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "0"}, Event{LastAffected: "3.1.0"})}},
		},
		{
			name: "nextcloud branches", vuln: ">= 32.0.0, >= 33.0.0, >= 34.0.0", patched: "32.0.12, 33.0.6, 34.0.1",
			ranges: []Range{
				{Type: RangeEcosystem, Events: ev(Event{Introduced: "32.0.0"}, Event{Fixed: "32.0.12"})},
				{Type: RangeEcosystem, Events: ev(Event{Introduced: "33.0.0"}, Event{Fixed: "33.0.6"})},
				{Type: RangeEcosystem, Events: ev(Event{Introduced: "34.0.0"}, Event{Fixed: "34.0.1"})},
			},
		},
		{
			name: "single lower bound with patch", vuln: ">= 34.0.0", patched: "34.0.1",
			ranges: []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "34.0.0"}, Event{Fixed: "34.0.1"})}},
		},
		{
			name: "bare version with later patch", vuln: "v3.2.2", patched: "v3.2.4",
			versions: []string{"3.2.2"},
			ranges:   []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "3.2.2"}, Event{Fixed: "3.2.4"}), DatabaseSpecific: map[string]any{RangeInferred: true}}},
		},
		{
			name: "prose range", vuln: "v4.0.0-alpha1 to v4.29.2", patched: "v4.29.3",
			ranges: []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "4.0.0-alpha1"}, Event{LastAffected: "4.29.2"}, Event{Fixed: "4.29.3"})}},
		},
		{
			name: "exclusive lower bound", vuln: "> 4.37.0", patched: "4.38.0",
			ranges: []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "4.37.0"}, Event{Fixed: "4.38.0"}), DatabaseSpecific: map[string]any{RangeInferred: true}}},
		},
		{
			name: "open range with two patches", vuln: ">= 1.0.0", patched: "1.4.2, 2.0.1",
			ranges: []Range{{Type: RangeEcosystem, Events: ev(Event{Introduced: "1.0.0"}, Event{Fixed: "1.4.2"}, Event{Fixed: "2.0.1"}), DatabaseSpecific: map[string]any{RangeInferred: true}}},
		},
	}
	for _, c := range cases {
		ranges, versions, err := ParseGitHubRange(c.vuln, c.patched)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(ranges, c.ranges) || !reflect.DeepEqual(versions, c.versions) {
			t.Errorf("%s:\n got %+v %v\nwant %+v %v", c.name, ranges, versions, c.ranges, c.versions)
		}
	}
}

func TestParseGitHubRangeRejects(t *testing.T) {
	for _, vuln := range []string{"", "all versions", ">= 1.0, >= 2.0", "< 1, < 2", "= 1.0, < 2.0", "*", ">= 1.0 < 2.0"} {
		if _, _, err := ParseGitHubRange(vuln, "2.0"); !errors.Is(err, ErrUnparsableRange) {
			t.Errorf("%q: %v", vuln, err)
		}
	}
}

func FuzzParseGitHubRange(f *testing.F) {
	f.Add(">= 32.0.0, >= 33.0.0", "32.0.1, 33.0.2")
	f.Add("< v1.2.3", "None")
	f.Fuzz(func(_ *testing.T, vuln, patched string) {
		_, _, _ = ParseGitHubRange(vuln, patched)
	})
}

func TestCVSS3BaseScore(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N": 3.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": 0,
		// 1.08 * (3.73317 + 2.28650) = 6.50124, rounded up to one decimal.
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L": 6.6,
	}
	for vec, want := range cases {
		got, err := CVSS3BaseScore(vec)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", vec, got, err, want)
		}
	}
	for _, bad := range []string{"", "CVSS:2.0/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"} {
		if _, err := CVSS3BaseScore(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzCVSS3(f *testing.F) {
	f.Add("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	f.Fuzz(func(t *testing.T, s string) {
		v, err := CVSS3BaseScore(s)
		if err == nil && (v < 0 || v > 10) {
			t.Fatalf("score %v out of range", v)
		}
	})
}
