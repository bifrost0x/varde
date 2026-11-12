// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

func TestAssess(t *testing.T) {
	pub, lan, internal, unknown := inventory.ExposurePublic, inventory.ExposureLAN, inventory.ExposureInternal, inventory.ExposureUnknown
	cases := []struct {
		name string
		in   Input
		want Priority
	}{
		{"unverified never prioritised", Input{Affected: false, KEV: true, CVSS: 10, Exposure: pub}, None},
		{"KEV internal", Input{Affected: true, KEV: true, CVSS: 3, Exposure: internal}, P1},
		{"critical public", Input{Affected: true, CVSS: 9.0, Exposure: pub}, P1},
		{"critical lan", Input{Affected: true, CVSS: 9.8, Exposure: lan}, P2},
		{"high public likely exploited", Input{Affected: true, CVSS: 7.0, EPSS: 0.10, Exposure: pub}, P1},
		{"high public unlikely", Input{Affected: true, CVSS: 7.5, EPSS: 0.09, Exposure: pub}, P2},
		{"high internal", Input{Affected: true, CVSS: 7.0, Exposure: internal}, P2},
		{"medium lan", Input{Affected: true, CVSS: 4.0, Exposure: lan}, P2},
		{"medium internal", Input{Affected: true, CVSS: 6.9, Exposure: internal}, P3},
		{"medium unknown exposure", Input{Affected: true, CVSS: 5, Exposure: unknown}, P3},
		{"low public", Input{Affected: true, CVSS: 3.9, Exposure: pub}, P3},
		{"no cvss public", Input{Affected: true, Exposure: pub}, P2},
		{"no cvss lan", Input{Affected: true, Exposure: lan}, P3},
	}
	th := Defaults()
	for _, c := range cases {
		if got, reason := th.Assess(c.in); got != c.want || reason == "" {
			t.Errorf("%s: %q (%s), want %q", c.name, got, reason, c.want)
		}
	}
	if P1.Rank() <= P2.Rank() || P2.Rank() <= P3.Rank() || P3.Rank() <= None.Rank() {
		t.Error("rank order")
	}
}
