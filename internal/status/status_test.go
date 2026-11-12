// SPDX-License-Identifier: Apache-2.0

package status

import (
	"testing"

	"github.com/bifrost0x/varde/internal/store"
)

func TestCountAndState(t *testing.T) {
	f := func(state, prio, match string) store.Finding {
		return store.Finding{State: state, Priority: prio, MatchState: match}
	}
	cases := []struct {
		name string
		fs   []store.Finding
		want string
	}{
		{"none", nil, Clear},
		{"resolved only", []store.Finding{f(store.StateResolved, "P1", "affected"), f(store.StateSuppressed, "P1", "affected")}, Clear},
		{"new P1", []store.Finding{f(store.StateOpen, "P1", "affected")}, Urgent},
		// A new P2 is not "clear"; the API used to say so.
		{"new P2", []store.Finding{f(store.StateOpen, "P2", "affected")}, New},
		{"new unverified", []store.Finding{f(store.StateOpen, "", "unverified")}, New},
		// An acknowledged P1 no longer notifies; it is not urgent.
		{"acknowledged P1", []store.Finding{f(store.StateAcknowledged, "P1", "affected"), f(store.StateSnoozed, "P3", "affected")}, Acknowledged},
	}
	for _, c := range cases {
		if got := Count(c.fs).State(); got != c.want {
			t.Errorf("%s: state %s, want %s", c.name, got, c.want)
		}
	}
	c := Count([]store.Finding{
		f(store.StateOpen, "P1", "affected"), f(store.StateOpen, "P2", "affected"), f(store.StateOpen, "P1", "unverified"),
		f(store.StateAcknowledged, "P2", "affected"), f(store.StateResolved, "P2", "affected"),
	})
	if c.New != (Priorities{P1: 1, P2: 1, Unverified: 1}) || c.Acknowledged != (Priorities{P2: 1}) || c.Open() != (Priorities{P1: 1, P2: 2, Unverified: 1}) {
		t.Errorf("counts: %+v open %+v", c, c.Open())
	}
}
