// SPDX-License-Identifier: Apache-2.0

package upstream

import "testing"

func TestDecide(t *testing.T) {
	cases := []struct {
		u    Urgency
		f    Fix
		want Bucket
	}{
		{Urgent, FixesTop, BucketNow},
		{Urgent, FixesOther, BucketMitigate},
		{Urgent, NoFix, BucketMitigate},
		{Serious, FixesTop, BucketSoon},
		{Serious, FixesOther, BucketSoon},
		{Serious, NoFix, BucketSoon},
		{Minor, FixesTop, BucketLater},
		{Minor, FixesOther, BucketLater},
		{Minor, NoFix, BucketLater},
		{Unconfirmed, FixesTop, BucketCheck},
		{Unconfirmed, FixesOther, BucketCheck},
		{Unconfirmed, NoFix, BucketCheck},
	}
	for _, c := range cases {
		if got := Decide(c.u, c.f); got != c.want {
			t.Errorf("Decide(%d, %d) = %s, want %s", c.u, c.f, got, c.want)
		}
	}
	// Every row of the table is covered above, and nothing outside it is
	// ever "update now".
	if n := len(decisions) * 3; n != len(cases) {
		t.Errorf("table has %d cases, test %d", n, len(cases))
	}
	if got := Decide(Urgency(9), FixesTop); got == BucketNow {
		t.Error("an unknown urgency became update now")
	}
	for _, p := range []struct {
		prio string
		want Urgency
	}{{"P1", Urgent}, {"P2", Serious}, {"P3", Minor}, {"", Unconfirmed}} {
		if got := UrgencyOf(p.prio); got != p.want {
			t.Errorf("UrgencyOf(%q) = %d", p.prio, got)
		}
	}
}
