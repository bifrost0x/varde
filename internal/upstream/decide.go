// SPDX-License-Identifier: Apache-2.0

package upstream

// Urgency is the most pressing confirmed finding of an app: P1 is urgent,
// P2 serious, P3 minor; Unconfirmed means only findings Varde cannot
// confirm.
type Urgency int

// Urgencies, least pressing first.
const (
	Unconfirmed Urgency = iota
	Minor
	Serious
	Urgent
)

// UrgencyOf maps a policy priority to an urgency.
func UrgencyOf(priority string) Urgency {
	switch priority {
	case "P1":
		return Urgent
	case "P2":
		return Serious
	case "P3":
		return Minor
	}
	return Unconfirmed
}

// Fix is what the one update of an app does to its findings.
type Fix int

const (
	// NoFix means no update is known to fix anything (no newer image, one that
	// fixes nothing, or Varde cannot tell).
	NoFix Fix = iota
	// FixesOther means an update fixes findings, but none of the most pressing
	// ones.
	FixesOther
	// FixesTop means an update fixes at least one of the most pressing
	// findings.
	FixesTop
)

// Bucket is the state of an app card: what a person does about it.
type Bucket string

// Buckets, most pressing first.
const (
	BucketNow      Bucket = "now"      // update now: urgent, and an update fixes it
	BucketMitigate Bucket = "mitigate" // urgent, but no update fixes it yet
	BucketSoon     Bucket = "soon"     // serious
	BucketLater    Bucket = "later"    // minor
	BucketCheck    Bucket = "check"    // nothing Varde can confirm
)

// decisions is the whole rule, one row per case. "Update now" needs both
// urgency and an update that fixes an urgent finding; urgency without one
// is "mitigate", which still notifies at once. Serious and minor findings
// keep their bucket with or without a fix: the card's action then says
// that none exists yet.
var decisions = map[Urgency]map[Fix]Bucket{
	Urgent:      {FixesTop: BucketNow, FixesOther: BucketMitigate, NoFix: BucketMitigate},
	Serious:     {FixesTop: BucketSoon, FixesOther: BucketSoon, NoFix: BucketSoon},
	Minor:       {FixesTop: BucketLater, FixesOther: BucketLater, NoFix: BucketLater},
	Unconfirmed: {FixesTop: BucketCheck, FixesOther: BucketCheck, NoFix: BucketCheck},
}

// Decide returns the bucket of an app card.
func Decide(u Urgency, f Fix) Bucket {
	if b, ok := decisions[u][f]; ok {
		return b
	}
	// Every combination has a row (TestDecide); a value outside them is
	// never "update now".
	if u >= Urgent {
		return BucketMitigate
	}
	return BucketCheck
}
