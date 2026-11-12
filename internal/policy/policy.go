// SPDX-License-Identifier: Apache-2.0

// Package policy assigns priorities to findings. Defaults:
//
//	P1 (notify now):   affected and (KEV, or CVSS >= 9 and public,
//	                   or CVSS >= 7 and public and EPSS >= 0.10)
//	P2 (daily digest): affected and (CVSS >= 7, or public/LAN and CVSS >= 4)
//	P3 (weekly):       any other affected finding
//
// Without CVSS: P2 if public, else P3. Unverified findings get no priority
// and never notify.
package policy

import (
	"github.com/bifrost0x/varde/internal/inventory"
)

// Priority of a finding. Empty means "no priority" (never notifies).
type Priority string

// Priorities, most urgent first.
const (
	P1   Priority = "P1"
	P2   Priority = "P2"
	P3   Priority = "P3"
	None Priority = ""
)

// Rank orders priorities: P1 = 3, P2 = 2, P3 = 1, None = 0.
func (p Priority) Rank() int {
	switch p {
	case P1:
		return 3
	case P2:
		return 2
	case P3:
		return 1
	}
	return 0
}

// Thresholds are the tunable parts of the matrix.
type Thresholds struct {
	P1CVSSPublic     float64 // CVSS for P1 on public exposure alone
	P1CVSSPublicEPSS float64 // CVSS for P1 on public exposure combined with EPSS
	P1EPSS           float64 // EPSS for that combination
	P2CVSS           float64 // CVSS for P2 regardless of exposure
	P2CVSSExposed    float64 // CVSS for P2 on public or LAN exposure
}

// Defaults returns the default thresholds.
func Defaults() Thresholds {
	return Thresholds{P1CVSSPublic: 9.0, P1CVSSPublicEPSS: 7.0, P1EPSS: 0.10, P2CVSS: 7.0, P2CVSSExposed: 4.0}
}

// Input is what the policy looks at.
type Input struct {
	Affected bool // false for unverified matches
	KEV      bool
	CVSS     float64 // 0 when unknown
	EPSS     float64
	Exposure inventory.Exposure
}

// Assess returns the priority and a short reason.
func (t Thresholds) Assess(in Input) (Priority, string) {
	if !in.Affected {
		return None, "unverified: not prioritised"
	}
	public := in.Exposure == inventory.ExposurePublic
	exposed := public || in.Exposure == inventory.ExposureLAN
	switch {
	case in.KEV:
		return P1, "known exploited (CISA KEV)"
	case public && in.CVSS >= t.P1CVSSPublic:
		return P1, "critical severity and publicly exposed"
	case public && in.CVSS >= t.P1CVSSPublicEPSS && in.EPSS >= t.P1EPSS:
		return P1, "high severity, publicly exposed, likely to be exploited (EPSS)"
	case in.CVSS == 0 && public:
		return P2, "severity unknown and publicly exposed"
	case in.CVSS == 0:
		return P3, "severity unknown"
	case in.CVSS >= t.P2CVSS:
		return P2, "high severity"
	case exposed && in.CVSS >= t.P2CVSSExposed:
		return P2, "medium severity and reachable"
	default:
		return P3, "low impact"
	}
}
