// SPDX-License-Identifier: Apache-2.0

// Package status condenses the findings into the counts and the overall state
// that the overview, the API and the metrics show, so every place reports
// the same numbers.
package status

import (
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// Overall states, from most to least pressing.
const (
	// Urgent: at least one new P1 finding.
	Urgent = "urgent"
	// New: new findings, none of them P1.
	New = "new"
	// Acknowledged: open findings, all seen by a user.
	Acknowledged = "acknowledged"
	// Clear: no open finding.
	Clear = "clear"
)

// Priorities counts findings per priority; Unverified are findings Varde
// could not confirm, which carry no priority that notifies.
type Priorities struct {
	P1         int `json:"P1"`
	P2         int `json:"P2"`
	P3         int `json:"P3"`
	Unverified int `json:"unverified"`
}

// Total is the sum of all counts.
func (p Priorities) Total() int { return p.P1 + p.P2 + p.P3 + p.Unverified }

// Findings are the counts of the active findings.
type Findings struct {
	// New are findings nobody acknowledged or snoozed yet.
	New Priorities `json:"new"`
	// Acknowledged are acknowledged or snoozed findings, still open.
	Acknowledged Priorities `json:"acknowledged"`
}

// Open is New plus Acknowledged.
func (f Findings) Open() Priorities {
	return Priorities{
		P1: f.New.P1 + f.Acknowledged.P1, P2: f.New.P2 + f.Acknowledged.P2, P3: f.New.P3 + f.Acknowledged.P3,
		Unverified: f.New.Unverified + f.Acknowledged.Unverified,
	}
}

// State is the overall state.
func (f Findings) State() string {
	switch {
	case f.New.P1 > 0:
		return Urgent
	case f.New.Total() > 0:
		return New
	case f.Acknowledged.Total() > 0:
		return Acknowledged
	}
	return Clear
}

// Active reports whether a finding state counts as open.
func Active(state string) bool {
	return state == store.StateOpen || state == store.StateAcknowledged || state == store.StateSnoozed
}

// Count counts the active findings. A finding Varde could not confirm is
// counted as unverified whatever its priority.
func Count(fs []store.Finding) Findings {
	var c Findings
	for _, f := range fs {
		if !Active(f.State) {
			continue
		}
		p := &c.New
		if f.State != store.StateOpen {
			p = &c.Acknowledged
		}
		switch {
		case f.MatchState != string(match.Affected):
			p.Unverified++
		case f.Priority == "P1":
			p.P1++
		case f.Priority == "P2":
			p.P2++
		case f.Priority == "P3":
			p.P3++
		}
	}
	return c
}
