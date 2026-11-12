// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"testing"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

func TestFindingGroupIncludesUrgentDuplicate(t *testing.T) {
	a := &app{d: Deps{Catalog: catalog.NewLive(&catalog.Catalog{})}}
	s := &snapshot{byID: map[string]inventory.Workload{
		"private": {ID: "private", Name: "private copy"},
		"public":  {ID: "public", Name: "public copy"},
	}}
	detail, err := json.Marshal(match.Finding{Evidence: match.Evidence{Version: "1.0.0"}, CVSS: 9.8})
	if err != nil {
		t.Fatal(err)
	}
	low := store.Finding{ID: "low", WorkloadID: "private", AppID: "app", AdvisoryID: "GHSA-1", MatchState: "affected", State: store.StateAcknowledged, Priority: "P3", Exposure: "internal", PathClass: "noise", Detail: detail}
	high := low
	high.ID = "high"
	high.WorkloadID = "public"
	high.State = store.StateOpen
	high.Priority = "P1"
	high.Exposure = "public"
	high.PathClass = "path-internet"
	for _, tc := range []struct {
		name string
		fs   []store.Finding
	}{
		{"private first", []store.Finding{low, high}},
		{"public first", []store.Finding{high, low}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gs := a.groupFindings(s, tc.fs)
			if len(gs) != 1 {
				t.Fatalf("groups %+v", gs)
			}
			g := gs[0]
			if g.Priority != "P1" || g.Exposure != "public" || g.PathClass != "path-internet" || g.New != 1 || g.Acknowledged != 0 || len(g.Rows) != 1 || len(g.Workloads) != 2 {
				t.Fatalf("duplicate hid urgent/open finding: %+v", g)
			}
			if r := g.Rows[0]; r.Priority != "P1" || r.State != store.StateOpen || r.WorkloadName != "public copy" {
				t.Fatalf("representative row hides urgent copy: %+v", r)
			}
		})
	}
}

// The group may contain an acknowledged P1 copy and an open P3 copy. The
// group keeps P1, but its row must link to the real open finding, with that
// finding's own state and priority.
func TestFindingGroupRowKeepsItsFindingState(t *testing.T) {
	a := &app{d: Deps{Catalog: catalog.NewLive(&catalog.Catalog{})}}
	s := &snapshot{byID: map[string]inventory.Workload{}}
	for _, reverse := range []bool{false, true} {
		ack := store.Finding{ID: "ack", AppID: "app", AdvisoryID: "GHSA-1", MatchState: "affected", State: store.StateAcknowledged, Priority: "P1"}
		open := ack
		open.ID, open.State, open.Priority = "open", store.StateOpen, "P3"
		fs := []store.Finding{ack, open}
		if reverse {
			fs[0], fs[1] = fs[1], fs[0]
		}
		g := a.groupFindings(s, fs)[0]
		if g.Priority != "P1" || g.New != 1 || g.Acknowledged != 0 || len(g.Rows) != 1 {
			t.Fatalf("group lost urgency or new state: %+v", g)
		}
		if row := g.Rows[0]; row.ID != open.ID || row.State != open.State || row.Priority != open.Priority {
			t.Fatalf("representative row does not match its linked finding: %+v", row)
		}
	}
}
