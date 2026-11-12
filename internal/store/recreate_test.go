// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

// docker compose up -d after a pull gives a container a new ID under the
// same name. It used to count as one container removed and one added, so
// every finding was resolved and opened again: the fixed ones could not be
// told apart from the rest, and acknowledgements were lost.
func TestRecreatedContainerKeepsItsFindings(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := t.Context(), time.Unix(1_800_000_000, 0)
	if err := s.UpsertHost(ctx, localHost(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("old", "node64", "ghcr.io/ipv64net/node64:latest"), container("db", "postgres", "postgres:16")}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "old")
	kept := FindingInput{WorkloadID: wid, AppID: "os:Go/stdlib", AdvisoryID: "GO-2026-1", MatchState: "affected", FixedIn: "1.26.1"}
	fixed := FindingInput{WorkloadID: wid, AppID: "os:Go/github.com/andybalholm/brotli", AdvisoryID: "GO-2026-6888", MatchState: "affected", FixedIn: "1.2.8"}
	if _, err := s.SyncFindings(ctx, []FindingInput{kept, fixed}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Acknowledge(ctx, kept.ID(), now); err != nil {
		t.Fatal(err)
	}

	later := now.Add(time.Hour)
	ch, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("new", "node64", "ghcr.io/ipv64net/node64:latest"), container("db", "postgres", "postgres:16")}, later)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Added != 0 || ch.Removed != 0 || ch.Changed != 1 {
		t.Errorf("changes %+v, want the container changed, not replaced", ch)
	}
	w, err := s.Workload(ctx, wid)
	if err != nil {
		t.Fatalf("workload of the recreated container: %v", err)
	}
	if w.RuntimeID != "new" || w.RemovedAt != nil {
		t.Errorf("workload runtime %q removed %v, want the new container, present", w.RuntimeID, w.RemovedAt)
	}
	// The analysis of the new image still reports one of the two.
	if _, err := s.SyncFindings(ctx, []FindingInput{kept}, later); err != nil {
		t.Fatal(err)
	}
	fs, err := s.Findings(ctx, FindingFilter{IncludeResolved: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("%d findings, want the same two", len(fs))
	}
	for _, f := range fs {
		switch f.AdvisoryID {
		case kept.AdvisoryID:
			if f.State != "acknowledged" || !f.FirstSeen.Equal(now) {
				t.Errorf("kept finding state %s first seen %v, want acknowledged since %v", f.State, f.FirstSeen, now)
			}
		case fixed.AdvisoryID:
			if f.State != "resolved" {
				t.Errorf("fixed finding state %s, want resolved", f.State)
			}
		}
	}

	// Removed first (docker compose down), created again in a later
	// snapshot: still the same workload. Another name is another one.
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer, []inventory.Workload{container("db", "postgres", "postgres:16")}, later.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ch, err = s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("again", "node64", "ghcr.io/ipv64net/node64:latest"), container("db", "postgres", "postgres:16"), container("x", "other", "nginx")}, later.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Added != 2 {
		t.Errorf("changes %+v, want node64 back and other new", ch)
	}
	if w, err := s.Workload(ctx, wid); err != nil || w.RuntimeID != "again" || w.RemovedAt != nil {
		t.Errorf("node64 after down and up: %+v %v", w, err)
	}
	if _, err := s.Workload(ctx, inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "x")); err != nil {
		t.Errorf("a container of a new name has its own workload: %v", err)
	}
}
