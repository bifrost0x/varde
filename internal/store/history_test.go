// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

// The history says when a finding was opened and resolved, and why: an
// update to a newer version, the workload or package gone, or the advisory
// no longer applying to the same version.
func TestFindingHistoryCauses(t *testing.T) {
	s, _ := openTest(t)
	ctx, t0 := t.Context(), time.Unix(1_800_000_000, 0)
	if err := s.UpsertHost(ctx, localHost(t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("a", "node64", "ghcr.io/ipv64net/node64:latest"), container("b", "immich", "immich:v1")}, t0); err != nil {
		t.Fatal(err)
	}
	wa := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "a")
	wb := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "b")
	in := func(w, app, adv, v string) FindingInput {
		return FindingInput{WorkloadID: w, AppID: app, AdvisoryID: adv, MatchState: "affected", FixedIn: "9",
			Detail: map[string]any{"evidence": map[string]any{"version": v}}}
	}
	updated := in(wa, "os:Go/github.com/andybalholm/brotli", "GO-1", "1.2.7")
	withdrawn := in(wa, "os:Debian:12/zlib", "DEBIAN-CVE-1", "1.2.13")
	uninstalled := in(wa, "os:Debian:12/curl", "DEBIAN-CVE-2", "7.88")
	removed := in(wb, "immich", "GHSA-1", "1.0")
	if _, err := s.SyncFindingsSeen(ctx, []FindingInput{updated, withdrawn, uninstalled, removed}, nil, t0); err != nil {
		t.Fatal(err)
	}

	t1 := t0.Add(48 * time.Hour)
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("a", "node64", "ghcr.io/ipv64net/node64:latest")}, t1); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{
		SeenKey(wa, updated.AppID):   "1.2.8",
		SeenKey(wa, withdrawn.AppID): "1.2.13",
		// The image of node64 was read: curl is gone from it.
		SeenKey(wa, SeenImage): "",
	}
	ch, err := s.SyncFindingsSeen(ctx, nil, seen, t1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Resolved) != 4 {
		t.Fatalf("resolved %d, want 4", len(ch.Resolved))
	}
	evs, err := s.FindingEvents(ctx, HistoryFilter{Kind: "resolved"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{ cause, from, to string }{
		updated.AdvisoryID:     {CauseUpdated, "1.2.7", "1.2.8"},
		withdrawn.AdvisoryID:   {CauseAdvisory, "1.2.13", ""},
		uninstalled.AdvisoryID: {CauseUninstalled, "7.88", ""},
		removed.AdvisoryID:     {CauseRemoved, "1.0", ""},
	}
	if len(evs) != len(want) {
		t.Fatalf("%d resolutions in the history, want %d: %+v", len(evs), len(want), evs)
	}
	for _, e := range evs {
		w := want[e.AdvisoryID]
		if e.Cause != w.cause || e.FromVersion != w.from || e.ToVersion != w.to {
			t.Errorf("%s: cause %q %q → %q, want %q %q → %q", e.AdvisoryID, e.Cause, e.FromVersion, e.ToVersion, w.cause, w.from, w.to)
		}
		if e.OpenedAt == nil || !e.OpenedAt.Equal(t0) || !e.At.Equal(t1) {
			t.Errorf("%s: open from %v to %v, want %v to %v", e.AdvisoryID, e.OpenedAt, e.At, t0, t1)
		}
		if e.HostName != "nas" || e.WorkloadName == "" {
			t.Errorf("%s: names %q/%q not copied", e.AdvisoryID, e.HostName, e.WorkloadName)
		}
	}

	// Back again: reopened, and the history keeps both.
	t2 := t1.Add(time.Hour)
	if _, err := s.SyncFindingsSeen(ctx, []FindingInput{withdrawn}, seen, t2); err != nil {
		t.Fatal(err)
	}
	all, err := s.FindingEvents(ctx, HistoryFilter{FindingID: withdrawn.ID()})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range all {
		kinds = append(kinds, e.Kind)
	}
	if len(kinds) != 3 || kinds[0] != "reopened" || kinds[1] != "resolved" || kinds[2] != "opened" {
		t.Errorf("history of one finding %v, want reopened, resolved, opened", kinds)
	}
	if got, err := s.FindingEvents(ctx, HistoryFilter{From: t1, To: t2}); err != nil || len(got) != 4 {
		t.Errorf("events in [t1, t2): %d %v, want the 4 resolutions", len(got), err)
	}
}

// A package missing from an image that was not read (yet, or completely)
// is not counted as fixed; a host package uninstalled from a host that is
// still there is.
func TestFindingHistoryUnknownAndUninstalled(t *testing.T) {
	s, _ := openTest(t)
	ctx, t0 := t.Context(), time.Unix(1_800_000_000, 0)
	if err := s.UpsertHost(ctx, localHost(t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer, []inventory.Workload{container("a", "web", "nginx:1.24")}, t0); err != nil {
		t.Fatal(err)
	}
	pkg := inventory.Workload{Kind: inventory.KindPackage, RuntimeID: "os:dpkg:openssl", Name: "openssl", State: "installed",
		Package: &inventory.Package{Manager: "dpkg", Name: "openssl", Version: "3.0.1", System: true}}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindPackage, []inventory.Workload{pkg}, t0); err != nil {
		t.Fatal(err)
	}
	wa := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "a")
	wp := inventory.WorkloadID(inventory.LocalHostID, inventory.KindPackage, pkg.RuntimeID)
	unread := FindingInput{WorkloadID: wa, AppID: "os:Debian:12/zlib", AdvisoryID: "DEBIAN-CVE-1", MatchState: "affected", FixedIn: "2"}
	host := FindingInput{WorkloadID: wp, AppID: "os:Debian:12/openssl", AdvisoryID: "DEBIAN-CVE-2", MatchState: "affected", FixedIn: "3.0.2"}
	if _, err := s.SyncFindingsSeen(ctx, []FindingInput{unread, host}, nil, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAssessments(ctx, []Assessment{{ID: unread.ID(), Priority: "P1", Exposure: "lan"}}); err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(time.Hour)
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindPackage, nil, t1); err != nil {
		t.Fatal(err)
	}
	ch, err := s.SyncFindingsSeen(ctx, nil, map[string]string{SeenKey(wa, SeenApps): ""}, t1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Resolved) != 1 || ch.Resolved[0] != host.ID() {
		t.Fatalf("only the uninstalled host package may resolve: %+v", ch)
	}
	f, err := s.GetFinding(ctx, unread.ID())
	if err != nil || f.State != StateOpen || f.ResolvedAt != nil {
		t.Fatalf("unread image finding must stay open: %+v (%v)", f, err)
	}
	evs, err := s.FindingEvents(ctx, HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		switch {
		case e.Kind == "resolved" && e.AdvisoryID == unread.AdvisoryID:
			t.Error("package of an unread image must not have a resolution event")
		case e.Kind == "resolved" && e.AdvisoryID == host.AdvisoryID && e.Cause != CauseUninstalled:
			t.Errorf("uninstalled host package resolved as %q, want %q", e.Cause, CauseUninstalled)
		case e.Kind == "opened" && e.AdvisoryID == unread.AdvisoryID && e.Priority != "P1":
			t.Errorf("opening keeps priority %q, want the first rating P1", e.Priority)
		}
	}
}

// The export reads every entry of a period, not the first page.
func TestEachFindingEventPages(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	const n = maxHistory + 3
	for i := range n {
		// Pairs share a time, so paging must order by ID as well.
		if _, err := tx.ExecContext(ctx, `INSERT INTO finding_events (finding_id, at, kind, workload_id, app_id, advisory_id) VALUES (?, ?, 'opened', 'w', 'a', 'x')`,
			fmt.Sprint(i), 1_800_000_000_000+int64(i/2)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	if err := s.EachFindingEvent(ctx, HistoryFilter{}, func(e FindingEvent) error {
		if seen[e.FindingID] {
			t.Fatalf("event %s twice", e.FindingID)
		}
		seen[e.FindingID] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != n {
		t.Errorf("%d events, want %d", len(seen), n)
	}
}
