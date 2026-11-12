// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

// One Go advisory naming two modules of a program is two findings, each
// with its own update; a distribution advisory keeps its (workload,
// advisory) ID, so existing findings keep theirs.
func TestFindingIDPerGoModule(t *testing.T) {
	xnet := FindingInput{WorkloadID: "w", AppID: "os:Go/golang.org/x/net", AdvisoryID: "GO-2026-4918"}
	std := FindingInput{WorkloadID: "w", AppID: "os:Go/stdlib", AdvisoryID: "GO-2026-4918"}
	if xnet.ID() == std.ID() {
		t.Fatal("two modules of one advisory share a finding")
	}
	if (FindingInput{WorkloadID: "w", AppID: "os:Debian:12/openssl", AdvisoryID: "DEBIAN-CVE-2024-1"}).ID() != FindingID("w", "DEBIAN-CVE-2024-1") {
		t.Fatal("distribution finding ID changed")
	}
}

// Both module findings of one advisory are stored: the table used to
// refuse a second finding of the same advisory on a workload, which
// stopped every analysis of an image with such a program.
func TestSyncFindingsTwoModulesOfOneAdvisory(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := t.Context(), time.Unix(1_800_000_000, 0)
	if err := s.UpsertHost(ctx, localHost(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer, []inventory.Workload{container("c", "traefik", "traefik:v2.10.4")}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "c")
	in := []FindingInput{
		{WorkloadID: wid, AppID: "os:Go/golang.org/x/net", AdvisoryID: "GO-2026-4918", MatchState: "affected", FixedIn: "0.38.0"},
		{WorkloadID: wid, AppID: "os:Go/stdlib", AdvisoryID: "GO-2026-4918", MatchState: "affected", FixedIn: "1.24.4"},
	}
	ch, err := s.SyncFindings(ctx, in, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.New) != 2 {
		t.Fatalf("%d new findings, want one per module", len(ch.New))
	}
	fs, err := s.Findings(ctx, FindingFilter{WorkloadID: wid})
	if err != nil || len(fs) != 2 {
		t.Fatalf("stored %d findings (%v), want 2", len(fs), err)
	}
}

// A Go finding stored under the (workload, advisory) ID before findings
// were split per module keeps its state under the module's ID: upgrading
// must not resolve and reopen every Go finding, which would notify again
// and drop acknowledgements.
func TestSyncFindingsMovesLegacyModuleID(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := t.Context(), time.Unix(1_800_000_000, 0)
	if err := s.UpsertHost(ctx, localHost(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer, []inventory.Workload{container("c", "traefik", "traefik:v2.10.4")}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "c")
	legacy := FindingID(wid, "GO-2026-4918")
	if _, err := s.db.ExecContext(ctx, `INSERT INTO findings (id, workload_id, app_id, advisory_id, match_state, fixed_in, detail_json, first_seen, last_changed, acknowledged_at, state)
		VALUES (?, ?, 'os:Go/golang.org/x/net', 'GO-2026-4918', 'affected', '0.38.0', '{}', ?, ?, ?, 'acknowledged')`, legacy, wid, millis(now), millis(now), millis(now)); err != nil {
		t.Fatal(err)
	}
	xnet := FindingInput{WorkloadID: wid, AppID: "os:Go/golang.org/x/net", AdvisoryID: "GO-2026-4918", MatchState: "affected", FixedIn: "0.38.0"}
	std := FindingInput{WorkloadID: wid, AppID: "os:Go/stdlib", AdvisoryID: "GO-2026-4918", MatchState: "affected", FixedIn: "1.24.4"}
	ch, err := s.SyncFindings(ctx, []FindingInput{std, xnet}, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Resolved) != 0 || len(ch.New) != 1 || ch.New[0] != std.ID() {
		t.Errorf("changes %+v, want only the standard library new", ch)
	}
	f, err := s.GetFinding(ctx, xnet.ID())
	if err != nil {
		t.Fatalf("x/net finding under its module ID: %v", err)
	}
	if f.State != "acknowledged" || !f.FirstSeen.Equal(now) {
		t.Errorf("moved finding state %s first seen %v, want acknowledged since %v", f.State, f.FirstSeen, now)
	}
	if _, err := s.GetFinding(ctx, legacy); err == nil {
		t.Error("legacy ID still stored")
	}
}
