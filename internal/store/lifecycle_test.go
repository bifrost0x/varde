// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

func setupFindings(t *testing.T) (*Store, []string, time.Time) {
	t.Helper()
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	if err := s.UpsertHost(ctx, localHost(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("a", "immich-1", "x"), container("b", "immich-2", "x")}, now); err != nil {
		t.Fatal(err)
	}
	wa := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "a")
	wb := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "b")
	in := []FindingInput{
		{WorkloadID: wa, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected"},
		{WorkloadID: wb, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected"},
		{WorkloadID: wa, AppID: "immich", AdvisoryID: "GHSA-2", MatchState: "affected"},
	}
	if _, err := s.SyncFindings(ctx, in, now); err != nil {
		t.Fatal(err)
	}
	return s, []string{FindingID(wa, "GHSA-1"), FindingID(wb, "GHSA-1"), FindingID(wa, "GHSA-2"), wa, wb}, now
}

func state(t *testing.T, s *Store, id string) Finding {
	t.Helper()
	f, err := s.GetFinding(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAckSnoozeReopen(t *testing.T) {
	ctx := context.Background()
	s, ids, now := setupFindings(t)
	if err := s.Acknowledge(ctx, ids[0], now); err != nil {
		t.Fatal(err)
	}
	if f := state(t, s, ids[0]); f.State != StateAcknowledged || f.AcknowledgedAt == nil {
		t.Fatalf("ack: %+v", f)
	}
	if err := s.Snooze(ctx, ids[0], now.Add(-time.Hour), now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("snooze into the past: %v", err)
	}
	if err := s.Snooze(ctx, ids[0], now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.ExpireSnoozes(ctx, now.Add(30*time.Minute)); n != 0 {
		t.Fatal("snooze expired early")
	}
	if n, _ := s.ExpireSnoozes(ctx, now.Add(2*time.Hour)); n != 1 || state(t, s, ids[0]).State != StateOpen {
		t.Fatal("snooze did not expire")
	}
	if err := s.Acknowledge(ctx, "nope", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.Reopen(ctx, ids[0], now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reopen open finding: %v", err)
	}
}

func TestSuppressionScopes(t *testing.T) {
	ctx := context.Background()
	s, ids, now := setupFindings(t)
	exp := now.Add(24 * time.Hour)
	if err := s.AddSuppression(ctx, Suppression{ID: "s1", AppID: "immich", WorkloadID: ids[3], AdvisoryID: "GHSA-1",
		Reason: "not reachable", CreatedBy: "test", CreatedAt: now, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySuppressions(ctx, now); err != nil {
		t.Fatal(err)
	}
	if f := state(t, s, ids[0]); f.State != StateSuppressed || f.SuppressionID != "s1" {
		t.Fatalf("workload-scoped suppression: %+v", f)
	}
	if state(t, s, ids[1]).State != StateOpen || state(t, s, ids[2]).State != StateOpen {
		t.Fatal("suppression leaked to other workload or advisory")
	}
	// Still suppressed after a re-sync of the same match.
	if _, err := s.SyncFindings(ctx, []FindingInput{
		{WorkloadID: ids[3], AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected"},
		{WorkloadID: ids[4], AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected"},
		{WorkloadID: ids[3], AppID: "immich", AdvisoryID: "GHSA-2", MatchState: "affected"},
	}, now); err != nil {
		t.Fatal(err)
	}
	if state(t, s, ids[0]).State != StateSuppressed {
		t.Fatal("re-sync dropped suppression")
	}
	// Expiry releases it.
	if err := s.ApplySuppressions(ctx, now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if f := state(t, s, ids[0]); f.State != StateOpen || f.SuppressionID != "" {
		t.Fatalf("expired suppression: %+v", f)
	}
	// App-wide suppression covers both workloads; deleting it releases them.
	if err := s.AddSuppression(ctx, Suppression{ID: "s2", AppID: "immich", AdvisoryID: "GHSA-1", Reason: "accepted risk", CreatedBy: "test", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySuppressions(ctx, now); err != nil {
		t.Fatal(err)
	}
	if state(t, s, ids[0]).State != StateSuppressed || state(t, s, ids[1]).State != StateSuppressed {
		t.Fatal("app-wide suppression")
	}
	if _, err := s.DeleteSuppression(ctx, "s2"); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySuppressions(ctx, now); err != nil {
		t.Fatal(err)
	}
	if state(t, s, ids[1]).State != StateOpen {
		t.Fatal("deleted suppression still applied")
	}
	if sups, _ := s.Suppressions(ctx); len(sups) != 1 {
		t.Fatalf("suppressions: %d", len(sups))
	}
}

func TestNotificationBookkeeping(t *testing.T) {
	ctx := context.Background()
	s, ids, now := setupFindings(t)
	if err := s.SetAssessments(ctx, []Assessment{{ID: ids[0], Priority: "P1", Reason: "kev", Exposure: "public", ExposureEvidence: []string{"traefik"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueDigest(ctx, ids[1:2], "P2"); err != nil {
		t.Fatal(err)
	}
	if f := state(t, s, ids[1]); f.DigestPending != "P2" {
		t.Fatalf("queued: %+v", f)
	}
	if err := s.MarkNotified(ctx, ids[:2], "P1", now); err != nil {
		t.Fatal(err)
	}
	f := state(t, s, ids[0])
	if f.Priority != "P1" || f.LastNotifiedPriority != "P1" || f.NotifiedAt == nil || f.ExposureEvidence[0] != "traefik" {
		t.Fatalf("notified: %+v", f)
	}
	if state(t, s, ids[1]).DigestPending != "" {
		t.Fatal("digest flag not cleared")
	}

	// Resolve and reopen: notification history starts fresh.
	wa := ids[3]
	if _, err := s.SyncFindings(ctx, nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncFindings(ctx, []FindingInput{{WorkloadID: wa, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected"}}, now); err != nil {
		t.Fatal(err)
	}
	if f := state(t, s, ids[0]); f.State != StateOpen || f.LastNotifiedPriority != "" || f.NotifiedAt != nil {
		t.Fatalf("reopened history: %+v", f)
	}

	if err := s.LogNotification(ctx, NotificationEntry{Channel: "ntfy", Kind: "immediate", FindingIDs: ids[:1], SentAt: now, Status: "sent"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Audit(ctx, AuditEntry{At: now, Actor: "api", Action: "suppress", Target: ids[0]}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Notifications(ctx, 10); len(n) != 1 || n[0].FindingIDs[0] != ids[0] {
		t.Fatalf("notification log: %+v", n)
	}
	if a, _ := s.AuditLog(ctx, 10); len(a) != 1 || a[0].Action != "suppress" {
		t.Fatalf("audit log: %+v", a)
	}
	if err := s.PurgeLogs(ctx, now.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Notifications(ctx, 10); len(n) != 0 {
		t.Fatal("notification log not purged")
	}
}
