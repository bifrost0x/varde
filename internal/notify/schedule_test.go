// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"log/slog"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/store"
)

func TestWeeklyDoesNotRunBeforeDigestHour(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 1, 0, 0, time.UTC)
	ms := newMemStore()
	ch := &fakeChannel{}
	ms.states["notifydaily"] = store.SourceState{Source: "notify", Key: "daily", LastSuccess: time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)}
	ms.states["notifyweekly"] = store.SourceState{Source: "notify", Key: "weekly", LastSuccess: time.Date(2026, 11, 8, 8, 0, 0, 0, time.UTC)}
	base := []Candidate{{Item: item("weekly", policy.P3), State: store.StateOpen}}
	ms.queued["weekly"] = "P3"
	s := NewService(Config{Channels: []Channel{ch}, Store: ms, Candidates: candidates(ms, base), Log: slog.New(slog.DiscardHandler),
		DigestHour: 8, DigestWeekday: time.Sunday, Location: time.UTC, Now: func() time.Time { return now }})
	s.digestsDue(t.Context())
	for _, msg := range ch.sent {
		if msg.Kind == KindDigestWeekly {
			t.Fatal("startup after missed Saturday digest sends Sunday's weekly digest at 00:01 instead of 08:00")
		}
	}
	now = time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)
	s.digestsDue(t.Context())
	if ch.count() != 1 || ch.sent[0].Kind != KindDigestWeekly {
		t.Fatalf("weekly digest not delivered at its configured hour: %+v", ch.sent)
	}
	now = now.Add(time.Minute)
	s.digestsDue(t.Context())
	if ch.count() != 1 {
		t.Fatal("weekly digest repeated after delivery")
	}
}

func TestWeeklyDueRespectsSlotAndLastSuccess(t *testing.T) {
	loc := time.FixedZone("CET", 3600)
	s := NewService(Config{DigestHour: 8, DigestWeekday: time.Sunday, Location: loc})
	slot := time.Date(2026, 11, 15, 8, 0, 0, 0, loc)
	for _, tc := range []struct {
		name      string
		now, last time.Time
		want      bool
	}{
		{"first before hour", slot.Add(-time.Minute), time.Time{}, false},
		{"first at hour", slot, time.Time{}, true},
		{"first after hour", slot.Add(time.Minute), time.Time{}, true},
		{"first on next day", slot.AddDate(0, 0, 1), time.Time{}, false},
		{"before hour", slot.Add(-time.Minute), slot.AddDate(0, 0, -7), false},
		{"at hour", slot, slot.AddDate(0, 0, -7), true},
		{"already delivered", slot.Add(time.Minute), slot, false},
		{"catch up", slot.AddDate(0, 0, 1), slot.AddDate(0, 0, -7), true},
		{"caught up", slot.AddDate(0, 0, 1), slot.Add(time.Minute), false},
		{"UTC input before local hour", slot.Add(-time.Minute).UTC(), time.Time{}, false},
		{"UTC input at local hour", slot.UTC(), time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.weeklyDue(tc.now, time.Sunday, tc.last); got != tc.want {
				t.Fatalf("weeklyDue(%v, %v) = %v, want %v", tc.now, tc.last, got, tc.want)
			}
		})
	}
}
