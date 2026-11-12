// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/store"
)

func TestDigestFailureRetriesBeforeNextDay(t *testing.T) {
	for _, failure := range []string{"channel", "candidates", "notices"} {
		t.Run(failure, func(t *testing.T) {
			ms := newMemStore()
			ch := &fakeChannel{}
			now := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
			previous := now.Add(-24 * time.Hour)
			ms.states["notifydaily"] = store.SourceState{Source: "notify", Key: "daily", LastSuccess: previous}
			base := []Candidate{{Item: item("daily", policy.P2), State: store.StateOpen}}
			failed := true
			cands := candidates(ms, base)
			svc := NewService(Config{Channels: []Channel{ch}, Store: ms, Log: slog.New(slog.DiscardHandler),
				DigestHour: 8, DigestWeekday: time.Sunday, Location: time.UTC, Now: func() time.Time { return now },
				Candidates: func(ctx context.Context) ([]Candidate, error) {
					if failed && failure == "candidates" {
						return nil, errors.New("database unavailable")
					}
					return cands(ctx)
				}, Notices: func(context.Context) ([]Notice, error) {
					if failed && failure == "notices" {
						return nil, errors.New("notices unavailable")
					}
					return nil, nil
				}})
			if err := svc.Evaluate(t.Context()); err != nil && failure != "candidates" {
				t.Fatal(err)
			}
			// Queue the existing finding even when its scheduled reload fails.
			ms.queued["daily"] = "P2"
			if failure == "channel" {
				ch.fails = 1
			}
			svc.digestsDue(t.Context())
			st, err := ms.SourceState(t.Context(), "notify", "daily")
			if err != nil {
				t.Fatal(err)
			}
			if !st.LastSuccess.Equal(previous) || !st.LastAttempt.Equal(now) {
				t.Errorf("failed run recorded as success: %+v", st)
			}
			failed = false
			now = now.Add(time.Minute)
			svc.digestsDue(t.Context())
			st, _ = ms.SourceState(t.Context(), "notify", "daily")
			if !st.LastSuccess.Equal(now) || ms.notified["daily"] != "P2" || ch.count() != 1 {
				t.Fatalf("digest not recovered next minute: state=%+v notified=%v sent=%d", st, ms.notified, ch.count())
			}
			svc.digestsDue(t.Context())
			if ch.count() != 1 {
				t.Fatal("successful digest repeated")
			}
		})
	}
}

func TestUnsentDigestFollowsPriorityDowngrade(t *testing.T) {
	ms := newMemStore()
	ch := &fakeChannel{}
	base := []Candidate{{Item: item("downgraded", policy.P2), State: store.StateOpen}}
	svc := NewService(Config{Channels: []Channel{ch}, Store: ms, Candidates: candidates(ms, base),
		Log: slog.New(slog.DiscardHandler), DigestWeekday: time.Sunday,
		Now: func() time.Time { return time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC) }})
	if err := svc.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	base[0].Item.Priority = policy.P3
	if err := svc.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	svc.RunDigests(t.Context())
	if ch.count() != 1 || ch.sent[0].Kind != KindDigestWeekly || ms.notified["downgraded"] != "P3" {
		t.Fatalf("downgraded finding lost: queued=%v notified=%v sent=%v", ms.queued, ms.notified, ch.sent)
	}
	// A previously delivered higher-priority finding must stay quiet.
	base[0].Item.Priority = policy.P2
	ms.notified["downgraded"] = "P1"
	if err := svc.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(ms.queued) != 0 {
		t.Fatalf("already notified finding queued: %v", ms.queued)
	}
}

func TestFirstWeeklyDigestFailureRetriesAfterMidnight(t *testing.T) {
	ms := newMemStore()
	ch := &fakeChannel{fails: 1}
	now := time.Date(2026, 11, 15, 23, 59, 0, 0, time.UTC)
	ms.states["notifydaily"] = store.SourceState{Source: "notify", Key: "daily", LastSuccess: now.Add(-24 * time.Hour)}
	base := []Candidate{{Item: item("weekly", policy.P3), State: store.StateOpen}}
	svc := NewService(Config{Channels: []Channel{ch}, Store: ms, Candidates: candidates(ms, base),
		Log: slog.New(slog.DiscardHandler), Location: time.UTC, DigestHour: 8, DigestWeekday: time.Sunday,
		Now: func() time.Time { return now }})
	if err := svc.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	svc.digestsDue(t.Context())
	now = now.Add(time.Minute)
	svc.digestsDue(t.Context())
	if ch.count() != 1 || ch.sent[0].Kind != KindDigestWeekly || ms.notified["weekly"] != "P3" {
		t.Fatalf("first weekly failure lost across weekday change: sent=%v notified=%v", ch.sent, ms.notified)
	}
}

// A digest that reached a channel is not repeated by the minute when the
// database cannot record it: the recipient would get it until the write
// works again.
func TestDeliveredDigestIsNotRepeatedWhenRecordingFails(t *testing.T) {
	ms := newMemStore()
	ms.markErr = errors.New("database is read-only")
	ch := &fakeChannel{}
	now := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	ms.states["notifydaily"] = store.SourceState{Source: "notify", Key: "daily", LastSuccess: now.Add(-24 * time.Hour)}
	base := []Candidate{{Item: item("daily", policy.P2), State: store.StateOpen}}
	svc := NewService(Config{Channels: []Channel{ch}, Store: ms, Log: slog.New(slog.DiscardHandler),
		DigestHour: 8, DigestWeekday: time.Sunday, Location: time.UTC, Now: func() time.Time { return now },
		Candidates: candidates(ms, base)})
	ms.queued["daily"] = "P2"
	svc.digestsDue(t.Context())
	now = now.Add(time.Minute)
	svc.digestsDue(t.Context())
	if ch.count() != 1 {
		t.Fatalf("digest sent %d times, want once", ch.count())
	}
	if ms.queued["daily"] != "P2" {
		t.Error("the unrecorded finding left the queue; it must stay for the next digest")
	}
}
