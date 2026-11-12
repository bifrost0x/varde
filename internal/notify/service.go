// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/store"
)

// Candidate is a finding with the state needed for notification decisions.
type Candidate struct {
	Item          Item
	State         string
	SnoozedUntil  *time.Time
	LastNotified  policy.Priority
	DigestPending policy.Priority
	FirstSeen     time.Time
	// ResolvedAt is set for a resolved finding.
	ResolvedAt *time.Time
}

// Decision is the outcome of Decide.
type Decision struct {
	Immediate []Item
	// Queue maps a digest priority to findings to add to it.
	Queue map[policy.Priority][]string
}

// Decide applies the quietness rules:
//   - only affected findings in state open notify; acknowledged ones only
//     when they escalate to P1; snoozed, suppressed and resolved never;
//   - a finding notifies again only when its priority rises above the
//     priority it was last notified at (no repeats on re-scans);
//   - P1 is sent immediately, P2 and P3 are queued for their digests.
func Decide(cands []Candidate, now time.Time) Decision {
	d := Decision{Queue: map[policy.Priority][]string{}}
	for _, c := range cands {
		p := c.Item.Priority
		if c.Item.MatchState != "affected" || p == policy.None {
			continue
		}
		switch c.State {
		case store.StateOpen:
		case store.StateAcknowledged:
			if p != policy.P1 {
				continue
			}
		case store.StateSnoozed:
			if c.SnoozedUntil != nil && c.SnoozedUntil.After(now) {
				continue
			}
		default:
			continue
		}
		if p.Rank() <= c.LastNotified.Rank() {
			continue
		}
		if p == policy.P1 {
			d.Immediate = append(d.Immediate, c.Item)
			continue
		}
		if p.Rank() > c.DigestPending.Rank() {
			d.Queue[p] = append(d.Queue[p], c.Item.FindingID)
		}
	}
	return d
}

// Store is the persistence the service needs.
type Store interface {
	MarkNotified(ctx context.Context, ids []string, priority string, now time.Time) error
	QueueDigest(ctx context.Context, ids []string, priority string) error
	LogNotification(ctx context.Context, e store.NotificationEntry) error
	SourceState(ctx context.Context, source, key string) (store.SourceState, error)
	PutSourceState(ctx context.Context, st store.SourceState) error
}

// Config configures a Service.
type Config struct {
	Channels []Channel
	Store    Store
	// Candidates returns all non-resolved findings with rendering data.
	Candidates func(ctx context.Context) ([]Candidate, error)
	Log        *slog.Logger
	// DigestHour (0-23, local time) and DigestWeekday schedule digests.
	DigestHour    int
	DigestWeekday time.Weekday
	// Notices, if set, returns system notices not delivered yet; they go into
	// the daily digest. NoticesSent records their delivery.
	Notices     func(ctx context.Context) ([]Notice, error)
	NoticesSent func(ctx context.Context, keys []string) error
	// Schedule, if set, overrides DigestHour and DigestWeekday at runtime.
	Schedule func() (hour int, weekday time.Weekday)
	Location *time.Location
	// RetryDelays between delivery attempts (default 5 s, 30 s, 2 min).
	RetryDelays []time.Duration
	Now         func() time.Time
}

// Service evaluates findings and delivers notifications.
type Service struct {
	cfg  Config
	jobs chan job

	mu       sync.Mutex
	inFlight map[string]bool
}

type job struct {
	msg      Message
	priority policy.Priority // recorded as last notified priority
	done     chan error      // optional
}

// NewService returns a Service with defaults applied.
func NewService(cfg Config) *Service {
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.RetryDelays == nil {
		cfg.RetryDelays = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg, jobs: make(chan job, 32), inFlight: map[string]bool{}}
}

// ChannelNames lists the configured channels.
func (s *Service) ChannelNames() []string {
	names := make([]string, 0, len(s.cfg.Channels))
	for _, c := range s.cfg.Channels {
		names = append(names, c.Name())
	}
	return names
}

// Enabled reports whether any channel is configured.
func (s *Service) Enabled() bool { return len(s.cfg.Channels) > 0 }

// Evaluate decides on notifications after an analysis run: P1 messages are
// handed to the delivery worker, P2/P3 are queued for digests.
func (s *Service) Evaluate(ctx context.Context) error {
	cands, err := s.cfg.Candidates(ctx)
	if err != nil {
		return err
	}
	d := Decide(cands, s.cfg.Now())
	for p, ids := range d.Queue {
		if err := s.cfg.Store.QueueDigest(ctx, ids, string(p)); err != nil {
			return err
		}
	}
	if len(d.Immediate) == 0 {
		return nil
	}
	if !s.Enabled() {
		s.cfg.Log.Warn("urgent finding but no notification channel configured", "findings", len(d.Immediate))
		return nil
	}
	s.mu.Lock()
	var fresh []Item
	for _, it := range d.Immediate {
		if !s.inFlight[it.FindingID] {
			s.inFlight[it.FindingID] = true
			fresh = append(fresh, it)
		}
	}
	s.mu.Unlock()
	if len(fresh) == 0 {
		return nil
	}
	select {
	case s.jobs <- job{msg: Immediate(fresh), priority: policy.P1}:
		return nil
	case <-ctx.Done():
		s.release(fresh)
		return ctx.Err()
	}
}

func (s *Service) release(items []Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range items {
		delete(s.inFlight, it.FindingID)
	}
}

// Test sends a test message to the named channel (or all when empty) and
// waits for the result.
func (s *Service) Test(ctx context.Context, channel string) error {
	var errs []error
	found := false
	for _, ch := range s.cfg.Channels {
		if channel != "" && ch.Name() != channel {
			continue
		}
		found = true
		err := ch.Send(ctx, Test())
		s.log(ctx, ch.Name(), Test(), err)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ch.Name(), err))
		}
	}
	if !found {
		return fmt.Errorf("channel %q is not configured", channel)
	}
	return errors.Join(errs...)
}

// Run delivers queued messages and sends digests on schedule until ctx is
// cancelled. The schedule is checked every minute, so a changed digest
// hour applies at once and a digest missed while Varde was down is sent
// when it is back.
func (s *Service) Run(ctx context.Context) {
	s.digestsDue(ctx)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-s.jobs:
			s.deliver(ctx, j)
		case <-tick.C:
			s.digestsDue(ctx)
		}
	}
}

// digestsDue runs the digests when the last digest hour has passed since
// they last ran. The first run of a new installation only records the
// time: there is nothing missed yet.
func (s *Service) digestsDue(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	st, err := s.cfg.Store.SourceState(ctx, "notify", "daily")
	if err != nil {
		s.cfg.Log.Error("digest: reading state failed", "err", err)
		return
	}
	now := s.cfg.Now()
	slot := s.lastSlot(now)
	switch {
	case st.LastSuccess.IsZero():
	case !st.LastSuccess.Before(slot):
		return
	default:
		s.RunDigests(ctx)
	}
	st.LastSuccess, st.LastAttempt = now, now
	if err := s.cfg.Store.PutSourceState(ctx, st); err != nil {
		s.cfg.Log.Error("digest: writing state failed", "err", err)
	}
}

// lastSlot is the most recent digest hour at or before now, in the
// configured time zone (across a daylight saving change too).
func (s *Service) lastSlot(now time.Time) time.Time {
	hour, _ := s.schedule()
	local := now.In(s.cfg.Location)
	slot := time.Date(local.Year(), local.Month(), local.Day(), hour, 0, 0, 0, s.cfg.Location)
	if slot.After(local) {
		slot = slot.AddDate(0, 0, -1)
	}
	return slot
}

// deliver sends to all channels with retries; success on any channel
// counts, because the user was reached.
func (s *Service) deliver(ctx context.Context, j job) {
	ids := j.msg.FindingIDs()
	defer s.release(j.msg.Items)
	var lastErr error
	for attempt := 0; attempt <= len(s.cfg.RetryDelays); attempt++ {
		if attempt > 0 {
			t := time.NewTimer(s.cfg.RetryDelays[attempt-1])
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		delivered := false
		var errs []error
		for _, ch := range s.cfg.Channels {
			err := ch.Send(ctx, j.msg)
			s.log(ctx, ch.Name(), j.msg, err)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", ch.Name(), err))
				continue
			}
			delivered = true
		}
		if delivered {
			if len(ids) > 0 && j.priority != policy.None {
				if err := s.cfg.Store.MarkNotified(ctx, ids, string(j.priority), s.cfg.Now()); err != nil {
					s.cfg.Log.Error("recording notification failed", "err", err)
				}
			}
			if j.done != nil {
				j.done <- nil
			}
			return
		}
		lastErr = errors.Join(errs...)
		s.cfg.Log.Warn("notification delivery failed", "kind", j.msg.Kind, "attempt", attempt+1, "err", lastErr)
	}
	if j.done != nil {
		j.done <- lastErr
	}
}

func (s *Service) log(ctx context.Context, channel string, m Message, err error) {
	e := store.NotificationEntry{Channel: channel, Kind: m.Kind, FindingIDs: m.FindingIDs(), SentAt: s.cfg.Now(), Status: "sent"}
	if err != nil {
		e.Status, e.Error = "failed", err.Error()
	}
	if lerr := s.cfg.Store.LogNotification(ctx, e); lerr != nil {
		s.cfg.Log.Error("writing notification log failed", "err", lerr)
	}
}

func (s *Service) schedule() (int, time.Weekday) {
	if s.cfg.Schedule != nil {
		return s.cfg.Schedule()
	}
	return s.cfg.DigestHour, s.cfg.DigestWeekday
}

// RunDigests sends the daily digest and, on the configured weekday, the
// weekly one. Empty digests are not sent.
func (s *Service) RunDigests(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	cands, err := s.cfg.Candidates(ctx)
	if err != nil {
		s.cfg.Log.Error("digest: loading findings failed", "err", err)
		return
	}
	now := s.cfg.Now()
	var notices []Notice
	if s.cfg.Notices != nil {
		if notices, err = s.cfg.Notices(ctx); err != nil {
			s.cfg.Log.Error("digest: loading notices failed", "err", err)
			notices = nil
		}
	}
	if _, delivered := s.sendDigest(ctx, KindDigestDaily, pending(cands, policy.P2), nil, notices, nil); delivered && len(notices) > 0 && s.cfg.NoticesSent != nil {
		keys := make([]string, 0, len(notices))
		for _, n := range notices {
			keys = append(keys, n.Key)
		}
		if err := s.cfg.NoticesSent(ctx, keys); err != nil {
			s.cfg.Log.Error("digest: recording notices failed", "err", err)
		}
	}
	_, weekday := s.schedule()
	st, err := s.cfg.Store.SourceState(ctx, "notify", "weekly")
	if err != nil {
		s.cfg.Log.Error("digest: reading state failed", "err", err)
		return
	}
	// The weekly digest is due on its weekday, or later when that day's
	// digest hour passed while Varde was down.
	if s.weeklyDue(now, weekday, st.LastSuccess) {
		attention := needsAttention(cands, st.LastSuccess)
		sent, delivered := s.sendDigest(ctx, KindDigestWeekly, pending(cands, policy.P3), attention, nil, resolvedSince(cands, st.LastSuccess))
		if delivered || !sent {
			st.LastSuccess, st.LastAttempt = now, now
			if err := s.cfg.Store.PutSourceState(ctx, st); err != nil {
				s.cfg.Log.Error("digest: writing state failed", "err", err)
			}
		}
	}
}

// weeklyDue reports whether the weekly digest is due: on its weekday, or
// once its last slot has passed since it last went out.
func (s *Service) weeklyDue(now time.Time, weekday time.Weekday, last time.Time) bool {
	if now.In(s.cfg.Location).Weekday() == weekday {
		return true
	}
	if last.IsZero() {
		return false
	}
	slot := s.lastSlot(now)
	for slot.Weekday() != weekday {
		slot = slot.AddDate(0, 0, -1)
	}
	return last.Before(slot)
}

// sendDigest renders and sends a digest. sent is false for an empty digest;
// delivered reports whether at least one channel accepted it. Only the
// prioritised items are recorded as notified: attention items are
// unverified and stay eligible if they later become affected.
func (s *Service) sendDigest(ctx context.Context, kind string, items, attention []Item, notices []Notice, resolved []Item) (sent, delivered bool) {
	msg, ok := Digest(kind, items, attention, notices, resolved)
	if !ok {
		return false, false
	}
	p := policy.P2
	if kind == KindDigestWeekly {
		p = policy.P3
	}
	var errs []error
	for _, ch := range s.cfg.Channels {
		err := ch.Send(ctx, msg)
		s.log(ctx, ch.Name(), msg, err)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ch.Name(), err))
			continue
		}
		delivered = true
	}
	if !delivered {
		s.cfg.Log.Warn("digest delivery failed; items stay queued", "kind", kind, "err", errors.Join(errs...))
		return true, false
	}
	if ids := (Message{Items: items}).FindingIDs(); len(ids) > 0 {
		if err := s.cfg.Store.MarkNotified(ctx, ids, string(p), s.cfg.Now()); err != nil {
			s.cfg.Log.Error("recording digest failed", "err", err)
		}
	}
	return true, true
}

// pending returns open items queued for the digest of priority p.
func pending(cands []Candidate, p policy.Priority) []Item {
	var out []Item
	for _, c := range cands {
		if c.DigestPending == p && c.Item.Priority == p && c.State == store.StateOpen {
			out = append(out, c.Item)
		}
	}
	return out
}

// resolvedSince returns findings Varde had notified about that were
// resolved since the last weekly digest: the user learns that the update
// worked, once, without a message of its own.
func resolvedSince(cands []Candidate, since time.Time) []Item {
	var out []Item
	for _, c := range cands {
		if c.State == store.StateResolved && c.LastNotified != "" && c.ResolvedAt != nil && c.ResolvedAt.After(since) {
			out = append(out, c.Item)
		}
	}
	return out
}

// needsAttention returns unverified findings of publicly exposed apps first
// seen since the last weekly digest, so each appears once.
func needsAttention(cands []Candidate, since time.Time) []Item {
	var out []Item
	for _, c := range cands {
		if c.Item.MatchState == "unverified" && c.Item.Exposure == "public" && c.State == store.StateOpen && c.FirstSeen.After(since) {
			out = append(out, c.Item)
		}
	}
	return out
}
