// SPDX-License-Identifier: Apache-2.0

// Package sources fetches advisory and enrichment data in direct mode:
// GitHub repository advisories, CISA KEV, FIRST EPSS, and opt-in OSV and
// NVD. Every source uses the hardened httpx client, persists its own
// conditional-request and rate-limit state, and only queries data for apps
// that are actually present (ADR 0009, ADR 0017).
package sources

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

// Store is the persistence sources need.
type Store interface {
	ReplaceAdvisories(ctx context.Context, appID, source string, recs []store.AdvisoryRecord, now time.Time) error
	Advisories(ctx context.Context, appID string) ([]store.AdvisoryRecord, error)
	AdvisoryCVEs(ctx context.Context) ([]string, error)
	ReplaceKEV(ctx context.Context, entries []store.KEVEntry) error
	UpsertEPSS(ctx context.Context, entries []store.EPSSEntry) error
	SourceState(ctx context.Context, source, key string) (store.SourceState, error)
	PutSourceState(ctx context.Context, st store.SourceState) error
}

// Source is one upstream advisory or enrichment source.
type Source interface {
	Name() string
	// Refresh updates stored data for the given apps (those present in
	// the inventory). It returns whether anything changed.
	Refresh(ctx context.Context, apps []*catalog.App) (Result, error)
}

// Result summarises a refresh.
type Result struct {
	Requests    int
	NotModified int
	Updated     int // keys (repositories, feeds, CPEs) whose data changed
	Skipped     int // keys not due or deferred by rate limits
}

// Changed reports whether stored data changed.
func (r Result) Changed() bool { return r.Updated > 0 }

// ErrRateLimited reports that a source stopped early because of upstream
// rate limits; the remaining keys are retried after the reset.
var ErrRateLimited = errors.New("rate limited by upstream")

// Deps are shared by all sources.
type Deps struct {
	HTTP  *httpx.Client
	Store Store
	Now   func() time.Time
	// Sleep waits between requests; replaceable in tests.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Deps) sleep(ctx context.Context, dur time.Duration) error {
	if d.Sleep != nil {
		return d.Sleep(ctx, dur)
	}
	if dur <= 0 {
		return nil
	}
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// due reports whether a key may be fetched now.
func due(st store.SourceState, now time.Time) bool {
	return st.NextRun.IsZero() || !now.Before(st.NextRun)
}

// recordFailure stores the error and, for rate limits, the retry time.
func recordFailure(ctx context.Context, s Store, st store.SourceState, now time.Time, err error) error {
	st.LastAttempt = now
	st.LastError = err.Error()
	var se *httpx.StatusError
	if errors.As(err, &se) && se.RateLimited() {
		switch {
		case se.RateLimit.RetryAfter > 0:
			st.NextRun = now.Add(se.RateLimit.RetryAfter)
		case !se.RateLimit.Reset.IsZero():
			st.NextRun = se.RateLimit.Reset
		default:
			st.NextRun = now.Add(time.Hour)
		}
	}
	if perr := s.PutSourceState(ctx, st); perr != nil {
		return errors.Join(err, perr)
	}
	return err
}

func isRateLimited(err error) bool {
	var se *httpx.StatusError
	return errors.As(err, &se) && se.RateLimited()
}

// truncate bounds upstream-controlled text stored and shown in the UI.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Do not cut inside a UTF-8 sequence.
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

func wrap(source, key string, err error) error {
	return fmt.Errorf("%s %s: %w", source, key, err)
}
