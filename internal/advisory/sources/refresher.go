// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
)

// Refresher runs all sources on a jittered schedule and on demand (when
// new apps appear), and reports when stored advisory data changed.
type Refresher struct {
	Sources []Source
	// Pick, when set, chooses the sources of each run instead of Sources:
	// the uplink switches between direct mode and the feed at runtime.
	Pick func() []Source
	// Apps returns the catalog apps currently present in the inventory.
	Apps func(ctx context.Context) ([]*catalog.App, error)
	// OnChange is called after a run that changed stored data.
	OnChange func(ctx context.Context)
	Log      *slog.Logger
	// Interval between scheduled runs (default 6 h) and its jitter
	// (default ±30 min) to avoid synchronised load on upstreams.
	Interval time.Duration
	Jitter   time.Duration
	// StartDelay lets the first inventory sync finish (default 10 s).
	StartDelay time.Duration

	trigger chan struct{}
}

// NewRefresher returns a Refresher with defaults applied.
func NewRefresher(r Refresher) *Refresher {
	if r.Interval <= 0 {
		r.Interval = 6 * time.Hour
	}
	if r.Jitter < 0 {
		r.Jitter = 0
	} else if r.Jitter == 0 {
		r.Jitter = 30 * time.Minute
	}
	if r.StartDelay <= 0 {
		r.StartDelay = 10 * time.Second
	}
	r.trigger = make(chan struct{}, 1)
	return &r
}

// Trigger requests a run soon, e.g. after new apps appeared.
func (r *Refresher) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// Run loops until ctx is cancelled.
func (r *Refresher) Run(ctx context.Context) {
	timer := time.NewTimer(r.StartDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.trigger:
		case <-timer.C:
		}
		r.RunOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(r.next())
	}
}

func (r *Refresher) next() time.Duration {
	if r.Jitter <= 0 {
		return r.Interval
	}
	j := time.Duration(rand.Int64N(int64(2*r.Jitter))) - r.Jitter //nolint:gosec // scheduling jitter
	return r.Interval + j
}

// RunOnce refreshes every source once.
func (r *Refresher) RunOnce(ctx context.Context) {
	apps, err := r.Apps(ctx)
	if err != nil {
		r.Log.Error("advisory refresh: listing apps failed", "err", err)
		return
	}
	changed := false
	srcs := r.Sources
	if r.Pick != nil {
		srcs = r.Pick()
	}
	for _, src := range srcs {
		start := time.Now()
		res, err := src.Refresh(ctx, apps)
		if ctx.Err() != nil {
			return
		}
		attrs := []any{"source", src.Name(), "requests", res.Requests, "updated", res.Updated,
			"not_modified", res.NotModified, "skipped", res.Skipped, "duration", time.Since(start).Round(time.Millisecond)}
		switch {
		case errors.Is(err, ErrRateLimited):
			r.Log.Warn("advisory source rate limited; continuing after reset", append(attrs, "err", err)...)
		case err != nil:
			r.Log.Error("advisory source failed", append(attrs, "err", err)...)
		default:
			r.Log.Info("advisory source refreshed", attrs...)
		}
		changed = changed || res.Changed()
	}
	if changed && r.OnChange != nil {
		r.OnChange(ctx)
	}
}

// Toggle wraps a source that the user can switch off at runtime.
type Toggle struct {
	Source
	Enabled func() bool
}

// Refresh implements Source; a disabled source does nothing.
func (t Toggle) Refresh(ctx context.Context, apps []*catalog.App) (Result, error) {
	if !t.Enabled() {
		return Result{}, nil
	}
	return t.Source.Refresh(ctx, apps)
}

// Only wraps a source so that it sees only the apps keep accepts (hybrid
// mode: direct sources cover what the feed does not).
type Only struct {
	Source
	Keep func(*catalog.App) bool
}

// Refresh implements Source.
func (o Only) Refresh(ctx context.Context, apps []*catalog.App) (Result, error) {
	kept := make([]*catalog.App, 0, len(apps))
	for _, a := range apps {
		if o.Keep(a) {
			kept = append(kept, a)
		}
	}
	if len(kept) == 0 {
		return Result{}, nil
	}
	return o.Source.Refresh(ctx, kept)
}
