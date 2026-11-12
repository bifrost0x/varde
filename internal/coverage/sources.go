// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/bifrost0x/varde/internal/store"
)

// sourceStale is how long an advisory source may go without a successful
// refresh, while it keeps being tried, before it becomes a notice: a day of
// rate limits passes, two days of failures mean the data is getting old.
const sourceStale = 48 * time.Hour

// SourceStore is what the source health notices need.
type SourceStore interface {
	SourceStates(ctx context.Context) ([]store.SourceState, error)
	SyncNotices(ctx context.Context, kind string, current []store.Notice, now time.Time) error
}

// RefreshSources syncs the notices for advisory sources that stopped
// refreshing.
func RefreshSources(ctx context.Context, st SourceStore, now time.Time) error {
	states, err := st.SourceStates(ctx)
	if err != nil {
		return err
	}
	return st.SyncNotices(ctx, store.NoticeSourceStale, SourceNotices(states, now), now)
}

// SourceNotices lists the advisory sources whose newest successful refresh
// of any key is older than sourceStale although they were tried since. One
// broken repository of many does not count; a source that is down, refused
// by an egress allowlist or rate limited for days does.
func SourceNotices(states []store.SourceState, now time.Time) []store.Notice {
	type agg struct {
		success, attempt time.Time
		lastErr          string
	}
	by := map[string]*agg{}
	for _, s := range states {
		a := by[s.Source]
		if a == nil {
			a = &agg{}
			by[s.Source] = a
		}
		if s.LastSuccess.After(a.success) {
			a.success = s.LastSuccess
		}
		if s.LastAttempt.After(a.attempt) {
			a.attempt = s.LastAttempt
			if s.LastError != "" {
				a.lastErr = s.LastError
			}
		}
	}
	names := make([]string, 0, len(by))
	for n := range by {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []store.Notice
	for _, n := range names {
		a := by[n]
		if a.attempt.IsZero() || !a.attempt.After(a.success) || now.Sub(a.success) < sourceStale || a.lastErr == "" {
			continue
		}
		last := "never"
		if !a.success.IsZero() {
			last = a.success.UTC().Format("2006-01-02 15:04 MST")
		}
		out = append(out, store.Notice{
			Key:     store.NoticeSourceStale + ":" + n,
			Subject: n,
			Title:   fmt.Sprintf("Advisory source %s is not updating", n),
			Detail: fmt.Sprintf("Last successful refresh: %s. Last error: %s. New advisories from it are not seen until it works again.",
				last, truncateText(a.lastErr, 300)),
		})
	}
	return out
}
