// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory/sources"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

// SourceStore is what the feed source records for the UI.
type SourceStore interface {
	SourceState(ctx context.Context, source, key string) (store.SourceState, error)
	PutSourceState(ctx context.Context, st store.SourceState) error
	FeedState(ctx context.Context) (store.FeedState, error)
	SyncNotices(ctx context.Context, kind string, current []store.Notice, now time.Time) error
	DeleteSourceStates(ctx context.Context, source string) error
}

// Source runs the feed client as an advisory source of the refresher.
type Source struct {
	Client *Client
	Store  SourceStore
	// StaleAfter raises a notice when no manifest verified for this long
	// (default 72 h).
	StaleAfter time.Duration
	// MinInterval, when set, returns the shortest time between two
	// scheduled checks; a Refresh that comes earlier does not contact the
	// mirror. The data package is built once a day, so asking more often
	// only adds traffic. A failed check is repeated with the next run.
	// Check ignores it.
	MinInterval func() time.Duration
}

// Name implements sources.Source.
func (s *Source) Name() string { return "feed" }

// Refresh updates the feed; the app list does not matter, the feed covers
// its whole catalog.
func (s *Source) Refresh(ctx context.Context, _ []*catalog.App) (sources.Result, error) {
	if s.MinInterval != nil {
		if d := s.MinInterval(); d > 0 {
			st, err := s.Store.SourceState(ctx, "feed", "manifest")
			if err == nil && st.LastError == "" && !st.LastSuccess.IsZero() && s.Client.now().Sub(st.LastSuccess) < d {
				// Not due; the age of what is installed is still judged.
				return sources.Result{}, s.syncStale(ctx, s.Client.now())
			}
		}
	}
	res, err := s.Check(ctx)
	if errors.Is(err, ErrNotInUse) {
		// Switched off between choosing the sources and running them.
		return sources.Result{}, nil
	}
	out := sources.Result{Requests: 1}
	switch {
	case res.Applied:
		out.Updated = 1
	case res.Unchanged:
		out.NotModified = 1
	}
	return out, err
}

// Check updates the feed now, whatever MinInterval says, and records the
// attempt and the stale notice. ErrNotInUse is returned unrecorded.
func (s *Source) Check(ctx context.Context) (Result, error) {
	now := s.Client.now()
	res, err := s.Client.Update(ctx)
	if errors.Is(err, ErrNotInUse) {
		return Result{}, err
	}
	if err != nil && ctx.Err() != nil {
		// The requester gave up or the server is stopping: that says
		// nothing about the mirror and is not a failed check.
		return Result{}, err
	}
	st, _ := s.Store.SourceState(ctx, "feed", "manifest")
	st.Source, st.Key, st.LastAttempt = "feed", "manifest", now
	if err != nil {
		st.LastError = truncateErr(err)
		if errors.Is(err, ErrTooOld) && !strings.Contains(st.LastError, ErrTooOld.Error()) {
			// The pages read this reason from the record; it must not
			// fall to the cut.
			st.LastError = ErrTooOld.Error() + ": " + st.LastError
		}
	} else {
		st.LastError, st.LastSuccess = "", now
	}
	if perr := s.Store.PutSourceState(ctx, st); perr != nil {
		err = errors.Join(err, perr)
	}
	if nerr := s.syncStale(ctx, now); nerr != nil {
		err = errors.Join(err, nerr)
	}
	return res, err
}

// Leave deactivates the feed (see Client.Deactivate), withdraws its stale
// notice and forgets its refresh state: both only apply while the feed is
// in use, and a last failed attempt would otherwise be reported as a
// source that stopped updating. Leave can be repeated.
func (s *Source) Leave(ctx context.Context, base *catalog.Catalog) error {
	return errors.Join(
		s.Client.Deactivate(ctx, base),
		s.Store.SyncNotices(ctx, store.NoticeFeedStale, nil, s.Client.now()),
		s.Store.DeleteSourceStates(ctx, s.Name()),
	)
}

// syncStale raises a notice while the newest verified manifest is older
// than StaleAfter or expired: then Varde may be missing new advisories.
func (s *Source) syncStale(ctx context.Context, now time.Time) error {
	after := s.StaleAfter
	if after <= 0 {
		after = 72 * time.Hour
	}
	var notices []store.Notice
	fs, err := s.Store.FeedState(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		notices = append(notices, store.Notice{Key: store.NoticeFeedStale, Subject: "feed", Title: "No advisory feed installed yet",
			Detail: "Varde has not verified a feed manifest yet, so it knows no advisories. Check the feed URL and Settings › Advisory data."})
	case err != nil:
		return err
	case !now.Before(fs.ExpiresAt):
		notices = append(notices, store.Notice{Key: store.NoticeFeedStale, Subject: "feed", Title: "Advisory feed expired",
			Detail: fmt.Sprintf("The installed feed (sequence %d) expired %s. New advisories are not known until a fresh feed verifies.", fs.Sequence, fs.ExpiresAt.Format("2006-01-02 15:04 MST"))})
	case now.Sub(fs.VerifiedAt) > after:
		notices = append(notices, store.Notice{Key: store.NoticeFeedStale, Subject: "feed", Title: "Advisory feed not updated",
			Detail: fmt.Sprintf("No feed manifest verified since %s.", fs.VerifiedAt.Format("2006-01-02 15:04 MST"))})
	}
	return s.Store.SyncNotices(ctx, store.NoticeFeedStale, notices, now)
}

func truncateErr(err error) string {
	s := err.Error()
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}
