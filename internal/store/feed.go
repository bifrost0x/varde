// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// FeedSource is the advisory source name of records from the central feed.
const FeedSource = "feed"

// FeedState describes the last applied feed manifest.
type FeedState struct {
	// Channel names where the manifest came from (the data package, the
	// uplink, a static feed); each channel has its own rollback floor.
	Channel        string
	Sequence       int64
	ManifestSHA256 string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	VerifiedAt     time.Time // last successful verification, also of an unchanged manifest
	AppliedAt      time.Time
}

// FeedData is the content of one verified feed snapshot.
type FeedData struct {
	State      FeedState
	Advisories []AdvisoryRecord // AppID set on every record
	KEV        []KEVEntry
	EPSS       []EPSSEntry
}

// FeedFloor is the newest manifest ever applied from one channel.
type FeedFloor struct {
	Sequence       int64
	ManifestSHA256 string
}

// ErrFeedRollback reports an attempt to apply an older feed.
var ErrFeedRollback = errors.New("feed sequence is older than the applied one")

// ApplyFeed replaces all feed advisories, KEV and EPSS and records the new
// feed state in one transaction. A lower sequence than the newest one ever
// applied from the same channel is refused, so neither a crash nor a race
// can roll data back.
func (s *Store) ApplyFeed(ctx context.Context, d FeedData, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if d.State.Channel == "" {
			return errors.New("apply feed: no channel")
		}
		var cur int64
		err := tx.QueryRowContext(ctx, `SELECT sequence FROM feed_floor WHERE channel = ?`, d.State.Channel).Scan(&cur)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return fmt.Errorf("read feed floor: %w", err)
		case d.State.Sequence < cur:
			return fmt.Errorf("%w: %d < %d", ErrFeedRollback, d.State.Sequence, cur)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feed_floor (channel, sequence, manifest_sha256) VALUES (?, ?, ?)
			ON CONFLICT (channel) DO UPDATE SET sequence = excluded.sequence, manifest_sha256 = excluded.manifest_sha256`,
			d.State.Channel, d.State.Sequence, d.State.ManifestSHA256); err != nil {
			return fmt.Errorf("write feed floor: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM advisories WHERE source = ?`, FeedSource); err != nil {
			return fmt.Errorf("clear feed advisories: %w", err)
		}
		if err := insertAdvisories(ctx, tx, FeedSource, d.Advisories, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
			return fmt.Errorf("clear kev: %w", err)
		}
		for _, e := range d.KEV {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO kev (cve_id, date_added, ransomware) VALUES (?, ?, ?)`,
				e.CVE, e.DateAdded, e.Ransomware); err != nil {
				return fmt.Errorf("insert kev %s: %w", e.CVE, err)
			}
		}
		// EPSS is not cleared: a feed may carry scores for its own CVEs
		// only, and the scores the EPSS source fetched for other CVEs
		// (distribution packages, NVD, apps asked about directly) have to
		// survive it. A score of a CVE nothing names any more is unused.
		for _, e := range d.EPSS {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO epss (cve_id, score, percentile, date) VALUES (?, ?, ?, ?)`,
				e.CVE, e.Score, e.Percentile, e.Date); err != nil {
				return fmt.Errorf("insert epss %s: %w", e.CVE, err)
			}
		}
		st := d.State
		st.AppliedAt = now
		return putFeedState(ctx, tx, st)
	})
}

func putFeedState(ctx context.Context, tx *sql.Tx, st FeedState) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO feed_state (id, channel, sequence, manifest_sha256, created_at, expires_at, verified_at, applied_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET channel = excluded.channel, sequence = excluded.sequence, manifest_sha256 = excluded.manifest_sha256,
			created_at = excluded.created_at, expires_at = excluded.expires_at, verified_at = excluded.verified_at,
			applied_at = excluded.applied_at`,
		st.Channel, st.Sequence, st.ManifestSHA256, millis(st.CreatedAt), millis(st.ExpiresAt), millis(st.VerifiedAt), millis(st.AppliedAt))
	if err != nil {
		return fmt.Errorf("write feed state: %w", err)
	}
	return nil
}

// FeedState returns the applied feed state, or ErrNotFound before the first
// feed was applied.
func (s *Store) FeedState(ctx context.Context) (FeedState, error) {
	var st FeedState
	var cr, ex, ver, ap int64
	err := s.db.QueryRowContext(ctx, `SELECT channel, sequence, manifest_sha256, created_at, expires_at, verified_at, applied_at
		FROM feed_state WHERE id = 1`).Scan(&st.Channel, &st.Sequence, &st.ManifestSHA256, &cr, &ex, &ver, &ap)
	if errors.Is(err, sql.ErrNoRows) {
		return FeedState{}, ErrNotFound
	}
	if err != nil {
		return FeedState{}, fmt.Errorf("read feed state: %w", err)
	}
	st.CreatedAt, st.ExpiresAt, st.VerifiedAt, st.AppliedAt = fromMillis(cr), fromMillis(ex), fromMillis(ver), fromMillis(ap)
	return st, nil
}

// FeedFloor returns the newest manifest ever applied from channel; the zero
// value when none was.
func (s *Store) FeedFloor(ctx context.Context, channel string) (FeedFloor, error) {
	var f FeedFloor
	err := s.db.QueryRowContext(ctx, `SELECT sequence, manifest_sha256 FROM feed_floor WHERE channel = ?`, channel).Scan(&f.Sequence, &f.ManifestSHA256)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return FeedFloor{}, fmt.Errorf("read feed floor: %w", err)
	}
	return f, nil
}

// TouchFeedVerified records that the applied manifest was verified again
// (an unchanged manifest; protects against a frozen mirror only while its
// expiry holds).
func (s *Store) TouchFeedVerified(ctx context.Context, sequence int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE feed_state SET verified_at = ? WHERE id = 1 AND sequence = ?`, millis(now), sequence)
	if err != nil {
		return fmt.Errorf("touch feed state: %w", err)
	}
	return nil
}

// ClearFeed removes the advisories that came from the feed, for leaving
// feed mode. The feed state stays: its sequence keeps protecting against a
// rollback when the feed is used again. KEV and EPSS stay too; the direct
// sources replace them on their next run.
func (s *Store) ClearFeed(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM advisories WHERE source = ?`, FeedSource); err != nil {
		return fmt.Errorf("clear feed advisories: %w", err)
	}
	return nil
}
