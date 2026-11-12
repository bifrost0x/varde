// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Notice kinds.
const (
	NoticeHostStale   = "host-stale"
	NoticePublicRoute = "public-route-unidentified"
	NoticeFeedStale   = "feed-stale"
	// NoticeIntegrationFailing is an integration that has not read
	// successfully for three intervals.
	NoticeIntegrationFailing = "integration-failing"
	// NoticeFirmware is a network device whose controller offers a newer
	// firmware: no advisory feed covers device firmware.
	NoticeFirmware = "firmware-outdated"
	// NoticeSourceStale is an advisory source that keeps failing.
	NoticeSourceStale = "source-stale"
	// NoticeUplink is the uplink that went off by itself: the license
	// expired or can no longer be used.
	NoticeUplink = "uplink-ended"
)

// Notice is a system notice: a blind spot rather than a vulnerability, for
// example a host that stopped reporting. Notices are delivered with the daily
// digest, never as urgent notifications.
type Notice struct {
	Key        string     `json:"key"`
	Kind       string     `json:"kind"`
	Subject    string     `json:"subject"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail,omitempty"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	NotifiedAt *time.Time `json:"notified_at,omitempty"`
}

// SyncNotices makes the active notices of kind equal to current: new ones
// are opened, known ones refreshed, missing ones resolved. A notice that
// reappears after being resolved starts a new episode and is notified again.
func (s *Store) SyncNotices(ctx context.Context, kind string, current []Notice, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		keep := map[string]bool{}
		for _, n := range current {
			keep[n.Key] = true
			_, err := tx.ExecContext(ctx, `INSERT INTO notices (key, kind, subject, title, detail, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (key) DO UPDATE SET
					subject = excluded.subject, title = excluded.title, detail = excluded.detail, last_seen = excluded.last_seen,
					first_seen = CASE WHEN notices.resolved_at IS NULL THEN notices.first_seen ELSE excluded.first_seen END,
					notified_at = CASE WHEN notices.resolved_at IS NULL THEN notices.notified_at ELSE NULL END,
					resolved_at = NULL`,
				n.Key, kind, n.Subject, n.Title, n.Detail, millis(now), millis(now))
			if err != nil {
				return fmt.Errorf("upsert notice %s: %w", n.Key, err)
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT key FROM notices WHERE kind = ? AND resolved_at IS NULL`, kind)
		if err != nil {
			return fmt.Errorf("query notices: %w", err)
		}
		var gone []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan notice: %w", err)
			}
			if !keep[k] {
				gone = append(gone, k)
			}
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate notices: %w", err)
		}
		for _, k := range gone {
			if _, err := tx.ExecContext(ctx, `UPDATE notices SET resolved_at = ? WHERE key = ?`, millis(now), k); err != nil {
				return fmt.Errorf("resolve notice %s: %w", k, err)
			}
		}
		return nil
	})
}

// ActiveNotices returns unresolved notices, oldest first.
func (s *Store) ActiveNotices(ctx context.Context) ([]Notice, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, kind, subject, title, detail, first_seen, last_seen, notified_at
		FROM notices WHERE resolved_at IS NULL ORDER BY first_seen, key`)
	if err != nil {
		return nil, fmt.Errorf("query notices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Notice
	for rows.Next() {
		var n Notice
		var first, last int64
		var notified sql.NullInt64
		if err := rows.Scan(&n.Key, &n.Kind, &n.Subject, &n.Title, &n.Detail, &first, &last, &notified); err != nil {
			return nil, fmt.Errorf("scan notice: %w", err)
		}
		n.FirstSeen, n.LastSeen = fromMillis(first), fromMillis(last)
		if notified.Valid {
			t := fromMillis(notified.Int64)
			n.NotifiedAt = &t
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notices: %w", err)
	}
	return out, nil
}

// MarkNoticesNotified records that the notices were delivered.
func (s *Store) MarkNoticesNotified(ctx context.Context, keys []string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, k := range keys {
			if _, err := tx.ExecContext(ctx, `UPDATE notices SET notified_at = ? WHERE key = ?`, millis(now), k); err != nil {
				return fmt.Errorf("mark notice %s notified: %w", k, err)
			}
		}
		return nil
	})
}
