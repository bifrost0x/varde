// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"math"
	"time"
)

// FindingEvent is one entry in the history of a finding: it was opened,
// reopened or resolved, and for a resolution why.
type FindingEvent struct {
	ID           int64     `json:"id"`
	FindingID    string    `json:"finding_id"`
	At           time.Time `json:"at"`
	Kind         string    `json:"kind"`
	Cause        string    `json:"cause,omitempty"`
	HostID       string    `json:"host_id,omitempty"`
	HostName     string    `json:"host_name,omitempty"`
	WorkloadID   string    `json:"workload_id"`
	WorkloadName string    `json:"workload_name,omitempty"`
	ImageRef     string    `json:"image_ref,omitempty"`
	AppID        string    `json:"app_id"`
	AdvisoryID   string    `json:"advisory_id"`
	Priority     string    `json:"priority,omitempty"`
	FromVersion  string    `json:"from_version,omitempty"`
	ToVersion    string    `json:"to_version,omitempty"`
	FixedIn      string    `json:"fixed_in,omitempty"`
	// OpenedAt is, for a resolution, when the finding was last opened:
	// how long it was open.
	OpenedAt *time.Time `json:"opened_at,omitempty"`
}

// HistoryFilter narrows FindingEvents. Zero fields do not filter; From is
// inclusive, To exclusive.
type HistoryFilter struct {
	From, To   time.Time
	HostID     string
	WorkloadID string
	FindingID  string
	Kind       string
	// Limit bounds the result (default and maximum 5000).
	Limit int
}

const maxHistory = 5000

// FindingEvents returns history entries, newest first, at most f.Limit
// (default and maximum 5000).
func (s *Store) FindingEvents(ctx context.Context, f HistoryFilter) ([]FindingEvent, error) {
	limit := f.Limit
	if limit <= 0 || limit > maxHistory {
		limit = maxHistory
	}
	return s.findingEventsPage(ctx, f, math.MaxInt64, math.MaxInt64, limit)
}

// EachFindingEvent calls fn for every history entry the filter matches,
// newest first, without a limit: it reads pages of 5000, so an export of
// a long period neither stops early nor holds the database while the
// caller writes. Limit is ignored.
func (s *Store) EachFindingEvent(ctx context.Context, f HistoryFilter, fn func(FindingEvent) error) error {
	at, id := int64(math.MaxInt64), int64(math.MaxInt64)
	for {
		page, err := s.findingEventsPage(ctx, f, at, id, maxHistory)
		if err != nil {
			return err
		}
		for _, e := range page {
			if err := fn(e); err != nil {
				return err
			}
		}
		if len(page) < maxHistory {
			return nil
		}
		last := page[len(page)-1]
		at, id = last.At.UnixMilli(), last.ID
	}
}

// findingEventsPage returns up to limit entries older than (beforeAt,
// beforeID) in the order (at, id) descending.
func (s *Store) findingEventsPage(ctx context.Context, f HistoryFilter, beforeAt, beforeID int64, limit int) ([]FindingEvent, error) {
	from, to := int64(0), int64(math.MaxInt64)
	if !f.From.IsZero() {
		from = millis(f.From)
	}
	if !f.To.IsZero() {
		to = millis(f.To)
	}
	// One fixed statement: an empty filter value matches everything.
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.finding_id, e.at, e.kind, e.cause, e.host_id, e.host_name, e.workload_id, e.workload_name, e.image_ref,
			e.app_id, e.advisory_id, e.priority, e.from_version, e.to_version, e.fixed_in,
			CASE WHEN e.kind = 'resolved' THEN (SELECT MAX(o.at) FROM finding_events o
				WHERE o.finding_id = e.finding_id AND o.kind IN ('opened', 'reopened') AND o.at <= e.at) END
		FROM finding_events e
		WHERE e.at >= ? AND e.at < ?
			AND (? = '' OR e.host_id = ?) AND (? = '' OR e.workload_id = ?)
			AND (? = '' OR e.finding_id = ?) AND (? = '' OR e.kind = ?)
			AND (e.at < ? OR (e.at = ? AND e.id < ?))
		ORDER BY e.at DESC, e.id DESC LIMIT ?`,
		from, to, f.HostID, f.HostID, f.WorkloadID, f.WorkloadID, f.FindingID, f.FindingID, f.Kind, f.Kind, beforeAt, beforeAt, beforeID, limit)
	if err != nil {
		return nil, fmt.Errorf("query finding history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []FindingEvent
	for rows.Next() {
		var e FindingEvent
		var at int64
		var opened *int64
		if err := rows.Scan(&e.ID, &e.FindingID, &at, &e.Kind, &e.Cause, &e.HostID, &e.HostName, &e.WorkloadID, &e.WorkloadName,
			&e.ImageRef, &e.AppID, &e.AdvisoryID, &e.Priority, &e.FromVersion, &e.ToVersion, &e.FixedIn, &opened); err != nil {
			return nil, fmt.Errorf("scan finding history: %w", err)
		}
		e.At = fromMillis(at)
		if opened != nil {
			t := fromMillis(*opened)
			e.OpenedAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditFor returns the audit entries about one target (a finding ID, for
// example), newest first.
func (s *Store) AuditFor(ctx context.Context, target string, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, actor, action, target, detail FROM audit_log WHERE target = ? ORDER BY id DESC LIMIT ?`, target, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		e.At = fromMillis(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
