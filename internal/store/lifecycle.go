// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Finding states.
const (
	StateOpen         = "open"
	StateAcknowledged = "acknowledged"
	StateSnoozed      = "snoozed"
	StateSuppressed   = "suppressed"
	StateResolved     = "resolved"
)

// ErrInvalidState is returned for transitions that are not allowed, e.g.
// acknowledging a resolved finding.
var ErrInvalidState = errors.New("invalid state transition")

// Assessment is the exposure and priority computed for a finding.
type Assessment struct {
	ID               string
	Priority         string
	Reason           string
	Exposure         string
	ExposureEvidence []string
	// PathClass and PathReason relate the finding to the attack paths.
	PathClass, PathReason string
}

// SetAssessments stores priorities and exposure of findings.
func (s *Store) SetAssessments(ctx context.Context, as []Assessment) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `UPDATE findings SET priority = ?, priority_reason = ?, exposure = ?, exposure_evidence_json = ?, path_class = ?, path_reason = ? WHERE id = ?`)
		if err != nil {
			return fmt.Errorf("prepare assessment update: %w", err)
		}
		defer func() { _ = stmt.Close() }()
		// A finding is rated after it is opened: its opening carries the
		// first rating, so the history keeps it after the finding is purged.
		opening, err := tx.PrepareContext(ctx, `UPDATE finding_events SET priority = ? WHERE finding_id = ? AND priority = '' AND kind IN ('opened', 'reopened')`)
		if err != nil {
			return fmt.Errorf("prepare history rating: %w", err)
		}
		defer func() { _ = opening.Close() }()
		for _, a := range as {
			if a.Priority != "" {
				if _, err := opening.ExecContext(ctx, a.Priority, a.ID); err != nil {
					return fmt.Errorf("rate history of %s: %w", a.ID, err)
				}
			}
			ev, err := json.Marshal(nonNil(a.ExposureEvidence))
			if err != nil {
				return fmt.Errorf("encode exposure evidence: %w", err)
			}
			if _, err := stmt.ExecContext(ctx, a.Priority, a.Reason, a.Exposure, string(ev), truncate(a.PathClass, 32), truncate(a.PathReason, 300), a.ID); err != nil {
				return fmt.Errorf("update assessment %s: %w", a.ID, err)
			}
		}
		return nil
	})
}

// Acknowledge marks an open or snoozed finding as acknowledged.
func (s *Store) Acknowledge(ctx context.Context, id string, now time.Time) error {
	return s.transition(ctx, id, []string{StateOpen, StateSnoozed},
		`UPDATE findings SET state = 'acknowledged', acknowledged_at = ?, snoozed_until = NULL, last_changed = ? WHERE id = ?`,
		millis(now), millis(now), id)
}

// Snooze hides a finding from notifications until the given time.
func (s *Store) Snooze(ctx context.Context, id string, until, now time.Time) error {
	if !until.After(now) {
		return fmt.Errorf("%w: snooze end must be in the future", ErrInvalidState)
	}
	return s.transition(ctx, id, []string{StateOpen, StateAcknowledged, StateSnoozed},
		`UPDATE findings SET state = 'snoozed', snoozed_until = ?, last_changed = ? WHERE id = ?`,
		millis(until), millis(now), id)
}

// Reopen returns an acknowledged or snoozed finding to open.
func (s *Store) Reopen(ctx context.Context, id string, now time.Time) error {
	return s.transition(ctx, id, []string{StateAcknowledged, StateSnoozed},
		`UPDATE findings SET state = 'open', snoozed_until = NULL, acknowledged_at = NULL, last_changed = ? WHERE id = ?`,
		millis(now), id)
}

func (s *Store) transition(ctx context.Context, id string, from []string, update string, args ...any) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var state string
		err := tx.QueryRowContext(ctx, `SELECT state FROM findings WHERE id = ?`, id).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read finding state: %w", err)
		}
		allowed := false
		for _, f := range from {
			allowed = allowed || f == state
		}
		if !allowed {
			return fmt.Errorf("%w: finding is %s", ErrInvalidState, state)
		}
		if _, err := tx.ExecContext(ctx, update, args...); err != nil {
			return fmt.Errorf("update finding %s: %w", id, err)
		}
		return nil
	})
}

// ExpireSnoozes reopens findings whose snooze ended.
func (s *Store) ExpireSnoozes(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE findings SET state = 'open', snoozed_until = NULL, last_changed = ?
		WHERE state = 'snoozed' AND snoozed_until <= ?`, millis(now), millis(now))
	if err != nil {
		return 0, fmt.Errorf("expire snoozes: %w", err)
	}
	return res.RowsAffected()
}

// Suppression hides an advisory for one app or one workload.
type Suppression struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	WorkloadID string     `json:"workload_id,omitempty"`
	AdvisoryID string     `json:"advisory_id"`
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// AddSuppression stores sup.
func (s *Store) AddSuppression(ctx context.Context, sup Suppression) error {
	var expires any
	if sup.ExpiresAt != nil {
		expires = millis(*sup.ExpiresAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO suppressions (id, app_id, workload_id, advisory_id, reason, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, sup.ID, sup.AppID, sup.WorkloadID, sup.AdvisoryID, sup.Reason, sup.CreatedBy, millis(sup.CreatedAt), expires)
	if err != nil {
		return fmt.Errorf("add suppression: %w", err)
	}
	return nil
}

// DeleteSuppression removes a suppression; findings reopen on the next
// ApplySuppressions.
func (s *Store) DeleteSuppression(ctx context.Context, id string) (Suppression, error) {
	sup, err := s.suppression(ctx, id)
	if err != nil {
		return sup, err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM suppressions WHERE id = ?`, id); err != nil {
		return sup, fmt.Errorf("delete suppression: %w", err)
	}
	return sup, nil
}

func (s *Store) suppression(ctx context.Context, id string) (Suppression, error) {
	var sup Suppression
	var created int64
	var expires sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, workload_id, advisory_id, reason, created_by, created_at, expires_at
		FROM suppressions WHERE id = ?`, id).Scan(&sup.ID, &sup.AppID, &sup.WorkloadID, &sup.AdvisoryID, &sup.Reason, &sup.CreatedBy, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return sup, ErrNotFound
	}
	if err != nil {
		return sup, fmt.Errorf("read suppression: %w", err)
	}
	sup.CreatedAt, sup.ExpiresAt = fromMillis(created), optPtr(expires)
	return sup, nil
}

// Suppressions lists all suppressions, including expired ones.
func (s *Store) Suppressions(ctx context.Context) ([]Suppression, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, app_id, workload_id, advisory_id, reason, created_by, created_at, expires_at
		FROM suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("query suppressions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Suppression{}
	for rows.Next() {
		var sup Suppression
		var created int64
		var expires sql.NullInt64
		if err := rows.Scan(&sup.ID, &sup.AppID, &sup.WorkloadID, &sup.AdvisoryID, &sup.Reason, &sup.CreatedBy, &created, &expires); err != nil {
			return nil, fmt.Errorf("scan suppression: %w", err)
		}
		sup.CreatedAt, sup.ExpiresAt = fromMillis(created), optPtr(expires)
		out = append(out, sup)
	}
	return out, rows.Err()
}

// ApplySuppressions sets active suppressions on matching findings and
// releases findings whose suppression expired or was deleted.
func (s *Store) ApplySuppressions(ctx context.Context, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET state = 'open', suppression_id = '', last_changed = ?
			WHERE state = 'suppressed' AND NOT EXISTS (
				SELECT 1 FROM suppressions s WHERE s.id = findings.suppression_id
				AND (s.expires_at IS NULL OR s.expires_at > ?))`, millis(now), millis(now)); err != nil {
			return fmt.Errorf("release suppressions: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET state = 'suppressed', last_changed = ?,
				suppression_id = (
					SELECT s.id FROM suppressions s
					WHERE s.advisory_id = findings.advisory_id AND s.app_id = findings.app_id
					AND (s.workload_id = '' OR s.workload_id = findings.workload_id)
					AND (s.expires_at IS NULL OR s.expires_at > ?)
					ORDER BY s.created_at LIMIT 1)
			WHERE state IN ('open', 'acknowledged', 'snoozed') AND EXISTS (
				SELECT 1 FROM suppressions s
				WHERE s.advisory_id = findings.advisory_id AND s.app_id = findings.app_id
				AND (s.workload_id = '' OR s.workload_id = findings.workload_id)
				AND (s.expires_at IS NULL OR s.expires_at > ?))`, millis(now), millis(now), millis(now)); err != nil {
			return fmt.Errorf("apply suppressions: %w", err)
		}
		return nil
	})
}

// MarkNotified records a successful notification at priority.
func (s *Store) MarkNotified(ctx context.Context, ids []string, priority string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET notified_at = ?, last_notified_priority = ?, digest_pending = ''
				WHERE id = ?`, millis(now), priority, id); err != nil {
				return fmt.Errorf("mark notified %s: %w", id, err)
			}
		}
		return nil
	})
}

// QueueDigest marks findings for the next digest of the given priority.
func (s *Store) QueueDigest(ctx context.Context, ids []string, priority string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET digest_pending = ? WHERE id = ?`, priority, id); err != nil {
				return fmt.Errorf("queue digest %s: %w", id, err)
			}
		}
		return nil
	})
}

// NotificationEntry is one row of the notification log.
type NotificationEntry struct {
	Channel    string    `json:"channel"`
	Kind       string    `json:"kind"`
	FindingIDs []string  `json:"finding_ids,omitempty"`
	SentAt     time.Time `json:"sent_at"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
}

// LogNotification appends to the notification log.
func (s *Store) LogNotification(ctx context.Context, e NotificationEntry) error {
	ids, err := json.Marshal(nonNil(e.FindingIDs))
	if err != nil {
		return fmt.Errorf("encode finding ids: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO notification_log (channel, kind, finding_ids_json, sent_at, status, error) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Channel, e.Kind, string(ids), millis(e.SentAt), e.Status, truncate(e.Error, 1024)); err != nil {
		return fmt.Errorf("log notification: %w", err)
	}
	return nil
}

// Notifications returns the most recent log entries.
func (s *Store) Notifications(ctx context.Context, limit int) ([]NotificationEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT channel, kind, finding_ids_json, sent_at, status, error FROM notification_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query notifications: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []NotificationEntry{}
	for rows.Next() {
		var e NotificationEntry
		var ids string
		var sent int64
		if err := rows.Scan(&e.Channel, &e.Kind, &ids, &sent, &e.Status, &e.Error); err != nil {
			return nil, fmt.Errorf("scan notification: %w", err)
		}
		if err := json.Unmarshal([]byte(ids), &e.FindingIDs); err != nil {
			return nil, fmt.Errorf("decode finding ids: %w", err)
		}
		e.SentAt = fromMillis(sent)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeLogs applies retention: notification log 30 days, resolved findings
// and notices 90 days, the audit log a year, image records of images not
// read for 30 days.
func (s *Store) PurgeLogs(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE at < ?`, millis(now.Add(-365*24*time.Hour))); err != nil {
		return fmt.Errorf("purge audit log: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM notices WHERE resolved_at IS NOT NULL AND resolved_at < ?`, millis(now.Add(-90*24*time.Hour))); err != nil {
		return fmt.Errorf("purge resolved notices: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM notification_log WHERE sent_at < ?`, millis(now.Add(-30*24*time.Hour))); err != nil {
		return fmt.Errorf("purge notification log: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE state = 'resolved' AND resolved_at < ?`, millis(now.Add(-90*24*time.Hour))); err != nil {
		return fmt.Errorf("purge resolved findings: %w", err)
	}
	// The history outlives the findings it describes, for two years.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM finding_events WHERE at < ?`, millis(now.Add(-730*24*time.Hour))); err != nil {
		return fmt.Errorf("purge finding history: %w", err)
	}
	// Images in use are read again every week; older rows belong to images
	// no container runs any more.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM image_package_reads WHERE read_at < ?`, millis(now.Add(-30*24*time.Hour))); err != nil {
		return fmt.Errorf("purge image packages: %w", err)
	}
	return nil
}

// AuditEntry is one security-relevant action.
type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Audit appends to the audit log.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		millis(e.At), truncate(e.Actor, 128), truncate(e.Action, 64), truncate(e.Target, 256), truncate(e.Detail, 1024)); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// AuditLog returns the most recent audit entries.
func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []AuditEntry{}
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
