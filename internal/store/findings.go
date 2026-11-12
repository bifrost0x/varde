// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// FindingInput is one current match result to persist.
type FindingInput struct {
	WorkloadID string
	AppID      string
	AdvisoryID string
	MatchState string
	FixedIn    string
	Detail     any // serialised as detail_json
}

// Finding is a stored finding.
type Finding struct {
	ID          string          `json:"id"`
	WorkloadID  string          `json:"workload_id"`
	AppID       string          `json:"app_id"`
	AdvisoryID  string          `json:"advisory_id"`
	MatchState  string          `json:"match_state"`
	State       string          `json:"state"`
	Priority    string          `json:"priority,omitempty"`
	Exposure    string          `json:"exposure,omitempty"`
	FixedIn     string          `json:"fixed_in,omitempty"`
	Detail      json.RawMessage `json:"detail"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastChanged time.Time       `json:"last_changed"`
	ResolvedAt  *time.Time      `json:"resolved_at,omitempty"`

	PriorityReason       string     `json:"priority_reason,omitempty"`
	ExposureEvidence     []string   `json:"exposure_evidence,omitempty"`
	AcknowledgedAt       *time.Time `json:"acknowledged_at,omitempty"`
	SnoozedUntil         *time.Time `json:"snoozed_until,omitempty"`
	SuppressionID        string     `json:"suppression_id,omitempty"`
	NotifiedAt           *time.Time `json:"notified_at,omitempty"`
	LastNotifiedPriority string     `json:"last_notified_priority,omitempty"`
	DigestPending        string     `json:"-"`
	// PathClass and PathReason relate the finding to the attack paths
	// (ADR 0034): path-internet, path-lan, amplifier, noise or unclear.
	PathClass  string `json:"path_class,omitempty"`
	PathReason string `json:"path_reason,omitempty"`
}

// FindingChanges summarises a SyncFindings call.
type FindingChanges struct {
	New      []string // finding IDs created or reopened
	Changed  []string // match state or fixed version changed
	Resolved []string
}

// FindingID derives the stable ID of a (workload, advisory) finding.
func FindingID(workloadID, advisoryID string) string {
	h := sha256.Sum256([]byte(workloadID + "\x00" + advisoryID))
	return hex.EncodeToString(h[:12])
}

// ID is the finding's stable ID. An advisory of a language ecosystem often
// names several packages of one app (golang.org/x/net and the standard
// library, two Maven artifacts): each is its own finding with its own
// update, so the package is part of the ID. Every other finding keeps the
// (workload, advisory) ID.
func (f FindingInput) ID() string {
	if perPackage(f.AppID) {
		return FindingID(f.WorkloadID, f.AdvisoryID+"\x00"+f.AppID)
	}
	return FindingID(f.WorkloadID, f.AdvisoryID)
}

// languagePrefixes are the app IDs of packages of language ecosystems.
var languagePrefixes = []string{"os:Go/", "os:npm/", "os:PyPI/", "os:Maven/", "os:RubyGems/", "os:NuGet/", "os:Packagist/", "os:crates.io/"}

func perPackage(appID string) bool {
	for _, p := range languagePrefixes {
		if strings.HasPrefix(appID, p) {
			return true
		}
	}
	return false
}

// SyncFindings makes the set of open findings equal to current: new ones
// are created, existing ones updated, reappearing ones reopened, and open
// findings that no longer match are resolved. User states (acknowledged,
// snoozed, suppressed) of still-matching findings are kept. It records no
// cause for what it resolves; the analysis uses SyncFindingsSeen.
func (s *Store) SyncFindings(ctx context.Context, current []FindingInput, now time.Time) (FindingChanges, error) {
	return s.SyncFindingsSeen(ctx, current, nil, now)
}

// SeenKey keys Seen: the version of an app or package on a workload.
func SeenKey(workloadID, appID string) string { return workloadID + "\x00" + appID }

// Resolution causes recorded in the history.
const (
	CauseUpdated     = "updated"
	CauseRemoved     = "removed"
	CauseUninstalled = "uninstalled"
	CauseAdvisory    = "advisory"
)

// SyncFindingsSeen is SyncFindings with what the analysis saw: seen maps
// SeenKey(workload, app) to the version found, for every app and package
// analysed, whether affected or not. It tells why a finding was resolved
// (an update, the workload or package gone, or the advisory no longer
// applying), which the history records with every opened, reopened and
// resolved finding. When seen is non-nil, findings with insufficient
// inventory evidence to establish a resolution are kept unchanged.
func (s *Store) SyncFindingsSeen(ctx context.Context, current []FindingInput, seen map[string]string, now time.Time) (FindingChanges, error) {
	var ch FindingChanges
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		type row struct {
			state, matchState, fixedIn string
			workloadID, appID, version string
			gone, packageGone          bool
		}
		existing := map[string]row{}
		rows, err := tx.QueryContext(ctx, `
			SELECT f.id, f.state, f.match_state, f.fixed_in, f.workload_id, f.app_id,
				COALESCE(json_extract(f.detail_json, '$.evidence.version'), ''), w.id IS NULL OR w.removed_at IS NOT NULL,
				w.kind = 'package' AND w.removed_at IS NOT NULL AND h.id IS NOT NULL
			FROM findings f LEFT JOIN workloads w ON w.id = f.workload_id LEFT JOIN hosts h ON h.id = w.host_id`)
		if err != nil {
			return fmt.Errorf("query findings: %w", err)
		}
		for rows.Next() {
			var id string
			var r row
			if err := rows.Scan(&id, &r.state, &r.matchState, &r.fixedIn, &r.workloadID, &r.appID, &r.version, &r.gone, &r.packageGone); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan finding: %w", err)
			}
			existing[id] = r
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close findings: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate findings: %w", err)
		}

		present := map[string]bool{}
		for _, f := range current {
			id := f.ID()
			if present[id] {
				continue
			}
			present[id] = true
			detail, err := json.Marshal(f.Detail)
			if err != nil {
				return fmt.Errorf("encode finding detail: %w", err)
			}
			prev, ok := existing[id]
			if !ok {
				// Before one finding per module, a Go or npm finding had the
				// (workload, advisory) ID: it keeps its state and history
				// under the new ID instead of being resolved and opened again.
				legacy := FindingID(f.WorkloadID, f.AdvisoryID)
				if old, found := existing[legacy]; found && legacy != id && !present[legacy] && old.workloadID == f.WorkloadID && old.appID == f.AppID {
					if _, err := tx.ExecContext(ctx, `UPDATE findings SET id = ? WHERE id = ?`, id, legacy); err != nil {
						return fmt.Errorf("move finding %s to %s: %w", legacy, id, err)
					}
					if _, err := tx.ExecContext(ctx, `UPDATE finding_events SET finding_id = ? WHERE finding_id = ?`, id, legacy); err != nil {
						return fmt.Errorf("move history of finding %s to %s: %w", legacy, id, err)
					}
					delete(existing, legacy)
					existing[id], prev, ok = old, old, true
				}
			}
			switch {
			case !ok:
				ch.New = append(ch.New, id)
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO findings (id, workload_id, app_id, advisory_id, match_state, fixed_in, detail_json, first_seen, last_changed)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					id, f.WorkloadID, f.AppID, f.AdvisoryID, f.MatchState, f.FixedIn, string(detail), millis(now), millis(now)); err != nil {
					return fmt.Errorf("insert finding: %w", err)
				}
				if err := recordFindingEvent(ctx, tx, id, "opened", "", "", now); err != nil {
					return err
				}
			default:
				state, lastChanged := prev.state, any(nil)
				switch {
				case prev.state == "resolved":
					ch.New = append(ch.New, id)
					state, lastChanged = "open", millis(now)
				case prev.matchState != f.MatchState || prev.fixedIn != f.FixedIn:
					ch.Changed = append(ch.Changed, id)
					lastChanged = millis(now)
				}
				// A reopened finding starts a fresh notification history: the
				// user changed something and the issue came back.
				if _, err := tx.ExecContext(ctx, `
					UPDATE findings SET match_state = ?, fixed_in = ?, detail_json = ?,
						resolved_at = CASE WHEN ? = 'open' AND state = 'resolved' THEN NULL ELSE resolved_at END,
						last_notified_priority = CASE WHEN state = 'resolved' THEN '' ELSE last_notified_priority END,
						notified_at = CASE WHEN state = 'resolved' THEN NULL ELSE notified_at END,
						acknowledged_at = CASE WHEN state = 'resolved' THEN NULL ELSE acknowledged_at END,
						digest_pending = CASE WHEN state = 'resolved' THEN '' ELSE digest_pending END,
						state = ?,
						last_changed = COALESCE(?, last_changed)
					WHERE id = ?`,
					f.MatchState, f.FixedIn, string(detail), state, state, lastChanged, id); err != nil {
					return fmt.Errorf("update finding: %w", err)
				}
				if prev.state == "resolved" {
					if err := recordFindingEvent(ctx, tx, id, "reopened", "", "", now); err != nil {
						return err
					}
				}
			}
		}
		for id, prev := range existing {
			if present[id] || prev.state == "resolved" {
				continue
			}
			cause, to := resolution(prev.gone, prev.packageGone, prev.version, seen, prev.workloadID, prev.appID)
			if seen != nil && cause == "" {
				// Missing evidence is not a fix: a partial or unavailable
				// inventory must keep the finding and its notification state.
				continue
			}
			ch.Resolved = append(ch.Resolved, id)
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET state = 'resolved', resolved_at = ?, last_changed = ?, digest_pending = '' WHERE id = ?`,
				millis(now), millis(now), id); err != nil {
				return fmt.Errorf("resolve finding: %w", err)
			}
			if err := recordFindingEvent(ctx, tx, id, "resolved", cause, to, now); err != nil {
				return err
			}
		}
		return nil
	})
	return ch, err
}

// Markers in the seen versions: the workload's apps were identified, the
// packages of its image were read completely. A package missing from seen
// is gone only where its inventory was read.
const (
	SeenApps  = "\x00apps"
	SeenImage = "\x00image"
)

// resolution tells why a finding stopped matching: its workload is gone, a
// package workload is gone from a host that is still there (uninstalled),
// the version changed (to is the new one), the app or package is gone from
// a workload whose inventory was read, or the same version no longer
// matches the advisory. Otherwise the cause is not known: an image not read
// yet must not count as fixed.
func resolution(gone, packageGone bool, version string, seen map[string]string, workloadID, appID string) (cause, to string) {
	marker := SeenApps
	if strings.HasPrefix(appID, "os:") {
		// A package of an image (a host's own packages are workloads of
		// their own, removed when uninstalled).
		marker = SeenImage
	}
	_, inspected := seen[SeenKey(workloadID, marker)]
	switch now, ok := seen[SeenKey(workloadID, appID)]; {
	case packageGone:
		return CauseUninstalled, ""
	case gone:
		return CauseRemoved, ""
	case seen == nil:
		return "", ""
	case !ok && inspected:
		return CauseUninstalled, ""
	case !ok:
		return "", ""
	case now != version:
		return CauseUpdated, now
	default:
		return CauseAdvisory, ""
	}
}

// recordFindingEvent adds an entry to the history of a finding, copying the
// names it shows from the finding, its workload and host as they are now.
func recordFindingEvent(ctx context.Context, tx *sql.Tx, id, kind, cause, to string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_events (finding_id, at, kind, cause, host_id, host_name, workload_id, workload_name, image_ref,
			app_id, advisory_id, priority, from_version, to_version, fixed_in)
		SELECT f.id, ?, ?, ?, COALESCE(w.host_id, ''), COALESCE(h.name, ''), f.workload_id, COALESCE(w.name, ''),
			COALESCE(w.image_ref, ''), f.app_id, f.advisory_id, f.priority,
			COALESCE(json_extract(f.detail_json, '$.evidence.version'), ''), ?, f.fixed_in
		FROM findings f LEFT JOIN workloads w ON w.id = f.workload_id LEFT JOIN hosts h ON h.id = w.host_id
		WHERE f.id = ?`, millis(now), kind, cause, to, id); err != nil {
		return fmt.Errorf("record %s finding %s: %w", kind, id, err)
	}
	return nil
}

// FindingFilter narrows Findings.
type FindingFilter struct {
	IncludeResolved bool
	WorkloadID      string
}

const findingSelect = `SELECT id, workload_id, app_id, advisory_id, match_state, state, priority, exposure, fixed_in,
	detail_json, first_seen, last_changed, resolved_at, priority_reason, exposure_evidence_json, acknowledged_at,
	snoozed_until, suppression_id, notified_at, last_notified_priority, digest_pending, path_class, path_reason FROM findings`

// Findings returns findings ordered by first seen, newest first.
func (s *Store) Findings(ctx context.Context, f FindingFilter) ([]Finding, error) {
	q := findingSelect + ` WHERE 1 = 1`
	var args []any
	if !f.IncludeResolved {
		q += ` AND state <> 'resolved'`
	}
	if f.WorkloadID != "" {
		q += ` AND workload_id = ?`
		args = append(args, f.WorkloadID)
	}
	q += ` ORDER BY first_seen DESC, id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Finding{}
	for rows.Next() {
		fd, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, fd)
	}
	return out, rows.Err()
}

// GetFinding returns one finding or ErrNotFound.
func (s *Store) GetFinding(ctx context.Context, id string) (Finding, error) {
	fd, err := scanFinding(s.db.QueryRowContext(ctx, findingSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	return fd, err
}

func scanFinding(sc scanner) (Finding, error) {
	var f Finding
	var detail, evidence string
	var first, last int64
	var resolved, acked, snoozed, notified sql.NullInt64
	if err := sc.Scan(&f.ID, &f.WorkloadID, &f.AppID, &f.AdvisoryID, &f.MatchState, &f.State, &f.Priority, &f.Exposure,
		&f.FixedIn, &detail, &first, &last, &resolved, &f.PriorityReason, &evidence, &acked, &snoozed,
		&f.SuppressionID, &notified, &f.LastNotifiedPriority, &f.DigestPending, &f.PathClass, &f.PathReason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return f, err
		}
		return f, fmt.Errorf("scan finding: %w", err)
	}
	f.Detail = json.RawMessage(detail)
	f.FirstSeen, f.LastChanged = fromMillis(first), fromMillis(last)
	f.ResolvedAt, f.AcknowledgedAt, f.SnoozedUntil, f.NotifiedAt = optPtr(resolved), optPtr(acked), optPtr(snoozed), optPtr(notified)
	if err := json.Unmarshal([]byte(evidence), &f.ExposureEvidence); err != nil {
		return f, fmt.Errorf("decode exposure evidence: %w", err)
	}
	return f, nil
}

func optPtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMillis(v.Int64)
	return &t
}
