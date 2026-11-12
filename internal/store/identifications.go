// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bifrost0x/varde/internal/identify"
)

// ReplaceIdentifications stores rs as the complete set of identifications.
// Rows of workloads not in rs are deleted, so the table always reflects the
// latest analysis.
func (s *Store) ReplaceIdentifications(ctx context.Context, rs []identify.Result, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM identifications`); err != nil {
			return fmt.Errorf("clear identifications: %w", err)
		}
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO identifications (workload_id, app_id, confidence, rule, version, version_raw, version_source, note,
				trust, evidence_json, purl, unfixed, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare identification insert: %w", err)
		}
		defer func() { _ = stmt.Close() }()
		for _, r := range rs {
			ev := r.Evidence
			if ev == nil {
				ev = []identify.Evidence{}
			}
			evJSON, err := json.Marshal(ev)
			if err != nil {
				return fmt.Errorf("encode evidence of %s: %w", r.WorkloadID, err)
			}
			if _, err := stmt.ExecContext(ctx, r.WorkloadID, r.AppID, string(r.Confidence), r.Rule,
				r.Version, r.VersionRaw, r.VersionSource, r.Note, string(r.Trust), string(evJSON), r.PURL, r.Unfixed, millis(now)); err != nil {
				return fmt.Errorf("insert identification for %s: %w", r.WorkloadID, err)
			}
		}
		return nil
	})
}

// Identifications returns all stored identifications keyed by workload ID.
func (s *Store) Identifications(ctx context.Context) (map[string]identify.Result, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT workload_id, app_id, confidence, rule, version, version_raw, version_source, note, trust, evidence_json, purl, unfixed FROM identifications`)
	if err != nil {
		return nil, fmt.Errorf("query identifications: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]identify.Result{}
	for rows.Next() {
		var r identify.Result
		var conf, trust, ev string
		if err := rows.Scan(&r.WorkloadID, &r.AppID, &conf, &r.Rule, &r.Version, &r.VersionRaw, &r.VersionSource, &r.Note, &trust, &ev, &r.PURL, &r.Unfixed); err != nil {
			return nil, fmt.Errorf("scan identification: %w", err)
		}
		if err := json.Unmarshal([]byte(ev), &r.Evidence); err != nil {
			return nil, fmt.Errorf("decode evidence of %s: %w", r.WorkloadID, err)
		}
		r.Confidence, r.Trust = identify.Confidence(conf), identify.Trust(trust)
		out[r.WorkloadID] = r
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identifications: %w", err)
	}
	return out, nil
}
