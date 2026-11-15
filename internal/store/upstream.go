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

// maxCandidateBytes bounds a stored candidate package list (gzip JSON).
const maxCandidateBytes = 8 << 20

// UpstreamKey names one image as it runs: its repository, the tag it was
// pulled by, its registry digest and the host platform ("linux/amd64").
type UpstreamKey struct {
	Repository, Tag, RunningDigest, Platform string
}

// UpstreamCheck is what the registry said about one running image.
type UpstreamCheck struct {
	UpstreamKey
	// HeadDigest is what the running tag points to now.
	HeadDigest string
	// CandidateTag and CandidateDigest name a newer image: the running
	// tag rebuilt, or the newest tag on its track. Empty when none exists.
	CandidateTag, CandidateDigest string
	// Candidate is the candidate's package list as Varde read it from the
	// registry (gzip JSON), nil when it was not read; CandidateError says
	// why a read failed.
	Candidate       []byte
	CandidateReadAt time.Time
	CandidateError  string
	Checked         time.Time
	// Error is why the registry gave no answer, in the words of the
	// pages; empty on success.
	Error string
}

// UpstreamChecks returns every recorded check.
func (s *Store) UpstreamChecks(ctx context.Context) (map[UpstreamKey]UpstreamCheck, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT repository, tag, running_digest, platform, head_digest, candidate_tag, candidate_digest,
		candidate, candidate_read_at, candidate_error, checked_at, error FROM upstream_checks`)
	if err != nil {
		return nil, fmt.Errorf("query upstream checks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[UpstreamKey]UpstreamCheck{}
	for rows.Next() {
		var c UpstreamCheck
		var readAt, checked int64
		if err := rows.Scan(&c.Repository, &c.Tag, &c.RunningDigest, &c.Platform, &c.HeadDigest, &c.CandidateTag, &c.CandidateDigest,
			&c.Candidate, &readAt, &c.CandidateError, &checked, &c.Error); err != nil {
			return nil, fmt.Errorf("scan upstream check: %w", err)
		}
		if readAt > 0 {
			c.CandidateReadAt = fromMillis(readAt)
		}
		c.Checked = fromMillis(checked)
		out[c.UpstreamKey] = c
	}
	return out, rows.Err()
}

// RecordUpstreamCheck stores one check, replacing the earlier one of the
// same image.
func (s *Store) RecordUpstreamCheck(ctx context.Context, c UpstreamCheck) error {
	if len(c.Candidate) > maxCandidateBytes {
		return fmt.Errorf("record upstream check: candidate list of %d bytes is larger than %d", len(c.Candidate), maxCandidateBytes)
	}
	var cand any
	if c.Candidate != nil {
		cand = c.Candidate
	}
	var readAt int64
	if !c.CandidateReadAt.IsZero() {
		readAt = millis(c.CandidateReadAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO upstream_checks (repository, tag, running_digest, platform, head_digest, candidate_tag,
		candidate_digest, candidate, candidate_read_at, candidate_error, checked_at, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (repository, tag, running_digest, platform) DO UPDATE SET head_digest = excluded.head_digest,
		candidate_tag = excluded.candidate_tag, candidate_digest = excluded.candidate_digest, candidate = excluded.candidate,
		candidate_read_at = excluded.candidate_read_at, candidate_error = excluded.candidate_error,
		checked_at = excluded.checked_at, error = excluded.error`,
		truncate(c.Repository, 512), truncate(c.Tag, 128), truncate(c.RunningDigest, 128), truncate(c.Platform, 64),
		truncate(c.HeadDigest, 128), truncate(c.CandidateTag, 128), truncate(c.CandidateDigest, 128), cand, readAt,
		truncate(c.CandidateError, 512), millis(c.Checked), truncate(c.Error, 512))
	if err != nil {
		return fmt.Errorf("record upstream check: %w", err)
	}
	return nil
}

// PruneUpstreamChecks removes checks of images no container runs any more.
func (s *Store) PruneUpstreamChecks(ctx context.Context, keep map[UpstreamKey]bool) error {
	have, err := s.UpstreamChecks(ctx)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for k := range have {
			if keep[k] {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM upstream_checks WHERE repository = ? AND tag = ? AND running_digest = ? AND platform = ?`,
				k.Repository, k.Tag, k.RunningDigest, k.Platform); err != nil {
				return fmt.Errorf("prune upstream check: %w", err)
			}
		}
		return nil
	})
}

// ReplaceUpstreamStatus stores the upstream status of each container with
// image findings (JSON, by workload ID) and drops the others.
func (s *Store) ReplaceUpstreamStatus(ctx context.Context, status map[string]json.RawMessage, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM upstream_status`); err != nil {
			return fmt.Errorf("clear upstream status: %w", err)
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO upstream_status (workload_id, status, computed_at) VALUES (?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare upstream status: %w", err)
		}
		defer func() { _ = stmt.Close() }()
		for id, st := range status {
			if _, err := stmt.ExecContext(ctx, id, string(st), millis(now)); err != nil {
				return fmt.Errorf("store upstream status of %s: %w", id, err)
			}
		}
		return nil
	})
}

// UpstreamStatus returns the stored status of each container (JSON).
func (s *Store) UpstreamStatus(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT workload_id, status FROM upstream_status`)
	if err != nil {
		return nil, fmt.Errorf("query upstream status: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var id, st string
		if err := rows.Scan(&id, &st); err != nil {
			return nil, fmt.Errorf("scan upstream status: %w", err)
		}
		out[id] = json.RawMessage(st)
	}
	return out, rows.Err()
}

// TrimLayerReads drops layer reads, oldest first, beyond maxBytes: an
// installation keeps them only to read newer images again cheaply (ADR
// 0045), and the cache must not grow with every image ever read. It
// returns how many it dropped.
func (s *Store) TrimLayerReads(ctx context.Context, maxBytes int64) (int, error) {
	n := 0
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT digest, length(files) FROM layer_reads ORDER BY read_at DESC, digest`)
		if err != nil {
			return fmt.Errorf("query layer reads: %w", err)
		}
		var over []string
		var kept int64
		for rows.Next() {
			var d string
			var size int64
			if err := rows.Scan(&d, &size); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan layer read: %w", err)
			}
			if kept+size > maxBytes {
				over = append(over, d)
				continue
			}
			kept += size
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("query layer reads: %w", err)
		}
		for _, d := range over {
			if _, err := tx.ExecContext(ctx, `DELETE FROM layer_reads WHERE digest = ?`, d); err != nil {
				return fmt.Errorf("trim layer read: %w", err)
			}
		}
		n = len(over)
		return nil
	})
	return n, err
}
