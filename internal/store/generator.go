// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// recheckAfter is how long a shipped candidate is trusted before the
// builder checks it again.
const recheckAfter = 30 * 24 * time.Hour

// Candidate is an image the catalog generator considers. CheckedAt and
// ShippedAt are zero while the candidate was not checked or shipped.
type Candidate struct {
	Image, Repo string
	Weight      int64
	Status      string
	FailedCheck string
	EntryYAML   string
	InputsHash  string
	CheckedAt   time.Time
	ShippedAt   time.Time
}

// nullMillis stores a zero time as NULL.
func nullMillis(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: millis(t), Valid: true}
}

func fromNullMillis(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return fromMillis(n.Int64)
}

// UpsertCandidate stores a candidate, replacing the row of the same image.
func (s *Store) UpsertCandidate(ctx context.Context, c Candidate) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO gen_candidates (image, repo, weight, status, failed_check, entry_yaml, inputs_hash, checked_at, shipped_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (image) DO UPDATE SET repo = excluded.repo, weight = excluded.weight, status = excluded.status,
		failed_check = excluded.failed_check, entry_yaml = excluded.entry_yaml, inputs_hash = excluded.inputs_hash,
		checked_at = excluded.checked_at, shipped_at = excluded.shipped_at`,
		c.Image, c.Repo, c.Weight, c.Status, c.FailedCheck, c.EntryYAML, c.InputsHash, nullMillis(c.CheckedAt), nullMillis(c.ShippedAt))
	if err != nil {
		return fmt.Errorf("upsert candidate: %w", err)
	}
	return nil
}

// Candidates returns up to limit candidates to work on: first those never
// checked, heaviest first, then shipped ones last checked more than
// recheckAfter before now, oldest first.
func (s *Store) Candidates(ctx context.Context, limit int, now time.Time) ([]Candidate, error) {
	if limit <= 0 {
		return nil, nil
	}
	const cols = `SELECT image, repo, weight, status, failed_check, entry_yaml, inputs_hash, checked_at, shipped_at FROM gen_candidates `
	out, err := s.queryCandidates(ctx, cols+`WHERE checked_at IS NULL ORDER BY weight DESC, image LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	if len(out) >= limit {
		return out, nil
	}
	due, err := s.queryCandidates(ctx, cols+`WHERE status = 'shipped' AND checked_at < ? ORDER BY checked_at, image LIMIT ?`,
		millis(now.Add(-recheckAfter)), limit-len(out))
	if err != nil {
		return nil, err
	}
	return append(out, due...), nil
}

func (s *Store) queryCandidates(ctx context.Context, query string, args ...any) ([]Candidate, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Candidate
	for rows.Next() {
		var c Candidate
		var checked, shipped sql.NullInt64
		if err := rows.Scan(&c.Image, &c.Repo, &c.Weight, &c.Status, &c.FailedCheck, &c.EntryYAML, &c.InputsHash, &checked, &shipped); err != nil {
			return nil, fmt.Errorf("scan candidate: %w", err)
		}
		c.CheckedAt, c.ShippedAt = fromNullMillis(checked), fromNullMillis(shipped)
		out = append(out, c)
	}
	return out, rows.Err()
}

// LayerRead returns the cached files of a layer digest (gzip JSON) and
// whether the layer was read at all. A partial read is a stored read too:
// the caller decides from its own bounds whether to read the layer again.
func (s *Store) LayerRead(ctx context.Context, digest string) (files []byte, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT files FROM layer_reads WHERE digest = ?`, digest).Scan(&files)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("query layer read: %w", err)
	}
	return files, true, nil
}

// PutLayerRead stores what was read from a layer, replacing an earlier read
// of the same digest. files is gzip-compressed JSON.
func (s *Store) PutLayerRead(ctx context.Context, digest string, files []byte, partial bool) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO layer_reads (digest, files, partial, read_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (digest) DO UPDATE SET files = excluded.files, partial = excluded.partial, read_at = excluded.read_at`,
		digest, files, partial, millis(time.Now()))
	if err != nil {
		return fmt.Errorf("put layer read: %w", err)
	}
	return nil
}

// ReleaseRead returns the stored release read of an app's image on a
// platform: the tag, the digest of the index it came from and the JSON line.
func (s *Store) ReleaseRead(ctx context.Context, appID, image, platform string) (tag, indexDigest string, line []byte, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT tag, index_digest, line FROM release_reads WHERE app_id = ? AND image = ? AND platform = ?`,
		appID, image, platform).Scan(&tag, &indexDigest, &line)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil, false, nil
	}
	if err != nil {
		return "", "", nil, false, fmt.Errorf("query release read: %w", err)
	}
	return tag, indexDigest, line, true, nil
}

// PutReleaseRead stores a release read, replacing the earlier one of the
// same app, image and platform.
func (s *Store) PutReleaseRead(ctx context.Context, appID, image, platform, tag, indexDigest string, line []byte, readAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO release_reads (app_id, image, platform, tag, index_digest, line, read_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (app_id, image, platform) DO UPDATE SET tag = excluded.tag, index_digest = excluded.index_digest,
		line = excluded.line, read_at = excluded.read_at`,
		appID, image, platform, tag, indexDigest, line, millis(readAt))
	if err != nil {
		return fmt.Errorf("put release read: %w", err)
	}
	return nil
}

// ReleaseReads returns the line of every release read, ordered by app,
// image and platform so the published blob is reproducible.
func (s *Store) ReleaseReads(ctx context.Context) ([][]byte, error) {
	return s.lines(ctx, `SELECT line FROM release_reads ORDER BY app_id, image, platform`)
}

// ReleasePackageRow is one release package list of an installation. Line is
// the JSON the caller reads it from; the store keeps it opaque.
type ReleasePackageRow struct {
	AppID, Image, Platform, Tag, Version string
	Line                                 []byte
}

// ReplaceReleasePackages replaces the whole table in one transaction, so a
// reader sees either the old package's lists or the new one's, never a mix.
func (s *Store) ReplaceReleasePackages(ctx context.Context, rows []ReleasePackageRow) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM release_packages`); err != nil {
			return fmt.Errorf("clear release packages: %w", err)
		}
		for _, r := range rows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO release_packages (app_id, image, platform, tag, version, line) VALUES (?, ?, ?, ?, ?, ?)`,
				r.AppID, r.Image, r.Platform, r.Tag, r.Version, r.Line); err != nil {
				return fmt.Errorf("insert release package of %s: %w", r.AppID, err)
			}
		}
		return nil
	})
}

// ReleasePackagesFor returns the lines of an app's image, one per platform.
func (s *Store) ReleasePackagesFor(ctx context.Context, appID, image string) ([][]byte, error) {
	return s.lines(ctx, `SELECT line FROM release_packages WHERE app_id = ? AND image = ? ORDER BY platform`, appID, image)
}

func (s *Store) lines(ctx context.Context, query string, args ...any) ([][]byte, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query lines: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out [][]byte
	for rows.Next() {
		var l []byte
		if err := rows.Scan(&l); err != nil {
			return nil, fmt.Errorf("scan line: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
