// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RecheckAfter is how long the catalog generator trusts a check result of a
// candidate before it checks the candidate again.
const RecheckAfter = 30 * 24 * time.Hour

// CandidateShipped is the status of a candidate whose entry was shipped.
const CandidateShipped = "shipped"

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

// AllCandidates returns every candidate ordered by image. The generator
// needs the whole set: the package carries every shipped entry, and an image
// that left the index or got a reviewed entry has to be retired.
func (s *Store) AllCandidates(ctx context.Context) ([]Candidate, error) {
	return s.queryCandidates(ctx, `SELECT image, repo, weight, status, failed_check, entry_yaml, inputs_hash, checked_at, shipped_at FROM gen_candidates ORDER BY image`)
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

// LayerRead returns a cached read of an immutable blob or blob chain (gzip
// JSON): the release reader keys layer records by their chain key
// (imagelayers.LayerKeys) and image configs by their digest. partial says
// the read was cut off by a bound; ok whether anything is cached.
func (s *Store) LayerRead(ctx context.Context, digest string) (files []byte, partial, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT files, partial FROM layer_reads WHERE digest = ?`, digest).Scan(&files, &partial)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, fmt.Errorf("query layer read: %w", err)
	}
	return files, partial, true, nil
}

// PutLayerRead stores a read under its key (see LayerRead), replacing an
// earlier one. files is gzip-compressed JSON.
func (s *Store) PutLayerRead(ctx context.Context, digest string, files []byte, partial bool, readAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO layer_reads (digest, files, partial, read_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (digest) DO UPDATE SET files = excluded.files, partial = excluded.partial, read_at = excluded.read_at`,
		digest, files, partial, millis(readAt))
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
// same app, image and platform. The limits of the earlier read are
// cleared (SetReleaseReadLimits).
func (s *Store) PutReleaseRead(ctx context.Context, appID, image, platform, tag, indexDigest string, line []byte, readAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO release_reads (app_id, image, platform, tag, index_digest, line, read_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (app_id, image, platform) DO UPDATE SET tag = excluded.tag, index_digest = excluded.index_digest,
		line = excluded.line, read_at = excluded.read_at, limits = ''`,
		appID, image, platform, tag, indexDigest, line, millis(readAt))
	if err != nil {
		return fmt.Errorf("put release read: %w", err)
	}
	return nil
}

// ReleaseReadLimits returns the limits a release read was made with;
// empty when unknown or when there is no such read.
func (s *Store) ReleaseReadLimits(ctx context.Context, appID, image, platform string) (string, error) {
	var limits string
	err := s.db.QueryRowContext(ctx, `SELECT limits FROM release_reads WHERE app_id = ? AND image = ? AND platform = ?`,
		appID, image, platform).Scan(&limits)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query release read limits: %w", err)
	}
	return limits, nil
}

// SetReleaseReadLimits records the limits a stored release read was made
// with.
func (s *Store) SetReleaseReadLimits(ctx context.Context, appID, image, platform, limits string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE release_reads SET limits = ? WHERE app_id = ? AND image = ? AND platform = ?`,
		limits, appID, image, platform)
	if err != nil {
		return fmt.Errorf("set release read limits: %w", err)
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
// marker names what the rows were made from (ReleasePackagesMarker); it is
// replaced with them.
func (s *Store) ReplaceReleasePackages(ctx context.Context, marker string, rows []ReleasePackageRow) error {
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO release_packages_marker (id, marker) VALUES (1, ?)
			ON CONFLICT (id) DO UPDATE SET marker = excluded.marker`, marker); err != nil {
			return fmt.Errorf("store release packages marker: %w", err)
		}
		return nil
	})
}

// ReleasePackagesMarker returns the marker of the last ReplaceReleasePackages;
// "" when the table was never written.
func (s *Store) ReleasePackagesMarker(ctx context.Context) (string, error) {
	var m string
	err := s.db.QueryRowContext(ctx, `SELECT marker FROM release_packages_marker WHERE id = 1`).Scan(&m)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query release packages marker: %w", err)
	}
	return m, nil
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
