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

// ReleaseReadPlatforms returns the platforms an app's image has release
// reads under, in order.
func (s *Store) ReleaseReadPlatforms(ctx context.Context, appID, image string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT platform FROM release_reads WHERE app_id = ? AND image = ? ORDER BY platform`, appID, image)
	if err != nil {
		return nil, fmt.Errorf("query release read platforms: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan release read platform: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query release read platforms: %w", err)
	}
	return out, nil
}

// PutReleaseRead stores a release read, replacing the earlier one of the
// same app, image and platform. The limits and layers of the earlier read
// are cleared (SetReleaseReadLimits, SetReleaseReadLayers).
func (s *Store) PutReleaseRead(ctx context.Context, appID, image, platform, tag, indexDigest string, line []byte, readAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO release_reads (app_id, image, platform, tag, index_digest, line, read_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (app_id, image, platform) DO UPDATE SET tag = excluded.tag, index_digest = excluded.index_digest,
		line = excluded.line, read_at = excluded.read_at, limits = '', layers = ''`,
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

// ReleaseReadLayers returns the layer_reads keys a release read used, as
// SetReleaseReadLayers stored them; empty when unknown or when there is no
// such read.
func (s *Store) ReleaseReadLayers(ctx context.Context, appID, image, platform string) (string, error) {
	var layers string
	err := s.db.QueryRowContext(ctx, `SELECT layers FROM release_reads WHERE app_id = ? AND image = ? AND platform = ?`,
		appID, image, platform).Scan(&layers)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query release read layers: %w", err)
	}
	return layers, nil
}

// SetReleaseReadLayers records the layer_reads keys a stored release read
// used, a JSON array of strings (PruneBuilderReads keeps those).
func (s *Store) SetReleaseReadLayers(ctx context.Context, appID, image, platform, layers string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE release_reads SET layers = ? WHERE app_id = ? AND image = ? AND platform = ?`,
		layers, appID, image, platform)
	if err != nil {
		return fmt.Errorf("set release read layers: %w", err)
	}
	return nil
}

// ReleaseReadKey names one release read.
type ReleaseReadKey struct{ AppID, Image, Platform string }

// PruneStats says what PruneBuilderReads removed and what is left.
type PruneStats struct {
	// Reads and Layers are the release reads and the layer reads removed.
	Reads, Layers int
	// LayerBytes is the size of the layer reads left.
	LayerBytes int64
}

// PruneBuilderReads keeps the release reads of keep and drops the others
// (a platform a release dropped, an app that left the catalog, a line
// that no longer ships), then the layer reads no kept release read names
// (SetReleaseReadLayers), then, oldest first, layer reads beyond
// maxLayerBytes. The builder's store is published after every build;
// without this it would grow with every release and layer ever read. The
// freed pages are given back (VACUUM), as the file is what is published.
func (s *Store) PruneBuilderReads(ctx context.Context, keep []ReleaseReadKey, maxLayerBytes int64) (PruneStats, error) {
	var st PruneStats
	keys := make([]string, len(keep))
	for i, k := range keep {
		keys[i] = k.AppID + "\x00" + k.Image + "\x00" + k.Platform
	}
	arg, err := json.Marshal(keys)
	if err != nil {
		return st, fmt.Errorf("encode release reads: %w", err)
	}
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM release_reads
			WHERE app_id || char(0) || image || char(0) || platform NOT IN (SELECT value FROM json_each(?))`, string(arg))
		if err != nil {
			return fmt.Errorf("prune release reads: %w", err)
		}
		n, _ := res.RowsAffected()
		st.Reads = int(n)
		res, err = tx.ExecContext(ctx, `DELETE FROM layer_reads WHERE digest NOT IN (
			SELECT j.value FROM release_reads AS r, json_each(CASE WHEN json_valid(r.layers) THEN r.layers ELSE '[]' END) AS j)`)
		if err != nil {
			return fmt.Errorf("prune layer reads: %w", err)
		}
		n, _ = res.RowsAffected()
		st.Layers = int(n)
		rows, err := tx.QueryContext(ctx, `SELECT digest, length(files) FROM layer_reads ORDER BY read_at DESC, digest`)
		if err != nil {
			return fmt.Errorf("query layer reads: %w", err)
		}
		var over []string
		for rows.Next() {
			var d string
			var size int64
			if err := rows.Scan(&d, &size); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan layer read: %w", err)
			}
			if st.LayerBytes+size > maxLayerBytes {
				over = append(over, d)
				continue
			}
			st.LayerBytes += size
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("query layer reads: %w", err)
		}
		for _, d := range over {
			if _, err := tx.ExecContext(ctx, `DELETE FROM layer_reads WHERE digest = ?`, d); err != nil {
				return fmt.Errorf("prune layer read: %w", err)
			}
		}
		st.Layers += len(over)
		return nil
	})
	if err != nil {
		return st, err
	}
	return st, s.Vacuum(ctx)
}

// DropLayerReads removes every layer read and gives the pages back: the
// next build reads the layers it needs again.
func (s *Store) DropLayerReads(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM layer_reads`)
	if err != nil {
		return 0, fmt.Errorf("drop layer reads: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), s.Vacuum(ctx)
}

// Vacuum rebuilds the database file without free pages, and folds the
// write-ahead log into it.
func (s *Store) Vacuum(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
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

// ReleaseImage names the release lines of one app's image.
type ReleaseImage struct{ AppID, Image string }

// ReleasePackagesOf returns the lines of several apps' images in one read,
// for a page that shows many containers.
func (s *Store) ReleasePackagesOf(ctx context.Context, images []ReleaseImage) (map[ReleaseImage][][]byte, error) {
	out := map[ReleaseImage][][]byte{}
	if len(images) == 0 {
		return out, nil
	}
	keys := make([]string, len(images))
	for i, im := range images {
		keys[i] = im.AppID + "\x00" + im.Image
	}
	arg, err := json.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("encode release images: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT app_id, image, line FROM release_packages
		WHERE app_id || char(0) || image IN (SELECT value FROM json_each(?)) ORDER BY app_id, image, platform`, string(arg))
	if err != nil {
		return nil, fmt.Errorf("query release packages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var im ReleaseImage
		var l []byte
		if err := rows.Scan(&im.AppID, &im.Image, &l); err != nil {
			return nil, fmt.Errorf("scan release package: %w", err)
		}
		out[im] = append(out[im], l)
	}
	return out, rows.Err()
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
