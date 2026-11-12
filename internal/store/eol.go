// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// EOLRelease is one release line of a product as endoflife.date lists it.
type EOLRelease struct {
	// Name is the release line ("1.29", "13.2", "2026.8").
	Name string `json:"name"`
	// EOLFrom is the date support ends or ended (YYYY-MM-DD), empty when
	// none is announced.
	EOLFrom string `json:"eol_from,omitempty"`
	IsEOL   bool   `json:"is_eol"`
	// Latest is the newest release of the line.
	Latest string `json:"latest,omitempty"`
}

// maxEOLReleases bounds the release lines kept per product.
const maxEOLReleases = 200

// EOL returns the release lines of every recorded product.
func (s *Store) EOL(ctx context.Context) (map[string][]EOLRelease, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT product, releases FROM eol_releases`)
	if err != nil {
		return nil, fmt.Errorf("query eol: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]EOLRelease{}
	for rows.Next() {
		var product, raw string
		if err := rows.Scan(&product, &raw); err != nil {
			return nil, fmt.Errorf("scan eol: %w", err)
		}
		var rel []EOLRelease
		if err := json.Unmarshal([]byte(raw), &rel); err != nil {
			return nil, fmt.Errorf("decode eol of %s: %w", product, err)
		}
		out[product] = rel
	}
	return out, rows.Err()
}

// RecordEOL replaces the release lines of a product.
func (s *Store) RecordEOL(ctx context.Context, product string, releases []EOLRelease, now time.Time) error {
	if len(releases) > maxEOLReleases {
		releases = releases[:maxEOLReleases]
	}
	for i := range releases {
		r := &releases[i]
		r.Name, r.EOLFrom, r.Latest = truncate(r.Name, 64), truncate(r.EOLFrom, 32), truncate(r.Latest, 64)
	}
	raw, err := json.Marshal(releases)
	if err != nil {
		return fmt.Errorf("encode eol: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO eol_releases (product, releases, fetched_at) VALUES (?, ?, ?)
		ON CONFLICT (product) DO UPDATE SET releases = excluded.releases, fetched_at = excluded.fetched_at`,
		truncate(product, 64), string(raw), millis(now))
	if err != nil {
		return fmt.Errorf("record eol: %w", err)
	}
	return nil
}
