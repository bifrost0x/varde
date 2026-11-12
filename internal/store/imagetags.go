// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"
)

// ImageTag is what the registry said about one digest of a repository:
// the version tag that points to it, empty when none of the asked tags did.
type ImageTag struct {
	Repository, Digest, Tag string
	Checked                 time.Time
	Error                   string
}

// ImageTags returns every recorded answer, keyed by "repository@digest".
func (s *Store) ImageTags(ctx context.Context) (map[string]ImageTag, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT repository, digest, tag, checked_at, error FROM image_tags`)
	if err != nil {
		return nil, fmt.Errorf("query image tags: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]ImageTag{}
	for rows.Next() {
		var t ImageTag
		var checked int64
		if err := rows.Scan(&t.Repository, &t.Digest, &t.Tag, &checked, &t.Error); err != nil {
			return nil, fmt.Errorf("scan image tag: %w", err)
		}
		t.Checked = fromMillis(checked)
		out[t.Repository+"@"+t.Digest] = t
	}
	return out, rows.Err()
}

// RecordImageTag stores the answer for one digest. A digest never changes
// its content, so a found tag is kept; misses are asked again later.
func (s *Store) RecordImageTag(ctx context.Context, t ImageTag) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO image_tags (repository, digest, tag, checked_at, error) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (repository, digest) DO UPDATE SET tag = excluded.tag, checked_at = excluded.checked_at, error = excluded.error`,
		truncate(t.Repository, 512), truncate(t.Digest, 128), truncate(t.Tag, 128), millis(t.Checked), truncate(t.Error, 512))
	if err != nil {
		return fmt.Errorf("record image tag: %w", err)
	}
	return nil
}
