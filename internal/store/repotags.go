// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// maxRepositoryTags bounds the tags kept per repository.
const maxRepositoryTags = 2000

// RepositoryTags are the release tags a registry listed for a repository.
type RepositoryTags struct {
	Repository string
	Tags       []string
	Checked    time.Time
	Error      string
}

// RepositoryTags returns every recorded tag list, keyed by repository.
func (s *Store) RepositoryTags(ctx context.Context) (map[string]RepositoryTags, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT repository, tags, checked_at, error FROM repository_tags`)
	if err != nil {
		return nil, fmt.Errorf("query repository tags: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]RepositoryTags{}
	for rows.Next() {
		var t RepositoryTags
		var raw string
		var checked int64
		if err := rows.Scan(&t.Repository, &raw, &checked, &t.Error); err != nil {
			return nil, fmt.Errorf("scan repository tags: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &t.Tags); err != nil {
			return nil, fmt.Errorf("decode tags of %s: %w", t.Repository, err)
		}
		t.Checked = fromMillis(checked)
		out[t.Repository] = t
	}
	return out, rows.Err()
}

// RecordRepositoryTags stores one answer. A failed listing keeps the tags
// of an earlier successful one.
func (s *Store) RecordRepositoryTags(ctx context.Context, t RepositoryTags) error {
	if t.Error != "" {
		_, err := s.db.ExecContext(ctx, `INSERT INTO repository_tags (repository, checked_at, error) VALUES (?, ?, ?)
			ON CONFLICT (repository) DO UPDATE SET checked_at = excluded.checked_at, error = excluded.error`,
			truncate(t.Repository, 512), millis(t.Checked), truncate(t.Error, 512))
		if err != nil {
			return fmt.Errorf("record repository tags: %w", err)
		}
		return nil
	}
	tags := t.Tags
	if len(tags) > maxRepositoryTags {
		tags = tags[len(tags)-maxRepositoryTags:]
	}
	clean := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag != "" && len(tag) <= 128 {
			clean = append(clean, tag)
		}
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return fmt.Errorf("encode tags: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO repository_tags (repository, tags, checked_at, error) VALUES (?, ?, ?, '')
		ON CONFLICT (repository) DO UPDATE SET tags = excluded.tags, checked_at = excluded.checked_at, error = ''`,
		truncate(t.Repository, 512), string(raw), millis(t.Checked))
	if err != nil {
		return fmt.Errorf("record repository tags: %w", err)
	}
	return nil
}
