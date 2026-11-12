// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"
)

// NotAnApp returns the image repositories marked as not an app.
func (s *Store) NotAnApp(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT repository FROM not_an_app`)
	if err != nil {
		return nil, fmt.Errorf("query not-an-app marks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var repo string
		if err := rows.Scan(&repo); err != nil {
			return nil, fmt.Errorf("scan not-an-app mark: %w", err)
		}
		out[repo] = true
	}
	return out, rows.Err()
}

// MarkNotAnApp records that an image repository is not an app. Marking twice
// keeps the first record.
func (s *Store) MarkNotAnApp(ctx context.Context, repository, actor string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO not_an_app (repository, created_by, created_at) VALUES (?, ?, ?)
		ON CONFLICT (repository) DO NOTHING`, repository, truncate(actor, 128), millis(now)); err != nil {
		return fmt.Errorf("mark not an app: %w", err)
	}
	return nil
}

// UnmarkNotAnApp removes the mark; ErrNotFound when there was none.
func (s *Store) UnmarkNotAnApp(ctx context.Context, repository string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM not_an_app WHERE repository = ?`, repository)
	if err != nil {
		return fmt.Errorf("unmark not an app: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("unmark not an app: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}
