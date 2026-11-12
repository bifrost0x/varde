// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bifrost0x/varde/internal/paths"
)

// ReplacePaths stores the attack paths of an analysis run in place of the
// previous ones.
func (s *Store) ReplacePaths(ctx context.Context, ps []paths.Path, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM attack_paths`); err != nil {
			return fmt.Errorf("clear attack paths: %w", err)
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO attack_paths (id, entry, score, target, detail_json, computed_at) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare attack path insert: %w", err)
		}
		defer func() { _ = stmt.Close() }()
		for _, p := range ps {
			raw, err := json.Marshal(p)
			if err != nil {
				return fmt.Errorf("encode attack path: %w", err)
			}
			if _, err := stmt.ExecContext(ctx, p.ID, string(p.Entry), p.Score, p.Target, string(raw), millis(now)); err != nil {
				return fmt.Errorf("insert attack path %s: %w", p.ID, err)
			}
		}
		return nil
	})
}

// Paths returns the stored attack paths, highest score first.
func (s *Store) Paths(ctx context.Context) ([]paths.Path, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT detail_json FROM attack_paths ORDER BY score DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("query attack paths: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []paths.Path{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan attack path: %w", err)
		}
		var p paths.Path
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, fmt.Errorf("decode attack path: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
