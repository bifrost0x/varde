// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// keyRetention is how long an identity key is kept after it was last seen.
const keyRetention = 90 * 24 * time.Hour

// AssetIDs returns the asset of every known identity key.
func (s *Store) AssetIDs(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, value, asset_id FROM asset_keys`)
	if err != nil {
		return nil, fmt.Errorf("query asset keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var kind, value, id string
		if err := rows.Scan(&kind, &value, &id); err != nil {
			return nil, fmt.Errorf("scan asset key: %w", err)
		}
		out[kind+":"+value] = id
	}
	return out, rows.Err()
}

// SyncAssets gives every group of identity keys (one group per machine,
// keys as "kind:value") a stable asset ID and returns the IDs by group
// index. A group whose keys belong to one asset keeps it; keys of several
// assets merge into the oldest of them; a group without known keys gets a
// new asset. Keys move with their machine.
func (s *Store) SyncAssets(ctx context.Context, groups [][]string, now time.Time) (map[int]string, error) {
	out := map[int]string{}
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		created := map[string]int64{}
		// rowid orders assets by creation, also within one millisecond.
		rows, err := tx.QueryContext(ctx, `SELECT id, rowid FROM assets`)
		if err != nil {
			return fmt.Errorf("query assets: %w", err)
		}
		for rows.Next() {
			var id string
			var c int64
			if err := rows.Scan(&id, &c); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan asset: %w", err)
			}
			created[id] = c
		}
		_ = rows.Close()
		owner := map[string]string{}
		rows, err = tx.QueryContext(ctx, `SELECT kind, value, asset_id FROM asset_keys`)
		if err != nil {
			return fmt.Errorf("query asset keys: %w", err)
		}
		for rows.Next() {
			var kind, value, id string
			if err := rows.Scan(&kind, &value, &id); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan asset key: %w", err)
			}
			owner[kind+":"+value] = id
		}
		_ = rows.Close()

		for gi, keys := range groups {
			if len(keys) == 0 {
				continue
			}
			var candidates []string
			seen := map[string]bool{}
			for _, k := range keys {
				if id, ok := owner[k]; ok && !seen[id] {
					seen[id] = true
					candidates = append(candidates, id)
				}
			}
			var id string
			if len(candidates) > 0 {
				sort.Slice(candidates, func(i, j int) bool {
					if created[candidates[i]] != created[candidates[j]] {
						return created[candidates[i]] < created[candidates[j]]
					}
					return candidates[i] < candidates[j]
				})
				id = candidates[0]
			} else {
				b := make([]byte, 8)
				if _, err := rand.Read(b); err != nil {
					return fmt.Errorf("asset id: %w", err)
				}
				id = "a-" + hex.EncodeToString(b)
				res, err := tx.ExecContext(ctx, `INSERT INTO assets (id, created_at, last_seen) VALUES (?, ?, ?)`, id, millis(now), millis(now))
				if err != nil {
					return fmt.Errorf("create asset: %w", err)
				}
				if created[id], err = res.LastInsertId(); err != nil {
					return fmt.Errorf("create asset: %w", err)
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE assets SET last_seen = ? WHERE id = ?`, millis(now), id); err != nil {
				return fmt.Errorf("touch asset: %w", err)
			}
			for _, k := range keys {
				kind, value, ok := cutKey(k)
				if !ok {
					continue
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO asset_keys (asset_id, kind, value, last_seen) VALUES (?, ?, ?, ?)
					ON CONFLICT (kind, value) DO UPDATE SET asset_id = excluded.asset_id, last_seen = excluded.last_seen`,
					id, kind, truncate(value, 256), millis(now)); err != nil {
					return fmt.Errorf("record asset key: %w", err)
				}
				owner[k] = id
			}
			out[gi] = id
		}
		// Keys not seen for keyRetention are forgotten (a removed VM, an old
		// lease); assets whose keys all moved or expired are gone.
		if _, err := tx.ExecContext(ctx, `DELETE FROM asset_keys WHERE last_seen < ?`, millis(now.Add(-keyRetention))); err != nil {
			return fmt.Errorf("expire asset keys: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE id NOT IN (SELECT asset_id FROM asset_keys)`); err != nil {
			return fmt.Errorf("drop empty assets: %w", err)
		}
		return nil
	})
	return out, err
}

func cutKey(k string) (kind, value string, ok bool) {
	for i := 0; i < len(k); i++ {
		if k[i] == ':' {
			return k[:i], k[i+1:], i > 0 && i < len(k)-1
		}
	}
	return "", "", false
}
