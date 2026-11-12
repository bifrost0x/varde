// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
)

// Snapshot writes a consistent copy of the database at src to dest, which
// must not exist, while the server may keep running (VACUUM INTO reads one
// transaction). The copy carries the schema version it was taken at.
func Snapshot(ctx context.Context, src, dest string) error {
	q := url.Values{}
	q.Set("mode", "ro")
	q.Set("_busy_timeout", "10000")
	db, err := sql.Open("sqlite", "file:"+src+"?"+q.Encode())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dest); err != nil {
		return fmt.Errorf("copy database: %w", err)
	}
	return nil
}
