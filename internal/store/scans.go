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

// scanRunsKept is how many scan runs are kept.
const scanRunsKept = 50

// ScanRun is the outcome of one network scan.
type ScanRun struct {
	// Trigger is "manual" or "schedule".
	Trigger   string    `json:"trigger"`
	Networks  string    `json:"networks"`
	Started   time.Time `json:"started"`
	Ended     time.Time `json:"ended"`
	Addresses int       `json:"addresses"`
	Found     int       `json:"found"`
	// Intercepted are ports ignored because they answered almost
	// everywhere.
	Intercepted []int  `json:"intercepted,omitempty"`
	Error       string `json:"error,omitempty"`
}

// RecordScanRun stores a finished scan and drops the oldest runs beyond
// the kept number.
func (s *Store) RecordScanRun(ctx context.Context, r ScanRun) error {
	if r.Intercepted == nil {
		r.Intercepted = []int{}
	}
	ic, err := json.Marshal(r.Intercepted)
	if err != nil {
		return fmt.Errorf("encode intercepted ports: %w", err)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scan_runs (trigger, networks, started, ended, addresses, found, intercepted_json, error)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, truncate(r.Trigger, 16), truncate(r.Networks, 1024), millis(r.Started), millis(r.Ended),
			r.Addresses, r.Found, string(ic), truncate(r.Error, 1024)); err != nil {
			return fmt.Errorf("record scan run: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM scan_runs WHERE id NOT IN (SELECT id FROM scan_runs ORDER BY id DESC LIMIT ?)`, scanRunsKept); err != nil {
			return fmt.Errorf("prune scan runs: %w", err)
		}
		return nil
	})
}

// LastScanRun returns the newest scan run or ErrNotFound.
func (s *Store) LastScanRun(ctx context.Context) (ScanRun, error) {
	var r ScanRun
	var started, ended int64
	var ic string
	err := s.db.QueryRowContext(ctx, `SELECT trigger, networks, started, ended, addresses, found, intercepted_json, error
		FROM scan_runs ORDER BY id DESC LIMIT 1`).Scan(&r.Trigger, &r.Networks, &started, &ended, &r.Addresses, &r.Found, &ic, &r.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, fmt.Errorf("query last scan run: %w", err)
	}
	if err := json.Unmarshal([]byte(ic), &r.Intercepted); err != nil {
		return r, fmt.Errorf("decode intercepted ports: %w", err)
	}
	r.Started, r.Ended = fromMillis(started), fromMillis(ended)
	return r, nil
}
