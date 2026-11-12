// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestScanRuns(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.LastScanRun(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty: %v", err)
	}
	start := time.Now().Truncate(time.Millisecond)
	for i := range scanRunsKept + 5 {
		r := ScanRun{Trigger: "manual", Networks: "10.0.0.0/24", Started: start.Add(time.Duration(i) * time.Minute),
			Ended: start.Add(time.Duration(i)*time.Minute + 30*time.Second), Addresses: 254, Found: i, Intercepted: []int{53}}
		if err := s.RecordScanRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	last, err := s.LastScanRun(ctx)
	if err != nil || last.Found != scanRunsKept+4 || len(last.Intercepted) != 1 || last.Intercepted[0] != 53 || !last.Ended.Equal(start.Add(time.Duration(scanRunsKept+4)*time.Minute+30*time.Second)) {
		t.Fatalf("last: %+v %v", last, err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM scan_runs`).Scan(&n); err != nil || n != scanRunsKept {
		t.Errorf("kept %d runs, want %d (%v)", n, scanRunsKept, err)
	}
}
