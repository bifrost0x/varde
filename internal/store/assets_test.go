// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSyncAssetsKeepsIdentity(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Now()

	ids, err := s.SyncAssets(ctx, [][]string{{"host:pve-a-101", "mac:bc:24:11:00:00:01"}, {"host:ssh-x"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	vm, other := ids[0], ids[1]
	if vm == "" || other == "" || vm == other {
		t.Fatalf("ids %v", ids)
	}
	// The Proxmox integration is removed and added again: the host record
	// gets a new ID, the MAC stays. The machine keeps its asset.
	ids, err = s.SyncAssets(ctx, [][]string{{"host:pve-b-101", "mac:bc:24:11:00:00:01"}, {"host:ssh-x"}}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ids[0] != vm || ids[1] != other {
		t.Errorf("identity lost: %v, want %s %s", ids, vm, other)
	}
	// Two assets turn out to be one machine: the older one stays.
	ids, err = s.SyncAssets(ctx, [][]string{{"host:pve-b-101", "mac:bc:24:11:00:00:01", "host:ssh-x"}}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ids[0] != vm {
		t.Errorf("merge kept %s, want the older %s", ids[0], vm)
	}
	owner, err := s.AssetIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if owner["host:ssh-x"] != vm || owner["mac:bc:24:11:00:00:01"] != vm {
		t.Errorf("keys %v", owner)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM assets`).Scan(&n); err != nil || n != 1 {
		t.Errorf("assets left: %d %v (the merged one must be gone)", n, err)
	}
}
