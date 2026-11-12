// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "varde.db")
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func container(id, name, image string) inventory.Workload {
	return inventory.Workload{
		Kind: inventory.KindContainer, RuntimeID: id, Name: name, State: "running",
		Container: &inventory.Container{ImageRef: image, ImageID: "sha256:" + id, Labels: map[string]string{"a": "b"}},
	}
}

func localHost(now time.Time) inventory.Host {
	return inventory.Host{ID: inventory.LocalHostID, Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}
}

func TestOpenCreatesPrivateFileAndIsIdempotent(t *testing.T) {
	s, path := openTest(t)
	if err := s.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("database mode %o, want 600", perm)
		}
	}
	_ = s.Close()
	s2, err := Open(t.Context(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = s2.Close()
}

func TestOpenRefusesNewerSchema(t *testing.T) {
	s, path := openTest(t)
	if _, err := s.db.ExecContext(t.Context(), "INSERT INTO schema_migrations (version, name, applied_at) VALUES (9999, 'future', 0)"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(t.Context(), path); err == nil {
		t.Fatal("expected refusal of newer schema")
	}
}

func TestPragmas(t *testing.T) {
	s, _ := openTest(t)
	var mode string
	var fk int
	if err := s.db.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(t.Context(), "PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" || fk != 1 {
		t.Fatalf("journal_mode=%s foreign_keys=%d", mode, fk)
	}
}

func TestApplySnapshotLifecycle(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	if err := s.UpsertHost(ctx, localHost(t0)); err != nil {
		t.Fatal(err)
	}

	res, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("aaa", "immich", "ghcr.io/immich-app/immich-server:v1"), container("bbb", "jellyfin", "jellyfin/jellyfin:10")}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if res != (inventory.Changes{Added: 2}) {
		t.Fatalf("first snapshot: %+v", res)
	}

	// Same content again: nothing changes.
	t1 := t0.Add(time.Minute)
	res, err = s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("aaa", "immich", "ghcr.io/immich-app/immich-server:v1"), container("bbb", "jellyfin", "jellyfin/jellyfin:10")}, t1)
	if err != nil || res.Any() {
		t.Fatalf("identical snapshot: %+v, %v", res, err)
	}

	// jellyfin disappears, immich changes image.
	t2 := t1.Add(time.Minute)
	res, err = s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("aaa", "immich", "ghcr.io/immich-app/immich-server:v2")}, t2)
	if err != nil {
		t.Fatal(err)
	}
	if res != (inventory.Changes{Changed: 1, Removed: 1}) {
		t.Fatalf("third snapshot: %+v", res)
	}

	active, err := s.Workloads(ctx, WorkloadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Container.ImageRef != "ghcr.io/immich-app/immich-server:v2" {
		t.Fatalf("active: %+v", active)
	}
	if !active[0].FirstSeen.Equal(t0) || !active[0].LastSeen.Equal(t2) {
		t.Fatalf("timestamps first=%v last=%v", active[0].FirstSeen, active[0].LastSeen)
	}
	if active[0].Container.Labels["a"] != "b" {
		t.Fatalf("labels lost: %+v", active[0].Container)
	}

	all, err := s.Workloads(ctx, WorkloadFilter{IncludeRemoved: true})
	if err != nil || len(all) != 2 {
		t.Fatalf("all: %d, %v", len(all), err)
	}

	// jellyfin comes back: restored, counted as added.
	res, err = s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("aaa", "immich", "ghcr.io/immich-app/immich-server:v2"), container("bbb", "jellyfin", "jellyfin/jellyfin:10")}, t2.Add(time.Minute))
	if err != nil || res != (inventory.Changes{Added: 1}) {
		t.Fatalf("restore: %+v, %v", res, err)
	}
	w, err := s.Workload(ctx, inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "bbb"))
	if err != nil || w.RemovedAt != nil {
		t.Fatalf("restored workload: %+v, %v", w, err)
	}

	// Purge only affects removed workloads older than the cutoff.
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer, nil, t2.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	n, err := s.PurgeRemoved(ctx, t2.Add(3*time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("purge: %d, %v", n, err)
	}
}

func TestApplySnapshotRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now()
	if err := s.UpsertHost(ctx, localHost(now)); err != nil {
		t.Fatal(err)
	}
	dup := []inventory.Workload{container("aaa", "a", "x"), container("aaa", "b", "y")}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer, dup, now); err == nil {
		t.Error("duplicate runtime id accepted")
	}
	wrong := []inventory.Workload{{Kind: inventory.KindManual, RuntimeID: "m", Manual: &inventory.Manual{}}}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer, wrong, now); err == nil {
		t.Error("kind mismatch accepted")
	}
	if _, err := s.ApplySnapshot(ctx, "missing-host", inventory.KindContainer, []inventory.Workload{container("ccc", "c", "z")}, now); err == nil {
		t.Error("foreign key not enforced")
	}
	ws, err := s.Workloads(ctx, WorkloadFilter{IncludeRemoved: true})
	if err != nil || len(ws) != 0 {
		t.Fatalf("failed snapshots left data behind: %d, %v", len(ws), err)
	}
}

func TestManualWorkloads(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	h := inventory.Host{ID: "nas", Name: "Synology", Kind: inventory.HostAppliance, Source: inventory.SourceManual, LastContact: now}
	if err := s.UpsertHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	w, err := s.AddManual(ctx, inventory.Workload{
		HostID: "nas", Kind: inventory.KindManual, RuntimeID: "dsm", Name: "DSM",
		Manual: &inventory.Manual{AppID: "synology-dsm", Version: "7.2.2", Exposure: inventory.ExposureLAN},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if w.Manual.Version != "7.2.2" || w.HostID != "nas" {
		t.Fatalf("round trip: %+v", w)
	}
	if _, err := s.AddManual(ctx, w, now); err == nil {
		t.Error("duplicate manual entry accepted")
	}
	if err := s.RemoveWorkload(ctx, w.ID, inventory.KindContainer, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("kind guard: %v", err)
	}
	if err := s.RemoveWorkload(ctx, w.ID, inventory.KindManual, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveWorkload(ctx, w.ID, inventory.KindManual, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("second removal: %v", err)
	}
	if _, err := s.Workload(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing workload: %v", err)
	}
	hosts, err := s.Hosts(ctx)
	if err != nil || len(hosts) != 1 || hosts[0].Kind != inventory.HostAppliance {
		t.Fatalf("hosts: %+v, %v", hosts, err)
	}
	if _, err := s.Host(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing host: %v", err)
	}
}

// Temporary tables and sorts stay in memory: the container's read-only
// file system gives SQLite no temp directory it accepts.
func TestTempStoreInMemory(t *testing.T) {
	s, _ := openTest(t)
	var mode int
	if err := s.db.QueryRowContext(t.Context(), `PRAGMA temp_store`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 2 {
		t.Errorf("temp_store %d, want 2 (memory)", mode)
	}
}
