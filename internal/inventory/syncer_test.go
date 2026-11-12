// SPDX-License-Identifier: Apache-2.0

package inventory_test

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

type fakeCollector struct {
	mu        sync.Mutex
	workloads []inventory.Workload
	fail      error
	lists     atomic.Int32
	events    chan inventory.Event
}

func (f *fakeCollector) Kind() inventory.Kind { return inventory.KindContainer }

func (f *fakeCollector) List(context.Context) (inventory.Snapshot, error) {
	f.lists.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return inventory.Snapshot{}, f.fail
	}
	return inventory.Snapshot{Host: inventory.HostInfo{Name: "nas", OS: "linux", Arch: "arm64"}, Workloads: append([]inventory.Workload(nil), f.workloads...)}, nil
}

func (f *fakeCollector) Watch(ctx context.Context) <-chan inventory.Event {
	out := make(chan inventory.Event)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-f.events:
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

func (f *fakeCollector) set(ws []inventory.Workload, fail error) {
	f.mu.Lock()
	f.workloads, f.fail = ws, fail
	f.mu.Unlock()
}

func ctr(id, name string) inventory.Workload {
	return inventory.Workload{Kind: inventory.KindContainer, RuntimeID: id, Name: name, State: "running",
		Container: &inventory.Container{ImageRef: name + ":1", ImageID: "sha256:" + id}}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSyncerSyncsOnStartEventsAndRecovers(t *testing.T) {
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	col := &fakeCollector{events: make(chan inventory.Event)}
	col.set([]inventory.Workload{ctr("a1", "immich")}, nil)

	var changes atomic.Int32
	svc := inventory.NewSyncer(inventory.SyncerConfig{
		HostID: inventory.LocalHostID, HostKind: inventory.HostDocker, Source: inventory.SourceLocal,
		Collector: col, Store: st, Log: slog.New(slog.DiscardHandler),
		Resync: time.Hour, Debounce: 30 * time.Millisecond,
		OnChange: func(inventory.Changes) { changes.Add(1) },
	})
	if !errors.Is(svc.Ready(), inventory.ErrNotSynced) {
		t.Fatalf("ready before sync: %v", svc.Ready())
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()

	waitFor(t, "initial sync", func() bool { return svc.Ready() == nil })
	ws, err := st.Workloads(t.Context(), store.WorkloadFilter{})
	if err != nil || len(ws) != 1 {
		t.Fatalf("after initial sync: %d, %v", len(ws), err)
	}
	h, err := st.Host(t.Context(), inventory.LocalHostID)
	if err != nil || h.Name != "nas" || h.Arch != "arm64" {
		t.Fatalf("host: %+v, %v", h, err)
	}

	// A burst of events is debounced into a single sync.
	col.set([]inventory.Workload{ctr("a1", "immich"), ctr("b2", "jellyfin")}, nil)
	before := col.lists.Load()
	for range 5 {
		col.events <- inventory.Event{Reason: "container start"}
	}
	waitFor(t, "event sync", func() bool {
		ws, _ := st.Workloads(t.Context(), store.WorkloadFilter{})
		return len(ws) == 2
	})
	time.Sleep(100 * time.Millisecond)
	if n := col.lists.Load() - before; n != 1 {
		t.Errorf("burst caused %d syncs, want 1", n)
	}

	// Collector failure: not ready, retried, recovers.
	col.set(nil, errors.New("proxy unreachable"))
	svc.Trigger()
	waitFor(t, "failure surfaced", func() bool { return svc.Ready() != nil })
	col.set([]inventory.Workload{ctr("b2", "jellyfin")}, nil)
	waitFor(t, "recovery", func() bool { return svc.Ready() == nil })
	ws, _ = st.Workloads(t.Context(), store.WorkloadFilter{})
	if len(ws) != 1 || ws[0].Name != "jellyfin" {
		t.Fatalf("after recovery: %+v", ws)
	}

	// Unchanged inventory does not call OnChange.
	n := changes.Load()
	svc.Trigger()
	time.Sleep(100 * time.Millisecond)
	if changes.Load() != n {
		t.Error("OnChange called without changes")
	}
	if n != 3 {
		t.Errorf("OnChange calls: %d, want 3", n)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
