// SPDX-License-Identifier: Apache-2.0

package datapkg

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

type fixture struct {
	t       *testing.T
	dir     string
	feedKey ed25519.PrivateKey
	st      *store.Store
	src     *feed.Source
	now     time.Time
	changed atomic.Int64
	mgr     *Manager
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), now: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
	rootKey, err := feed.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if f.feedKey, err = feed.NewKey(); err != nil {
		t.Fatal(err)
	}
	root, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: f.now.Add(365 * 24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{f.feedKey.Public().(ed25519.PublicKey)},
		RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := feed.WriteRoot(f.dir, 1, root); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if f.st, err = store.Open(ctx, filepath.Join(t.TempDir(), "v.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.st.Close() })
	fetch, err := feed.NewFetcher("file://"+filepath.ToSlash(f.dir), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cat, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	client := &feed.Client{Dir: filepath.Join(t.TempDir(), "feed"), Store: f.st, Catalog: catalog.NewLive(cat),
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return f.now }, AllowDevelopment: true,
		Pick: func() feed.Channel { return feed.Channel{Name: feed.ChannelPackage, Mirrors: []feed.Fetcher{fetch}} }}
	if _, err := client.Init(root); err != nil {
		t.Fatal(err)
	}
	f.src = &feed.Source{Client: client, Store: f.st}
	f.mgr = New(Options{Source: f.src, Store: f.st, OnChange: func() { f.changed.Add(1) }})
	return f
}

func (f *fixture) publish(seq int64) {
	f.t.Helper()
	_, err := feed.WriteSnapshot(f.dir, feed.Snapshot{Channel: feed.ChannelPackage, Sequence: seq, CreatedAt: f.now.Add(-time.Hour), ExpiresAt: f.now.Add(7 * 24 * time.Hour),
		CatalogVersion: "test"}, f.feedKey)
	if err != nil {
		f.t.Fatal(err)
	}
}

func TestStatusStates(t *testing.T) {
	ctx := context.Background()
	if st := New(Options{Unavailable: "No trust root."}).Status(ctx); st.Available || st.Reason != "No trust root." {
		t.Fatalf("unavailable: %+v", st)
	}
	var none *Manager
	if st := none.Status(ctx); st.Available {
		t.Fatalf("nil manager: %+v", st)
	}
	if _, err := none.UpdateNow(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil manager update: %v", err)
	}

	f := newFixture(t)
	if st := f.mgr.Status(ctx); !st.Available || st.Channel != "" || st.Sequence != 0 || !st.CheckedAt.IsZero() {
		t.Fatalf("nothing installed: %+v", st)
	}
	f.publish(7)
	if res, err := f.mgr.UpdateNow(ctx); err != nil || !res.Applied {
		t.Fatalf("update: %+v, %v", res, err)
	}
	st := f.mgr.Status(ctx)
	if st.Channel != feed.ChannelPackage || st.Sequence != 7 || !st.BuiltAt.Equal(f.now.Add(-time.Hour)) || !st.CheckedAt.Equal(f.now) || st.LastError != "" {
		t.Fatalf("installed: %+v", st)
	}

	// The mirror goes away: the installed package stays, the error shows.
	if err := os.Remove(filepath.Join(f.dir, "v1", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	if _, err := f.mgr.UpdateNow(ctx); err == nil {
		t.Fatal("update from a broken mirror succeeded")
	}
	st = f.mgr.Status(ctx)
	if st.Sequence != 7 || st.LastError == "" || st.TooOld || !st.CheckedAt.Equal(f.now) {
		t.Fatalf("failed check: %+v", st)
	}
}

func TestStatusTooOld(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.publish(7)
	if _, err := f.mgr.UpdateNow(ctx); err != nil {
		t.Fatal(err)
	}
	// What a check records when the package is in a newer format.
	err := f.st.PutSourceState(ctx, store.SourceState{Source: "feed", Key: "manifest", LastAttempt: f.now,
		LastError: "https://mirror: manifest: schema 2, this version reads 1: " + feed.ErrTooOld.Error()})
	if err != nil {
		t.Fatal(err)
	}
	if st := f.mgr.Status(ctx); !st.TooOld || st.Sequence != 7 {
		t.Fatalf("status = %+v", st)
	}
}

func TestUpdateNowSerialised(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.publish(7)
	var wg sync.WaitGroup
	var applied, failed atomic.Int64
	for range 8 {
		wg.Go(func() {
			res, err := f.mgr.UpdateNow(ctx)
			if err != nil {
				failed.Add(1)
			}
			if res.Applied {
				applied.Add(1)
			}
		})
	}
	wg.Wait()
	if failed.Load() != 0 || applied.Load() != 1 {
		t.Fatalf("applied %d, failed %d; want 1 and 0", applied.Load(), failed.Load())
	}
	// OnChange only for the update that installed something.
	if n := f.changed.Load(); n != 1 {
		t.Fatalf("OnChange called %d times, want 1", n)
	}
	if _, err := f.mgr.UpdateNow(ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.changed.Load(); n != 1 {
		t.Fatalf("OnChange after an unchanged check: %d calls", n)
	}
}

func TestNotInUseIsUnavailable(t *testing.T) {
	f := newFixture(t)
	f.src.Client.InUse = func() bool { return false }
	if _, err := f.mgr.UpdateNow(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}
