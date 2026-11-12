// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"testing"

	"github.com/bifrost0x/varde/internal/catalog"
)

const testIndex = "ghcr.io/a/b\tgithub.com/a/b\tghcr,readme\nghcr.io/c/d\tgithub.com/c/d\thub\n"

func (f *fixture) publishIndex(seq int64, index string) {
	f.t.Helper()
	_, err := WriteSnapshot(f.pub, Snapshot{Channel: f.channel, Sequence: seq, CreatedAt: f.now, ExpiresAt: f.now.Add(7 * 24 * 3600e9),
		CatalogVersion: "test", Catalog: []catalog.Entry{{Name: "immich.yaml", Data: immichEntry}},
		Index: []byte(index), Shards: 4}, f.feedKey)
	if err != nil {
		f.t.Fatal(err)
	}
}

func TestIndexBlobActivates(t *testing.T) {
	f := newFixture(t)
	if f.client.Index() != nil {
		t.Fatal("index before any package")
	}
	f.publishIndex(5, testIndex)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	e, ok := f.client.Index().Lookup("ghcr.io/a/b")
	if !ok || e.Repo != "github.com/a/b" {
		t.Fatalf("lookup = %+v, %v", e, ok)
	}
	// A restart loads it again from the cache.
	again := &Client{Mirrors: f.client.Mirrors, Dir: f.client.Dir, Store: f.st, Catalog: f.client.Catalog,
		Log: f.client.Log, Now: f.client.Now, AllowDevelopment: true}
	if err := again.LoadActive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Index().Lookup("ghcr.io/c/d"); !ok {
		t.Fatal("index not loaded with the installed package")
	}
	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err := f.client.Deactivate(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if f.client.Index() != nil {
		t.Fatal("index survives leaving the package")
	}
}

func TestBadIndexRefusesUpdate(t *testing.T) {
	f := newFixture(t)
	f.publishIndex(5, testIndex)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	f.publishIndex(6, "not\ta\tvalid\ttable\trow\textra\n")
	if _, err := f.update(); err == nil {
		t.Fatal("a package with a malformed index was installed")
	}
	if _, ok := f.client.Index().Lookup("ghcr.io/a/b"); !ok {
		t.Fatal("previous index lost")
	}
	st, err := f.st.FeedState(context.Background())
	if err != nil || st.Sequence != 5 {
		t.Fatalf("state = %+v, %v; want sequence 5", st, err)
	}
}

func TestPackageWithoutIndex(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	if f.client.Index() != nil {
		t.Fatal("index without an index blob")
	}
}

// A package without an index replaces one with an index: the old table
// must not stay in use.
func TestIndexDroppedWithNewPackage(t *testing.T) {
	f := newFixture(t)
	f.publishIndex(5, testIndex)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	f.publish(6, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	if f.client.Index() != nil {
		t.Fatal("index of the replaced package still in use")
	}
}
