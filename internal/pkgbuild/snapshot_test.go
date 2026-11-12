// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

func (f *fixture) snapshot() feed.Snapshot {
	f.t.Helper()
	snap, err := Snapshot(context.Background(), f.st, []catalog.Entry{{Name: "widget.yaml", Data: widgetEntry}}, f.index, f.repos, f.now, 7*24*time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	return snap
}

func TestSnapshotBothIDs(t *testing.T) {
	f := newFixture(t)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	snap := f.snapshot()
	per := map[string]int{}
	for _, a := range snap.Advisories {
		per[a.AppID]++
	}
	if per["widget"] != 2 || per["gh-acme-widget"] != 2 || per["gh-other-tool"] != 1 || len(per) != 3 {
		t.Fatalf("advisories per app = %v", per)
	}
	if snap.Channel != feed.ChannelPackage || snap.Sequence != f.now.Unix() || !snap.ExpiresAt.Equal(f.now.Add(7*24*time.Hour)) {
		t.Fatalf("snapshot header: %+v", snap)
	}
	if len(snap.KEV) != 120 || snap.KEV[0].DateAdded != "2025-06-01" || len(snap.EPSS) != 3 {
		t.Fatalf("kev %d, epss %d", len(snap.KEV), len(snap.EPSS))
	}
	if !bytes.Equal(snap.Index, []byte(testIndex)) {
		t.Fatalf("index = %q", snap.Index)
	}
	// A score of a CVE that left the package stays behind.
	if err := f.st.UpsertEPSS(context.Background(), []store.EPSSEntry{{CVE: "CVE-2020-0001", Score: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if got := f.snapshot(); len(got.EPSS) != 3 {
		t.Fatalf("EPSS of a CVE outside the package was published: %d", len(got.EPSS))
	}
}

func TestSnapshotDeterministicAndVerifies(t *testing.T) {
	f := newFixture(t)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	rootKey, _ := feed.NewKey()
	feedKey, _ := feed.NewKey()
	root, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: f.now.Add(365 * 24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{feedKey.Public().(ed25519.PublicKey)},
		RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	var manifests [][]byte
	var dir string
	for range 2 {
		dir = t.TempDir()
		if err := feed.WriteRoot(dir, 1, root); err != nil {
			t.Fatal(err)
		}
		if _, err := feed.WriteSnapshot(dir, f.snapshot(), feedKey); err != nil {
			t.Fatal(err)
		}
		m, err := os.ReadFile(filepath.Join(dir, "v1", "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, m)
	}
	if !bytes.Equal(manifests[0], manifests[1]) {
		t.Fatal("two builds of the same store and clock differ")
	}
	// The real client installs it on the package channel.
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	fetch, err := feed.NewFetcher("file://"+filepath.ToSlash(dir), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	client := &feed.Client{Dir: filepath.Join(t.TempDir(), "feed"), Store: st, Catalog: catalog.NewLive(base), Log: slog.New(slog.DiscardHandler),
		Now: func() time.Time { return f.now }, AllowDevelopment: true,
		Pick: func() feed.Channel { return feed.Channel{Name: feed.ChannelPackage, Mirrors: []feed.Fetcher{fetch}} }}
	if _, err := client.Init(root); err != nil {
		t.Fatal(err)
	}
	res, err := client.Update(context.Background())
	if err != nil || !res.Applied {
		t.Fatalf("client: %+v, %v", res, err)
	}
	if _, ok := client.Index().Lookup("ghcr.io/acme/widget"); !ok {
		t.Fatal("index not in the installed package")
	}
	if recs, _ := st.Advisories(context.Background(), "widget"); len(recs) != 2 {
		t.Fatalf("advisories of the catalog app = %d", len(recs))
	}
}

func TestGuard(t *testing.T) {
	prev := Counts{Sequence: 100, Advisories: 100, KEV: 1000, EPSS: 500, Index: 200}
	ok := Counts{Sequence: 200, Advisories: 100, KEV: 1000, EPSS: 500, Index: 200}
	with := func(change func(*Counts)) Counts { c := ok; change(&c); return c }
	for _, tc := range []struct {
		name    string
		stats   Stats
		have    bool
		cur     Counts
		force   bool
		refused bool
	}{
		{"first build, no baseline", Stats{Repos: 100}, false, Counts{Sequence: 1}, false, false},
		{"first build, nothing at all", Stats{}, false, Counts{}, false, false},
		{"unchanged", Stats{Repos: 100}, true, ok, false, false},
		{"5 % failed", Stats{Repos: 100, Failed: 5}, true, ok, false, false},
		{"6 % failed", Stats{Repos: 100, Failed: 6}, true, ok, false, true},
		{"6 % failed, forced", Stats{Repos: 100, Failed: 6}, true, ok, true, true},
		{"6 % failed, first build", Stats{Repos: 100, Failed: 6}, false, ok, false, true},
		{"advisories to 90", Stats{Repos: 100}, true, with(func(c *Counts) { c.Advisories = 90 }), false, false},
		{"advisories to 89", Stats{Repos: 100}, true, with(func(c *Counts) { c.Advisories = 89 }), false, true},
		{"advisories to 89, forced", Stats{Repos: 100}, true, with(func(c *Counts) { c.Advisories = 89 }), true, false},
		{"KEV to 899", Stats{Repos: 100}, true, with(func(c *Counts) { c.KEV = 899 }), false, true},
		{"index to 179", Stats{Repos: 100}, true, with(func(c *Counts) { c.Index = 179 }), false, true},
		{"EPSS to 0", Stats{Repos: 100}, true, with(func(c *Counts) { c.EPSS = 0 }), false, false},
		{"sequence not above", Stats{Repos: 100}, true, with(func(c *Counts) { c.Sequence = 100 }), false, true},
		{"sequence not above, forced", Stats{Repos: 100}, true, with(func(c *Counts) { c.Sequence = 100 }), true, true},
	} {
		err := Guard(tc.stats, prev, tc.have, tc.cur, tc.force)
		if (err != nil) != tc.refused || (err != nil && !errors.Is(err, ErrRefused)) {
			t.Errorf("%s: err = %v, want refused = %v", tc.name, err, tc.refused)
		}
	}
}

func TestCountsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, have, err := ReadCounts(dir); err != nil || have {
		t.Fatalf("empty directory: have %v, %v", have, err)
	}
	if _, have, err := ReadCounts(""); err != nil || have {
		t.Fatalf("no directory: have %v, %v", have, err)
	}
	want := Counts{Sequence: 7, Advisories: 3, KEV: 2, EPSS: 1, Index: 9}
	if err := WriteCounts(dir, want); err != nil {
		t.Fatal(err)
	}
	if got, have, err := ReadCounts(dir); err != nil || !have || got != want {
		t.Fatalf("read back %+v, %v, %v", got, have, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stats.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCounts(dir); err == nil {
		t.Fatal("a broken baseline was read")
	}
}
