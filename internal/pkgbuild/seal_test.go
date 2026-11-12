// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

func testRoot(t *testing.T, now time.Time) (*feed.Root, ed25519.PrivateKey) {
	t.Helper()
	rootKey, _ := feed.NewKey()
	feedKey, _ := feed.NewKey()
	data, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: now.Add(365 * 24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{feedKey.Public().(ed25519.PublicKey)},
		RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := feed.VerifyRoot(data, now)
	if err != nil {
		t.Fatal(err)
	}
	return root, feedKey
}

// The builder's store and its baseline travel on the published branch,
// which more people and tokens can write than can sign. Both are used
// only when the feed key signed them.
func TestSealedFiles(t *testing.T) {
	now := time.Date(2026, 11, 11, 2, 17, 0, 0, time.UTC)
	root, key := testRoot(t, now)
	_, otherKey := testRoot(t, now)
	dir := t.TempDir()
	path := filepath.Join(dir, "builder.db")
	if err := os.WriteFile(path, []byte("store content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, "store", root, now); err == nil {
		t.Fatal("a file without a signature verified")
	}
	if err := Seal(path, "store", key); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, "store", root, now); err != nil {
		t.Fatalf("sealed file: %v", err)
	}
	// Signed for another purpose, by another key, or changed afterwards.
	if err := Verify(path, "counts", root, now); err == nil {
		t.Error("a signature for another purpose verified")
	}
	if err := os.WriteFile(path, []byte("store content, tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, "store", root, now); err == nil {
		t.Error("a changed file verified")
	}
	if err := Seal(path, "store", otherKey); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, "store", root, now); err == nil {
		t.Error("a signature of a key the root does not list verified")
	}
	// A symlink is not followed: it could point at anything the builder can read.
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symlinks here")
	}
	if err := Seal(target, "store", key); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target+".sig", link+".sig"); err != nil {
		t.Fatal(err)
	}
	if err := Verify(link, "store", root, now); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("a symlink verified: %v", err)
	}
}

func TestReposRefuseAnIDCollision(t *testing.T) {
	f := newFixture(t)
	// "a-b/c" and "a/b-c" both derive gh-a-b-c.
	table, err := applists.Unmarshal([]byte("ghcr.io/a-b/c\tgithub.com/a-b/c\tghcr,readme\nghcr.io/a/b-c\tgithub.com/a/b-c\tghcr,readme\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Repos(f.cat, table); err == nil || !strings.Contains(err.Error(), "gh-a-b-c") {
		t.Fatalf("err = %v", err)
	}
}

// Records stored under an ID by another repository never go out under it.
func TestSnapshotOnlyOwnRecords(t *testing.T) {
	f := newFixture(t)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	foreign := []store.AdvisoryRecord{{AppID: "gh-acme-widget", Vuln: advisory.Vulnerability{SchemaVersion: "1.6.0", ID: "GHSA-evil-evil-9999", Modified: f.now}}}
	if err := f.st.ReplaceAdvisories(context.Background(), "gh-acme-widget", "github:someone/else", foreign, f.now); err != nil {
		t.Fatal(err)
	}
	for _, a := range f.snapshot().Advisories {
		if a.OSV.ID == "GHSA-evil-evil-9999" {
			t.Fatalf("a record of another repository was published under %s", a.AppID)
		}
	}
}

// KEV and EPSS are fetched with every build, also one that runs earlier in
// the day than yesterday's.
func TestCollectAlwaysRefreshesEnrichment(t *testing.T) {
	f := newFixture(t)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	kevRequests := func() int {
		f.up.mu.Lock()
		defer f.up.mu.Unlock()
		return f.up.kev
	}
	if kevRequests() != 1 {
		t.Fatalf("kev requests = %d", kevRequests())
	}
	f.now = f.now.Add(23*time.Hour + 55*time.Minute)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	if kevRequests() != 2 {
		t.Fatalf("kev requests on the second day = %d, want 2", kevRequests())
	}
}

// A repository a reviewed catalog entry names must exist: a 404 there is a
// mistake in the catalog, not "no advisories".
func TestCatalogRepositoryMustExist(t *testing.T) {
	f := newFixture(t)
	f.up.status["acme/widget"] = 404
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 1 || len(stats.Failing) != 1 || !strings.HasPrefix(stats.Failing[0], "acme/widget") {
		t.Fatalf("stats = %+v", stats)
	}
}
