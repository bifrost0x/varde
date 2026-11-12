// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"archive/tar"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

const immichEntry = `id: immich
name: Immich
homepage: https://immich.app
images: [{match: ghcr.io/immich-app/immich-server}]
version: {scheme: semver}
advisories: {coverage: full, github_repos: [immich-app/immich]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`

type fixture struct {
	t        *testing.T
	pub      string // published feed directory
	rootKey  ed25519.PrivateKey
	feedKey  ed25519.PrivateKey
	rootData []byte
	st       *store.Store
	client   *Client
	now      time.Time
	// channel is written into the manifests publish makes.
	channel string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, pub: t.TempDir(), now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	var err error
	if f.rootKey, err = NewKey(); err != nil {
		t.Fatal(err)
	}
	if f.feedKey, err = NewKey(); err != nil {
		t.Fatal(err)
	}
	f.rootData = f.root(1, f.feedKey, f.rootKey)
	if err := WriteRoot(f.pub, 1, f.rootData); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f.st, err = store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.st.Close() })
	fetch, err := NewFetcher("file://"+filepath.ToSlash(f.pub), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cat, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	f.client = &Client{Mirrors: []Fetcher{fetch}, Dir: filepath.Join(t.TempDir(), "feed"), Store: f.st,
		Catalog: catalog.NewLive(cat), Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return f.now },
		AllowDevelopment: true}
	if _, err := f.client.Init(f.rootData); err != nil {
		t.Fatal(err)
	}
	return f
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func (f *fixture) root(version int64, feedKey ed25519.PrivateKey, signers ...ed25519.PrivateKey) []byte {
	f.t.Helper()
	rootKey := signers[len(signers)-1]
	data, err := SignRoot(RootSpec{Version: version, Expires: f.now.Add(365 * 24 * time.Hour), Environment: EnvDevelopment,
		RootKeys: []ed25519.PublicKey{pub(rootKey)}, FeedKeys: []ed25519.PublicKey{pub(feedKey)},
		RootThreshold: 1, FeedThreshold: 1}, signers...)
	if err != nil {
		f.t.Fatal(err)
	}
	return data
}

func (f *fixture) publish(seq int64, advisories int, signers ...ed25519.PrivateKey) {
	f.t.Helper()
	if len(signers) == 0 {
		signers = []ed25519.PrivateKey{f.feedKey}
	}
	var lines []AdvisoryLine
	for i := range advisories {
		lines = append(lines, AdvisoryLine{AppID: "immich", CVSS: 9.1, Severity: "critical", OSV: advisory.Vulnerability{
			SchemaVersion: "1.6.0", ID: "GHSA-test-" + string(rune('a'+i)), Modified: f.now,
		}})
	}
	_, err := WriteSnapshot(f.pub, Snapshot{Channel: f.channel, Sequence: seq, CreatedAt: f.now, ExpiresAt: f.now.Add(7 * 24 * time.Hour),
		CatalogVersion: "test", Catalog: []catalog.Entry{{Name: "immich.yaml", Data: immichEntry}}, Advisories: lines,
		KEV: []KEVLine{{CVE: "CVE-2026-0001", DateAdded: "2026-11-01"}}, EPSS: []EPSSLine{{CVE: "CVE-2026-0001", Score: 0.5, Percentile: 0.9, Date: "2026-11-08"}},
		Shards: 4}, signers...)
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) update() (Result, error) { return f.client.Update(context.Background()) }

func (f *fixture) feedAdvisories() int {
	recs, err := f.st.Advisories(context.Background(), "immich")
	if err != nil {
		f.t.Fatal(err)
	}
	return len(recs)
}

func TestValidFeedIsApplied(t *testing.T) {
	f := newFixture(t)
	f.publish(1, 3)
	res, err := f.update()
	if err != nil || !res.Applied || res.Sequence != 1 {
		t.Fatalf("update: %+v %v", res, err)
	}
	if f.feedAdvisories() != 3 {
		t.Fatalf("advisories: %d", f.feedAdvisories())
	}
	if app, ok := f.client.Catalog.Current().App("immich"); !ok || app.Origin != catalog.OriginFeed {
		t.Fatal("feed catalog not active")
	}
	kev, _ := f.st.KEV(context.Background())
	if !kev["CVE-2026-0001"] {
		t.Fatal("kev not applied")
	}
	// Unchanged manifest: verified again, nothing applied.
	f.now = f.now.Add(time.Hour)
	res, err = f.update()
	if err != nil || !res.Unchanged {
		t.Fatalf("second update: %+v %v", res, err)
	}
	st, _ := f.st.FeedState(context.Background())
	if !st.VerifiedAt.Equal(f.now) {
		t.Fatalf("verified_at not refreshed: %v", st.VerifiedAt)
	}
	// A newer sequence replaces the data.
	f.publish(2, 1)
	if res, err := f.update(); err != nil || !res.Applied || f.feedAdvisories() != 1 {
		t.Fatalf("sequence 2: %+v %v %d", res, err, f.feedAdvisories())
	}
}

func TestBadSignatureRejected(t *testing.T) {
	f := newFixture(t)
	other, _ := NewKey()
	f.publish(1, 1, other)
	if _, err := f.update(); !errors.Is(err, ErrSignature) {
		t.Fatalf("foreign key: %v", err)
	}
	// Tampered manifest with the original signature.
	f.publish(1, 1)
	path := filepath.Join(f.pub, "v1", "manifest.json")
	data, _ := os.ReadFile(path)
	_ = os.WriteFile(path, []byte(strings.Replace(string(data), `"catalog_version": "test"`, `"catalog_version": "evil"`, 1)), 0o644)
	if _, err := f.update(); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered manifest: %v", err)
	}
	if f.feedAdvisories() != 0 {
		t.Fatal("data applied from an invalid feed")
	}
}

func TestRollbackAndFreeze(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 2)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	// Older sequence.
	f.publish(4, 0)
	if _, err := f.update(); !errors.Is(err, ErrRollback) {
		t.Fatalf("older sequence: %v", err)
	}
	// Same sequence, different content.
	f.publish(5, 1)
	if _, err := f.update(); !errors.Is(err, ErrRollback) {
		t.Fatalf("reused sequence: %v", err)
	}
	if f.feedAdvisories() != 2 {
		t.Fatal("rejected feed changed data")
	}
	// Freeze: the mirror keeps serving a manifest that has expired.
	f.publish(6, 2)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(8 * 24 * time.Hour)
	if _, err := f.update(); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired manifest: %v", err)
	}
}

func TestBlobIntegrity(t *testing.T) {
	f := newFixture(t)
	data, err := WriteSnapshot(f.pub, Snapshot{Sequence: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour),
		Catalog: []catalog.Entry{{Name: "immich.yaml", Data: immichEntry}}}, f.feedKey)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	_ = json.Unmarshal(data, &m)
	blob := filepath.Join(f.pub, "v1", "blobs", "sha256", m.Blobs[0].SHA256)
	good, _ := os.ReadFile(blob)

	// Corrupted content.
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xff
	_ = os.WriteFile(blob, bad, 0o644)
	if _, err := f.update(); !errors.Is(err, ErrMismatch) {
		t.Fatalf("corrupt blob: %v", err)
	}
	// Partial download.
	_ = os.WriteFile(blob, good[:len(good)/2], 0o644)
	if _, err := f.update(); !errors.Is(err, ErrMismatch) {
		t.Fatalf("partial blob: %v", err)
	}
	// Oversized response is cut at the declared size.
	_ = os.WriteFile(blob, append(good, make([]byte, 1<<16)...), 0o644)
	if _, err := f.update(); err == nil {
		t.Fatal("oversized blob accepted")
	}
	_ = os.WriteFile(blob, good, 0o644)
	if _, err := f.update(); err != nil {
		t.Fatalf("intact blob: %v", err)
	}
}

// TestDecompressionBomb: a correctly hashed blob that expands beyond its
// declared size is stopped at the limit.
func TestDecompressionBomb(t *testing.T) {
	enc, _ := zstd.NewWriter(nil)
	packed := enc.EncodeAll(make([]byte, 64<<20), nil)
	_ = enc.Close()
	b := Blob{Name: "catalog", Compression: "zstd", Size: int64(len(packed)), UncompressedSize: 1024}
	if _, err := unpack(b, packed); !errors.Is(err, ErrMismatch) && err == nil {
		t.Fatal("bomb unpacked")
	}
	// The manifest-level cap refuses absurd declared sizes up front.
	f := newFixture(t)
	f.client.MaxUnpacked = 1024
	f.publish(1, 50)
	if _, err := f.update(); err == nil || !strings.Contains(err.Error(), "exceed the limit") && !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("total size cap: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	f := newFixture(t)
	f.publish(1, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	// Root 2 rotates both keys; it is signed by the old and the new root key.
	newRoot, _ := NewKey()
	newFeed, _ := NewKey()
	r2 := f.root(2, newFeed, f.rootKey, newRoot)
	if err := WriteRoot(f.pub, 2, r2); err != nil {
		t.Fatal(err)
	}
	f.publish(2, 2, newFeed)
	if _, err := f.update(); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	// The old feed key no longer counts.
	f.publish(3, 1, f.feedKey)
	if _, err := f.update(); !errors.Is(err, ErrSignature) {
		t.Fatalf("old feed key after rotation: %v", err)
	}
	// Root 3 signed only by a key the trusted root does not know.
	rogue, _ := NewKey()
	rogueFeed, _ := NewKey()
	if err := WriteRoot(f.pub, 3, f.root(3, rogueFeed, rogue)); err != nil {
		t.Fatal(err)
	}
	f.publish(3, 1, rogueFeed)
	if _, err := f.update(); !errors.Is(err, ErrSignature) {
		t.Fatalf("unendorsed root: %v", err)
	}
	// Root chain over several versions: 3 and 4 published, client at 2.
	r3 := f.root(3, newFeed, newRoot)
	r4 := f.root(4, newFeed, newRoot)
	_ = WriteRoot(f.pub, 3, r3)
	_ = WriteRoot(f.pub, 4, r4)
	f.publish(4, 1, newFeed)
	if _, err := f.update(); err != nil {
		t.Fatalf("root chain: %v", err)
	}
	if r, _ := f.client.trusted(); r.Version != 4 {
		t.Fatalf("trusted root version %d", r.Version)
	}
}

func TestMirrorFailover(t *testing.T) {
	f := newFixture(t)
	f.publish(1, 2)
	down := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	bad, _ := NewFetcher("file:///nonexistent-feed-dir", nil, nil)
	f.client.Mirrors = append([]Fetcher{bad}, f.client.Mirrors...)
	res, err := f.update()
	if err != nil || !res.Applied || !strings.HasPrefix(res.Mirror, "file://") || strings.Contains(res.Mirror, "nonexistent") {
		t.Fatalf("failover: %+v %v", res, err)
	}
}

func TestTarballImport(t *testing.T) {
	f := newFixture(t)
	f.publish(1, 2)
	tarPath := filepath.Join(t.TempDir(), "feed.tar")
	out, _ := os.Create(tarPath)
	tw := tar.NewWriter(out)
	_ = filepath.Walk(filepath.Join(f.pub, "v1"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(f.pub, p)
		data, _ := os.ReadFile(p)
		_ = tw.WriteHeader(&tar.Header{Name: "./" + filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
		return nil
	})
	_ = tw.Close()
	_ = out.Close()
	fetch, err := NewFetcher("file://"+filepath.ToSlash(tarPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.client.Mirrors = []Fetcher{fetch}
	if res, err := f.update(); err != nil || !res.Applied {
		t.Fatalf("tarball: %+v %v", res, err)
	}
}

// TestCrashBetweenDatabaseAndFiles: the database was updated but the active
// manifest file was not; the next run reinstalls instead of trusting the
// stale file, and the restart path loads the verified feed.
func TestCrashBetweenDatabaseAndFiles(t *testing.T) {
	f := newFixture(t)
	f.publish(1, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	f.publish(2, 3)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	// Simulate the crash: put the previous manifest back as active.
	for _, n := range []string{activeManifest, activeSig} {
		data, _ := os.ReadFile(filepath.Join(f.client.Dir, previousDir, n))
		_ = os.WriteFile(filepath.Join(f.client.Dir, n), data, 0o600)
	}
	res, err := f.update()
	if err != nil || !res.Applied || res.Sequence != 2 {
		t.Fatalf("reinstall after crash: %+v %v", res, err)
	}
	// Restart: a new client loads the active feed without network.
	cat, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	again := &Client{Dir: f.client.Dir, Store: f.st, Catalog: catalog.NewLive(cat), Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return f.now }, AllowDevelopment: true}
	if err := again.LoadActive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Catalog.Current().App("immich"); !ok {
		t.Fatal("restart did not load the feed catalog")
	}
}

func TestFetcherPathsAndSchemes(t *testing.T) {
	for _, bad := range []string{"http://feed.example.org", "ftp://x", "file://relative/x", "https://user@feed.example.org", "https://feed.example.org/?q=1"} {
		if _, err := NewFetcher(bad, nil, nil); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	d, _ := NewFetcher("file:///tmp", nil, nil)
	for _, p := range []string{"v1/../etc/passwd", "v1/blobs/sha256/../../x", "/etc/passwd", "v1/manifest.json/.."} {
		if _, _, _, err := d.Get(context.Background(), p, "", 10); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("path %q not rejected: %v", p, err)
		}
	}
}

func TestDevelopmentRootNeedsOptIn(t *testing.T) {
	f := newFixture(t)
	cat, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	strict := &Client{Dir: filepath.Join(t.TempDir(), "feed"), Store: f.st, Catalog: catalog.NewLive(cat), Log: slog.New(slog.DiscardHandler)}
	if _, err := strict.Init(f.rootData); !errors.Is(err, ErrDevelopmentRoot) {
		t.Fatalf("development root accepted without opt-in: %v", err)
	}
}
