// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/store"
)

var (
	testIndexDigest    = "sha256:" + strings.Repeat("a", 64)
	testManifestDigest = "sha256:" + strings.Repeat("b", 64)
)

func testRelease(appID string, arch string) ReleaseLine {
	return ReleaseLine{AppID: appID, Image: "ghcr.io/immich-app/immich-server", Tag: "v1.120.0", Version: "1.120.0",
		IndexDigest: testIndexDigest, Platform: ReleasePlatform{OS: "linux", Arch: arch}, ManifestDigest: testManifestDigest,
		Read: time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC), Distro: "debian-12", OS: "Debian GNU/Linux 12 (bookworm)",
		Packages: []inventory.Package{{Manager: "dpkg", Name: "openssl", Version: "3.0.15-1~deb12u1", Distro: "debian-12", Source: "openssl"}}}
}

// storedReleases returns the release lines the store keeps for an app's
// test image, where the pages read them.
func (f *fixture) storedReleases(appID string) []ReleaseLine {
	f.t.Helper()
	rows, err := f.st.ReleasePackagesFor(context.Background(), appID, "ghcr.io/immich-app/immich-server")
	if err != nil {
		f.t.Fatal(err)
	}
	var out []ReleaseLine
	for _, b := range rows {
		var l ReleaseLine
		if err := json.Unmarshal(b, &l); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, l)
	}
	return out
}

func TestReleaseLineValidation(t *testing.T) {
	if err := testRelease("immich", "amd64").Validate(); err != nil {
		t.Fatalf("valid line: %v", err)
	}
	// A single-platform image has no index digest.
	single := testRelease("immich", "amd64")
	single.IndexDigest = ""
	if err := single.Validate(); err != nil {
		t.Fatalf("line without index: %v", err)
	}
	many := make([]inventory.Package, 20001)
	for i := range many {
		many[i] = inventory.Package{Manager: "dpkg", Name: "p", Version: "1"}
	}
	for name, change := range map[string]func(l *ReleaseLine){
		"bad app id":          func(l *ReleaseLine) { l.AppID = "Immich!" },
		"bad image":           func(l *ReleaseLine) { l.Image = "ghcr.io/Immich/Server:latest" },
		"unnormalised image":  func(l *ReleaseLine) { l.Image = "grafana/grafana" },
		"empty tag":           func(l *ReleaseLine) { l.Tag = "" },
		"bad tag":             func(l *ReleaseLine) { l.Tag = "v1 rm" },
		"empty version":       func(l *ReleaseLine) { l.Version = "" },
		"long version":        func(l *ReleaseLine) { l.Version = strings.Repeat("1", 129) },
		"version charset":     func(l *ReleaseLine) { l.Version = "1.0 <b>" },
		"long source version": func(l *ReleaseLine) { l.Packages[0].SourceVersion = strings.Repeat("1", 129) },
		"bad index digest":    func(l *ReleaseLine) { l.IndexDigest = "sha256:abc" },
		"bad manifest digest": func(l *ReleaseLine) { l.ManifestDigest = "md5:" + strings.Repeat("b", 64) },
		"no manifest digest":  func(l *ReleaseLine) { l.ManifestDigest = "" },
		"no platform":         func(l *ReleaseLine) { l.Platform = ReleasePlatform{} },
		"bad variant":         func(l *ReleaseLine) { l.Platform.Variant = "V8;" },
		"no read time":        func(l *ReleaseLine) { l.Read = time.Time{} },
		"bad distro":          func(l *ReleaseLine) { l.Distro = "Debian 12; rm" },
		"long os":             func(l *ReleaseLine) { l.OS = strings.Repeat("x", 129) },
		"20001 packages":      func(l *ReleaseLine) { l.Packages = many },
		"long package name":   func(l *ReleaseLine) { l.Packages[0].Name = strings.Repeat("x", 257) },
		"system package":      func(l *ReleaseLine) { l.Packages[0].System = true },
	} {
		l := testRelease("immich", "amd64")
		change(&l)
		if err := l.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The blob is written sorted, whatever order the builder hands over, so
// the same reads give the same bytes (and the same hash).
func TestReleasesSorted(t *testing.T) {
	a, b := testRelease("immich", "arm64"), testRelease("immich", "amd64")
	c := testRelease("authelia", "amd64")
	first, err := marshalReleases([]ReleaseLine{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalReleases([]ReleaseLine{c, b, a})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("output depends on input order")
	}
	lines, err := parseReleases(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || lines[0].AppID != "authelia" || lines[1].Platform.Arch != "amd64" || lines[2].Platform.Arch != "arm64" {
		t.Fatalf("order = %+v", lines)
	}
}

func TestReleasesBlobRefusesInvalidLine(t *testing.T) {
	bad := testRelease("immich", "amd64")
	bad.ManifestDigest = "nope"
	if _, err := marshalReleases([]ReleaseLine{bad}); err == nil {
		t.Fatal("builder wrote an invalid line")
	}
	if _, err := parseReleases([]byte(`{"app_id":"immich","secret":1}` + "\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
}

// publishLayered publishes a package with generated entries and release
// package lists beside the reviewed catalog, the index and advisories.
func (f *fixture) publishLayered(seq int64, generated []catalog.Entry, releases []ReleaseLine) {
	f.t.Helper()
	_, err := WriteSnapshot(f.pub, Snapshot{Channel: f.channel, Sequence: seq, CreatedAt: f.now, ExpiresAt: f.now.Add(7 * 24 * time.Hour),
		CatalogVersion: "test", Catalog: []catalog.Entry{{Name: "immich.yaml", Data: immichEntry}},
		Advisories: []AdvisoryLine{{AppID: "immich", CVSS: 9.1, Severity: "critical", OSV: testOSV(f.now, "GHSA-test-a")}},
		Index:      []byte(testIndex), Generated: generated, Releases: releases, Shards: 4}, f.feedKey)
	if err != nil {
		f.t.Fatal(err)
	}
}

func TestGeneratedAndReleasesLoad(t *testing.T) {
	f := newFixture(t)
	gen := []catalog.Entry{generatedTestEntry("gh-a-b", "ghcr.io/a/b"), generatedTestEntry("gh-x-immich", "ghcr.io/immich-app/immich-server")}
	f.publishLayered(5, gen, []ReleaseLine{testRelease("immich", "arm64"), testRelease("immich", "amd64")})
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	cat := f.client.Catalog.Current()
	if a, ok := cat.App("gh-a-b"); !ok || a.Origin != catalog.OriginGenerated {
		t.Fatalf("generated entry = %+v", a)
	}
	if a, ok := cat.ByImage("ghcr.io/immich-app/immich-server"); !ok || a.ID != "immich" || a.Origin != catalog.OriginFeed {
		t.Fatalf("reviewed image = %+v", a)
	}
	rel := f.storedReleases("immich")
	if len(rel) != 2 || rel[0].Platform.Arch != "amd64" || len(rel[0].Packages) != 1 {
		t.Fatalf("releases = %+v", rel)
	}
	// A restart loads both from the cache.
	again := &Client{Mirrors: f.client.Mirrors, Dir: f.client.Dir, Store: f.st, Catalog: catalog.NewLive(nil),
		Log: f.client.Log, Now: f.client.Now, AllowDevelopment: true}
	if err := again.LoadActive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Catalog.Current().App("gh-a-b"); !ok || len(f.storedReleases("immich")) != 2 {
		t.Fatal("generated entries or releases not loaded with the installed package")
	}
	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err := f.client.Deactivate(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if f.storedReleases("immich") != nil {
		t.Fatal("releases survive leaving the package")
	}
	// A package without the blobs drops what the last one carried.
	f.publishLayered(6, nil, nil)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.client.Catalog.Current().App("gh-a-b"); ok || f.storedReleases("immich") != nil {
		t.Fatal("generated entries or releases of the previous package kept")
	}
}

// The builder refuses a line installations would refuse; a blob with one
// that reaches an installation anyway refuses the whole update, like any
// other malformed blob, and the previous package stays.
func TestBadReleasesRefusesUpdate(t *testing.T) {
	f := newFixture(t)
	bad := testRelease("immich", "amd64")
	bad.Packages = make([]inventory.Package, 20001)
	if _, err := WriteSnapshot(t.TempDir(), Snapshot{Sequence: 5, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour),
		Catalog: []catalog.Entry{{Name: "immich.yaml", Data: immichEntry}}, Releases: []ReleaseLine{bad}}, f.feedKey); err == nil {
		t.Fatal("snapshot with an invalid release line written")
	}

	f.publishLayered(5, nil, []ReleaseLine{testRelease("immich", "amd64")})
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	f.publishLayered(6, nil, nil)
	line, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(line)
	h := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(f.pub, "v1", "blobs", "sha256", h), line, 0o600); err != nil {
		t.Fatal(err)
	}
	f.republish(func(m *Manifest) {
		m.Blobs = append(m.Blobs, Blob{Name: "releases", MediaType: MediaReleases, Compression: "none", SHA256: h,
			Size: int64(len(line)), UncompressedSize: int64(len(line))})
	})
	if _, err := f.update(); err == nil || !strings.Contains(err.Error(), "releases line 1") {
		t.Fatalf("err = %v, want the bad line refused", err)
	}
	if rel := f.storedReleases("immich"); len(rel) != 1 {
		t.Fatalf("releases = %d, want the previous 1", len(rel))
	}
}

// The line format is frozen once shipped: this pins its exact encoding.
func TestReleaseLineGolden(t *testing.T) {
	l := testRelease("immich", "arm64")
	l.Platform.Variant = "v8"
	l.Partial = true
	got, err := marshalReleases([]ReleaseLine{l})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"app_id":"immich","image":"ghcr.io/immich-app/immich-server","tag":"v1.120.0","version":"1.120.0",` +
		`"index_digest":"sha256:` + strings.Repeat("a", 64) + `","platform":{"os":"linux","architecture":"arm64","variant":"v8"},` +
		`"manifest_digest":"sha256:` + strings.Repeat("b", 64) + `","read":"2026-11-12T03:00:00Z","distro":"debian-12",` +
		`"os_name":"Debian GNU/Linux 12 (bookworm)","partial":true,"packages":[{"manager":"dpkg","name":"openssl",` +
		`"version":"3.0.15-1~deb12u1","distro":"debian-12","source":"openssl"}]}` + "\n"
	if string(got) != want {
		t.Fatalf("encoding changed:\n got %s\nwant %s", got, want)
	}
	p := registry.Platform{OS: "linux", Arch: "arm64", Variant: "v8"}
	if PlatformOf(p).Registry() != p {
		t.Fatal("platform conversion loses a field")
	}
}

// One package list per app, image and platform: the builder and the
// reader refuse a second.
func TestReleasesDuplicateRefused(t *testing.T) {
	a := testRelease("immich", "amd64")
	if _, err := marshalReleases([]ReleaseLine{a, a}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("builder: err = %v", err)
	}
	one, err := marshalReleases([]ReleaseLine{a})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseReleases(append(one, one...)); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("reader: err = %v", err)
	}
	// Another platform of the same image is a line of its own.
	if _, err := marshalReleases([]ReleaseLine{a, testRelease("immich", "arm64")}); err != nil {
		t.Fatal(err)
	}
}

// The builder refuses a snapshot every reader would refuse for its size.
func TestSnapshotUnpackedLimit(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Sequence: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), MaxUnpacked: 1 << 10,
		Catalog: []catalog.Entry{{Name: "immich.yaml", Data: immichEntry}}}
	if _, err := WriteSnapshot(t.TempDir(), s, key); err != nil {
		t.Fatalf("small snapshot: %v", err)
	}
	s.Releases = []ReleaseLine{testRelease("immich", "amd64"), testRelease("immich", "arm64"), testRelease("authelia", "amd64")}
	if _, err := WriteSnapshot(t.TempDir(), s, key); err == nil || !strings.Contains(err.Error(), "exceed the limit") {
		t.Fatalf("err = %v, want the unpacked limit", err)
	}
}

func testOSV(now time.Time, id string) advisory.Vulnerability {
	return advisory.Vulnerability{SchemaVersion: "1.6.0", ID: id, Modified: now}
}

// countingReleases counts the writes of release package lists; with fail
// set it cannot keep them.
type countingReleases struct {
	*store.Store
	fail  bool
	calls int
}

func (s *countingReleases) ReplaceReleasePackages(ctx context.Context, marker string, rows []store.ReleasePackageRow) error {
	s.calls++
	if s.fail {
		return errors.New("disk full")
	}
	return s.Store.ReplaceReleasePackages(ctx, marker, rows)
}

// The installation keeps the release package lists of the applied package
// in its store, replaced with each package and on startup; a package
// without them clears the table. Failing to keep them is logged and does
// not cost the catalog or the advisories.
func TestClientStoresReleases(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.publishLayered(5, nil, []ReleaseLine{testRelease("immich", "amd64"), testRelease("immich", "arm64")})
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	lines, err := f.st.ReleasePackagesFor(ctx, "immich", "ghcr.io/immich-app/immich-server")
	if err != nil || len(lines) != 2 {
		t.Fatalf("stored lines = %d, %v", len(lines), err)
	}
	var got ReleaseLine
	if err := json.Unmarshal(lines[1], &got); err != nil || got.Platform.Arch != "arm64" || got.Tag != "v1.120.0" || len(got.Packages) != 1 {
		t.Fatalf("stored line = %+v, %v", got, err)
	}

	// Startup writes the table from the installed package again: a store
	// restored from a backup or an older Varde gets the lists back.
	if err := f.st.ReplaceReleasePackages(ctx, "", nil); err != nil {
		t.Fatal(err)
	}
	counting := &countingReleases{Store: f.st}
	again := &Client{Mirrors: f.client.Mirrors, Dir: f.client.Dir, Store: counting, Catalog: catalog.NewLive(nil),
		Log: f.client.Log, Now: f.client.Now, AllowDevelopment: true}
	if err := again.LoadActive(ctx); err != nil {
		t.Fatal(err)
	}
	if lines, err := f.st.ReleasePackagesFor(ctx, "immich", "ghcr.io/immich-app/immich-server"); err != nil || len(lines) != 2 {
		t.Fatalf("after startup: %d lines, %v", len(lines), err)
	}
	// The next start finds them kept and does not write them again.
	if err := again.LoadActive(ctx); err != nil {
		t.Fatal(err)
	}
	if counting.calls != 1 {
		t.Fatalf("writes on two starts = %d, want 1", counting.calls)
	}

	// A package without the blob clears them.
	f.publishLayered(6, nil, nil)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	if lines, err := f.st.ReleasePackagesFor(ctx, "immich", "ghcr.io/immich-app/immich-server"); err != nil || len(lines) != 0 {
		t.Fatalf("after a package without releases: %d lines, %v", len(lines), err)
	}

	// A store that refuses them: the package still applies, the failure
	// is logged.
	var logged bytes.Buffer
	bad := &countingReleases{Store: f.st, fail: true}
	f.client.Store = bad
	f.client.Log = slog.New(slog.NewTextHandler(&logged, nil))
	f.publishLayered(7, nil, []ReleaseLine{testRelease("immich", "amd64")})
	res, err := f.update()
	if err != nil || !res.Applied {
		t.Fatalf("update with a failing release store: %+v, %v", res, err)
	}
	if bad.calls != 1 || !strings.Contains(logged.String(), "disk full") {
		t.Fatalf("calls = %d, log = %q", bad.calls, logged.String())
	}
	if _, ok := f.client.Catalog.Current().App("immich"); !ok || f.feedAdvisories() != 1 {
		t.Fatal("catalog or advisories lost with the release store")
	}
}
