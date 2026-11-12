// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

const (
	idA  = "1111111111111111111111111111111111111111111111111111111111111111"
	idB  = "2222222222222222222222222222222222222222222222222222222222222222"
	idC  = "3333333333333333333333333333333333333333333333333333333333333333"
	imgA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imgB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func tarFile(t *testing.T, hdr tar.Header, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if hdr.Typeflag == tar.TypeReg {
		hdr.Size = int64(len(body))
	}
	hdr.Mode = 0o644
	if err := tw.WriteHeader(&hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Typeflag == tar.TypeReg {
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	return buf.Bytes()
}

// files serves the archive endpoint from a map of container ID and path.
func files(t *testing.T, fs map[string]string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "read-only", http.StatusForbidden)
			return
		}
		id := strings.Split(r.URL.Path, "/")[3]
		path := r.URL.Query().Get("path")
		body, ok := fs[id+path]
		if !ok {
			http.Error(w, `{"message":"no such file"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-tar")
		_, _ = w.Write(tarFile(t, tar.Header{Name: path[strings.LastIndexByte(path, '/')+1:], Typeflag: tar.TypeReg}, body))
	}
}

func TestReadFile(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)
	ctx := t.Context()
	if _, err := col.client.Negotiate(ctx); err != nil {
		t.Fatal(err)
	}
	f.archive = files(t, map[string]string{idA + "/etc/os-release": "ID=debian\n"})
	if b, err := col.client.ReadFile(ctx, idA, "/etc/os-release"); err != nil || string(b) != "ID=debian\n" {
		t.Fatalf("read: %q %v", b, err)
	}
	if _, err := col.client.ReadFile(ctx, idA, "/var/lib/dpkg/status"); !errors.Is(err, ErrNoFile) {
		t.Errorf("missing file: %v", err)
	}
	// Only the fixed paths, and only valid container IDs, are requested.
	before := f.count("/v1.51/containers/" + idA + "/archive")
	for _, c := range []struct{ id, path string }{
		{idA, "/etc/shadow"}, {idA, "/etc/os-release/../shadow"}, {"../x", "/etc/os-release"},
		{idA, "app/package.json"}, {idA, "/app/../etc/package.json"}, {idA, "/app//package.json"},
		{idA, "/app/package.json.bak"}, {idA, "/app/.env"},
	} {
		if _, err := col.client.ReadFile(ctx, c.id, c.path); err == nil {
			t.Errorf("%s %s read", c.id, c.path)
		}
	}
	if f.count("/v1.51/containers/"+idA+"/archive") != before {
		t.Error("refused path was requested")
	}
	// A symlink under a fixed path is not followed: a container could point
	// it at another file.
	f.archive = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarFile(t, tar.Header{Name: "os-release", Typeflag: tar.TypeSymlink, Linkname: "../usr/lib/os-release"}, ""))
	}
	if _, err := col.client.ReadFile(ctx, idA, "/etc/os-release"); !errors.Is(err, ErrNoFile) {
		t.Errorf("symlink: %v", err)
	}
	f.archive = func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: "status", Typeflag: tar.TypeReg, Size: fileLimit + 1, Mode: 0o644})
		_, _ = w.Write(buf.Bytes())
	}
	if _, err := col.client.ReadFile(ctx, idA, "/var/lib/dpkg/status"); err == nil || errors.Is(err, ErrNoFile) {
		t.Errorf("oversized file: %v", err)
	}
}

type memPackages struct {
	mu sync.Mutex
	m  map[string]inventory.ImagePackages
}

func (s *memPackages) ImagePackagesRead(context.Context) (map[string]inventory.ImagePackages, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]inventory.ImagePackages{}
	for k, v := range s.m {
		out[k] = v
	}
	return out, nil
}

func (s *memPackages) RecordImagePackages(_ context.Context, p inventory.ImagePackages) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[p.ImageID] = p
	return nil
}

func TestPackageReader(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)
	f.archive = files(t, map[string]string{
		// Debian's /etc/os-release is a symlink, which is not followed.
		idA + "/usr/lib/os-release":   "ID=debian\nVERSION_ID=\"13\"\nNAME=\"Debian GNU/Linux\"\n",
		idA + "/var/lib/dpkg/status":  "Package: jellyfin-server\nStatus: install ok installed\nVersion: 10.10.7+deb13\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n",
		idB + "/lib/apk/db/installed": "P:busybox\nV:1.37.0-r18\n",
		// The working directory of image a is /app/backend; the app's
		// manifest sits in its parent.
		idA + "/app/package.json": `{"name": "immich", "version": "1.120.0", "dependencies": {"x": "1"}}`,
	})
	// Every container is unchanged against its image.
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/changes") {
			_, _ = w.Write([]byte(`[{"Path": "/tmp/x", "Kind": 1}]`))
			return true
		}
		return false
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	st := &memPackages{m: map[string]inventory.ImagePackages{}}
	changed := 0
	col.Packages = &PackageReader{Store: st, Now: func() time.Time { return now }, Changed: func(context.Context) { changed++ }}
	if _, err := col.List(t.Context()); err != nil {
		t.Fatal(err)
	}
	a, b := st.m[imgA], st.m[imgB]
	want := inventory.Package{Manager: "dpkg", Name: "jellyfin-server", Version: "10.10.7+deb13", Distro: "debian-13"}
	manifest := inventory.Package{Manager: "npm", Name: "immich", Version: "1.120.0", Path: "/app/package.json"}
	if a.Distro != "debian-13" || a.OS != "Debian GNU/Linux 13" || len(a.Packages) != 2 || a.Packages[1] != want || a.Packages[0] != manifest {
		t.Errorf("image a: %+v", a)
	}
	if b.Distro != "" || len(b.Packages) != 1 || b.Packages[0].Name != "busybox" || b.Error != "" {
		t.Errorf("image b: %+v", b)
	}
	// One container per image: the third runs image a too.
	if n := f.count("/v1.51/containers/" + idC + "/archive"); n != 0 {
		t.Errorf("second container of an image read %d times", n)
	}
	if changed != 1 {
		t.Errorf("changed %d times", changed)
	}
	// Fresh reads are not repeated; after a week they are.
	reads := func() int {
		return f.count("/v1.51/containers/"+idA+"/archive") + f.count("/v1.51/containers/"+idB+"/archive")
	}
	n := reads()
	if _, err := col.List(t.Context()); err != nil || reads() != n || changed != 1 {
		t.Fatalf("fresh images read again: %d -> %d, changed %d", n, reads(), changed)
	}
	now = now.Add(packagesRefresh + time.Minute)
	if _, err := col.List(t.Context()); err != nil || reads() == n {
		t.Fatal("stale images not read again")
	}

	// A refusal is recorded once, keeps nothing, stops the round and is
	// retried after a day.
	st.m = map[string]inventory.ImagePackages{}
	f.archive = func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "forbidden", http.StatusForbidden) }
	if _, err := col.List(t.Context()); err != nil {
		t.Fatalf("a refused read failed the sync: %v", err)
	}
	if len(st.m) != 1 {
		t.Fatalf("refusal recorded for %d images, want 1", len(st.m))
	}
	var refused string
	for id, p := range st.m {
		refused = id
		if p.Error == "" || len(p.Packages) != 0 {
			t.Errorf("refusal: %+v", p)
		}
	}
	n = reads()
	now = now.Add(time.Hour)
	_, _ = col.List(t.Context())
	if reads() != n+1 {
		t.Errorf("%d reads in the next sync, want 1 (the other image)", reads()-n)
	}
	now = now.Add(packagesRetry)
	before := st.m[refused].Read
	_, _ = col.List(t.Context())
	if !st.m[refused].Read.After(before) {
		t.Error("refused image not retried after a day")
	}

	// Switched off, nothing is read.
	st.m = map[string]inventory.ImagePackages{}
	col.Packages.Enabled = func() bool { return false }
	n = reads()
	_, _ = col.List(t.Context())
	if reads() != n || len(st.m) != 0 {
		t.Error("disabled reader read files")
	}
}

func TestManifestPaths(t *testing.T) {
	for dir, want := range map[string]string{
		"/app/backend":  "/app/backend/package.json /app/package.json",
		"/app":          "/app/package.json",
		"/opt/frigate/": "/opt/frigate/package.json /opt/package.json",
		"/":             "",
		"":              "",
		"app":           "",
	} {
		if got := strings.Join(manifestPaths(dir), " "); got != want {
			t.Errorf("%q: %q, want %q", dir, got, want)
		}
		for _, f := range manifestPaths(dir) {
			if !allowedFile(f) {
				t.Errorf("%s refused", f)
			}
		}
	}
}

// The record of an image stands for all its containers: it is read only
// from a container whose package files are the image's own.
func TestPackageReaderSkipsChangedContainers(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)
	f.archive = files(t, map[string]string{
		// Container a rewrote its dpkg database; c, of the same image, did not.
		idA + "/var/lib/dpkg/status": "Package: jellyfin-server\nStatus: install ok installed\nVersion: 99.0.0+forged\n",
		idC + "/var/lib/dpkg/status": "Package: jellyfin-server\nStatus: install ok installed\nVersion: 10.10.7+deb13\n",
	})
	changes := map[string]string{
		idA: `[{"Path": "/var/lib/dpkg/status", "Kind": 0}]`,
		idB: `[{"Path": "/lib/apk/db/installed", "Kind": 0}]`,
		idC: `[]`,
	}
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		for id, body := range changes {
			if r.URL.Path == "/v1.51/containers/"+id+"/changes" {
				_, _ = w.Write([]byte(body))
				return true
			}
		}
		return false
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	st := &memPackages{m: map[string]inventory.ImagePackages{}}
	col.Packages = &PackageReader{Store: st, Now: func() time.Time { return now }}
	if _, err := col.List(t.Context()); err != nil {
		t.Fatal(err)
	}
	a := st.m[imgA]
	if len(a.Packages) != 1 || a.Packages[0].Version != "10.10.7+deb13" {
		t.Errorf("image a read from the changed container: %+v", a)
	}
	if f.count("/v1.51/containers/"+idA+"/archive") != 0 {
		t.Error("changed container read")
	}
	// Image b's only container changed its database: nothing is stored.
	if b := st.m[imgB]; len(b.Packages) != 0 || b.Error == "" {
		t.Errorf("image b: %+v", b)
	}
}

// An image of an rpm distribution: the SQLite package database is read
// next to os-release (testdata/rpmdb.sqlite as in internal/pkgdb).
func TestReadImagePackagesRPM(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)
	ctx := t.Context()
	if _, err := col.client.Negotiate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := os.ReadFile("testdata/rpmdb.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	f.archive = files(t, map[string]string{
		idA + "/usr/lib/os-release":       "ID=\"almalinux\"\nVERSION_ID=\"9.4\"\nNAME=\"AlmaLinux\"\n",
		idA + "/var/lib/rpm/rpmdb.sqlite": string(db),
	})
	got, err := ReadImagePackages(ctx, col.client, idA, ImageConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Distro != "almalinux-9.4" || len(got.Packages) != 42 {
		t.Fatalf("read: %s, %d packages", got.Distro, len(got.Packages))
	}
	for _, p := range got.Packages {
		if p.Name == "openssl-libs" && (p.Manager != "rpm" || p.Version != "1:3.0.7-27.el9" || p.Source != "openssl" || p.Distro != "almalinux-9.4") {
			t.Fatalf("openssl-libs: %+v", p)
		}
	}
}

func TestBinaryPaths(t *testing.T) {
	for _, c := range []struct {
		cfg  ImageConfig
		want []string
	}{
		{ImageConfig{Entrypoint: []string{"/entrypoint.sh"}, Cmd: []string{"traefik"}}, []string{"/usr/local/bin/traefik", "/usr/bin/traefik", "/bin/traefik", "/app/traefik"}},
		{ImageConfig{Entrypoint: []string{"/sbin/tini", "--", "/app/server", "--port", "80"}}, []string{"/sbin/tini", "/app/server"}},
		{ImageConfig{Cmd: []string{"/bin/sh", "-c", "exec /app/x"}}, nil},
		{ImageConfig{Entrypoint: []string{"/usr/bin/../bin/gitea", "web"}}, []string{"/usr/bin/gitea"}},
	} {
		if got := binaryPaths(c.cfg); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%+v: got %v, want %v", c.cfg, got, c.want)
		}
	}
}

// The Go modules of the program an image runs, and the dependencies in
// the app's npm lock file, are read with its packages.
func TestReadImagePackagesLanguages(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)
	ctx := t.Context()
	if _, err := col.client.Negotiate(ctx); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	bin, err := os.ReadFile(exe) //nolint:gosec // the running test binary
	if err != nil {
		t.Skip(err)
	}
	f.archive = files(t, map[string]string{
		idA + "/usr/local/bin/server":    string(bin),
		idA + "/app/package.json":        `{"name":"app","version":"1.0.0"}`,
		idA + "/app/package-lock.json":   `{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.18.2"}}}`,
		idA + "/usr/local/bin/script.sh": "#!/bin/sh\n",
	})
	got, err := ReadImagePackages(ctx, col.client, idA, ImageConfig{WorkingDir: "/app", Entrypoint: []string{"server"}})
	if err != nil {
		t.Fatal(err)
	}
	var goStd, express bool
	for _, p := range got.Packages {
		goStd = goStd || (p.Manager == "go" && p.Name == "stdlib" && p.Path == "/usr/local/bin/server")
		express = express || (p.Manager == "npm" && p.Name == "express" && p.Path == "/app/package-lock.json")
	}
	if !goStd || !express {
		t.Fatalf("packages: %+v", got.Packages)
	}
}

// A record of an older reader is read again although it is fresh.
func TestPackageReaderRereadsOlderFormat(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	fresh := inventory.ImagePackages{ImageID: imgA, Read: now.Add(-time.Hour), Format: ReaderFormat}
	old := inventory.ImagePackages{ImageID: imgA, Read: now.Add(-time.Hour)}
	for name, c := range map[string]struct {
		rec  inventory.ImagePackages
		read bool
	}{"current format": {fresh, false}, "older format": {old, true}} {
		if got := due(c.rec, now); got != c.read {
			t.Errorf("%s: due = %v", name, got)
		}
	}
}

// The Go programs in /usr/local/bin are read too (gosu in official images);
// other files there are skipped.
func TestReadGoPrograms(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)
	ctx := t.Context()
	if _, err := col.client.Negotiate(ctx); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	bin, err := os.ReadFile(exe) //nolint:gosec // the running test binary
	if err != nil {
		t.Skip(err)
	}
	f.archive = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("path") != ProgramDir {
			http.Error(w, `{"message":"no such file"}`, http.StatusNotFound)
			return
		}
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: "bin/", Typeflag: tar.TypeDir, Mode: 0o755})
		_ = tw.WriteHeader(&tar.Header{Name: "bin/docker-entrypoint.sh", Typeflag: tar.TypeReg, Mode: 0o755, Size: 2048})
		_, _ = tw.Write(bytes.Repeat([]byte("#"), 2048))
		_ = tw.WriteHeader(&tar.Header{Name: "bin/gosu", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(bin))})
		_, _ = tw.Write(bin)
		_ = tw.Close()
		_, _ = w.Write(buf.Bytes())
	}
	got, err := ReadImagePackages(ctx, col.client, idA, ImageConfig{Entrypoint: []string{"docker-entrypoint.sh"}})
	if err != nil {
		t.Fatal(err)
	}
	var std bool
	for _, p := range got.Packages {
		std = std || (p.Manager == "go" && p.Name == "stdlib" && p.Path == "/usr/local/bin/gosu")
	}
	if !std {
		t.Fatalf("gosu's modules not read: %+v", got.Packages)
	}
}

// Use names exactly the files ReadPackages reads, with their limits, so a
// source that copies them ahead of the read serves the same files.
func TestUse(t *testing.T) {
	cfg := ImageConfig{WorkingDir: "/srv/app/web", Entrypoint: []string{"server"}}
	cases := []struct {
		path  string
		use   FileUse
		limit int64
	}{
		{"/etc/os-release", WholeFile, fileLimit},
		{"/var/lib/rpm/rpmdb.sqlite", WholeFile, rpmFileLimit},
		{"/srv/app/web/package.json", WholeFile, fileLimit},
		{"/srv/app/package-lock.json", WholeFile, fileLimit},
		{"/srv/package.json", Unread, 0},
		{"/usr/local/bin/gosu", Program, binaryLimit},
		{"/usr/bin/server", Program, binaryLimit},
		{"/usr/bin/other", Unread, 0},
		{"/var/lib/dpkg/status.d/bash", StatusFile, statusDirBytes},
		{"/usr/local/lib/python3.11/site-packages/x-1.dist-info/METADATA", LanguageMeta, languageMetaMax},
		{"/opt/app/lib/x.jar", LanguageMeta, languageArchiveMax},
		{"/opt/app/lib/x.class", Unread, 0},
		{"/etc/../etc/os-release", Unread, 0},
		{"/etc/shadow", Unread, 0},
	}
	for _, c := range cases {
		if use, limit := Use(cfg, c.path); use != c.use || limit != c.limit {
			t.Errorf("Use(%s) = %d, %d; want %d, %d", c.path, use, limit, c.use, c.limit)
		}
	}
	locs := strings.Join(ReadLocations(cfg), " ")
	for _, want := range []string{"/etc/os-release", "/srv/app/package.json", "/usr/local/bin/server", StatusDir, ProgramDir, "/usr/local/lib"} {
		if !strings.Contains(" "+locs+" ", " "+want+" ") {
			t.Errorf("ReadLocations misses %s: %s", want, locs)
		}
	}
}
