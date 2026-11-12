// SPDX-License-Identifier: Apache-2.0

package releases

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/imagelayers"
	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/store"
)

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// repo is one repository of the fake registry.
type repo struct {
	tags      []string
	manifests map[string][]byte // tag or digest -> body
	blobs     map[string][]byte
}

// fakeRegistry serves tag lists, manifests and blobs of several
// repositories without authentication and records every request.
type fakeRegistry struct {
	mu       sync.Mutex
	repos    map[string]*repo
	requests []string
	srv      *httptest.Server
	host     string
	client   *registry.Client
}

func newRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{repos: map[string]*repo{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	f.client = registry.New(httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second}))
	f.host = strings.TrimPrefix(f.srv.URL, "https://")
	return f
}

func (f *fakeRegistry) serve(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req.Method+" "+req.URL.Path)
	p := strings.TrimPrefix(req.URL.Path, "/v2/")
	for _, sep := range []string{"/tags/list", "/manifests/", "/blobs/"} {
		name, ref, ok := strings.Cut(p, sep)
		if !ok {
			continue
		}
		r := f.repos[name]
		if r == nil {
			break
		}
		switch sep {
		case "/tags/list":
			_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "tags": r.tags})
			return
		case "/manifests/":
			body, ok := r.manifests[ref]
			if !ok {
				break
			}
			ct := "application/vnd.oci.image.manifest.v1+json"
			if bytes.Contains(body, []byte(`"manifests"`)) {
				ct = "application/vnd.oci.image.index.v1+json"
			}
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Docker-Content-Digest", digestOf(body))
			if req.Method == http.MethodGet {
				_, _ = w.Write(body)
			}
			return
		case "/blobs/":
			b, ok := r.blobs[ref]
			if !ok {
				break
			}
			_, _ = w.Write(b)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func (f *fakeRegistry) repo(name string) *repo {
	r := f.repos[name]
	if r == nil {
		r = &repo{manifests: map[string][]byte{}, blobs: map[string][]byte{}}
		f.repos[name] = r
	}
	return r
}

// requestsFor returns the requests of one repository and resets the log.
func (f *fakeRegistry) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.requests
	f.requests = nil
	return out
}

func count(reqs []string, part string) int {
	n := 0
	for _, r := range reqs {
		if strings.Contains(r, part) {
			n++
		}
	}
	return n
}

// file is one regular file of a test layer.
type file struct{ name, body string }

func layerOf(t *testing.T, files ...file) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()
	return buf.Bytes()
}

// platform is one platform of a test image.
type platform struct {
	arch, variant string
	layers        [][]file
	workDir       string
	cmd           string
}

// push publishes an image under tag: an index of the platforms, or a
// single manifest when there is one platform and single is set. It
// returns the digest the tag names.
func (f *fakeRegistry) push(t *testing.T, name, tag string, single bool, plats ...platform) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.repo(name)
	var descs []string
	var last []byte
	for _, p := range plats {
		var layers []string
		for _, files := range p.layers {
			b := layerOf(t, files...)
			d := digestOf(b)
			r.blobs[d] = b
			layers = append(layers, fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}`, d, len(b)))
		}
		cfg := fmt.Appendf(nil, `{"os":"linux","architecture":%q,"variant":%q,"config":{"WorkingDir":%q,"Cmd":[%q],"Labels":{"a":"b"}}}`, p.arch, p.variant, p.workDir, p.cmd)
		cd := digestOf(cfg)
		r.blobs[cd] = cfg
		m := fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[%s]}`, cd, len(cfg), strings.Join(layers, ","))
		md := digestOf(m)
		r.manifests[md] = m
		last = m
		variant := ""
		if p.variant != "" {
			variant = fmt.Sprintf(`,"variant":%q`, p.variant)
		}
		descs = append(descs, fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d,"platform":{"os":"linux","architecture":%q%s}}`, md, len(m), p.arch, variant))
	}
	body := last
	if !single {
		body = fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s]}`, strings.Join(descs, ","))
	}
	d := digestOf(body)
	r.manifests[tag], r.manifests[d] = body, body
	if !contains(r.tags, tag) {
		r.tags = append(r.tags, tag)
	}
	return d
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if x == y {
			return true
		}
	}
	return false
}

const osRelease = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n"

func status(pkgs ...string) string {
	var b strings.Builder
	for _, p := range pkgs {
		name, ver, _ := strings.Cut(p, "=")
		fmt.Fprintf(&b, "Package: %s\nStatus: install ok installed\nVersion: %s\n\n", name, ver)
	}
	return b.String()
}

// debian is a two-layer Debian image with the given dpkg packages.
func debian(arch, variant string, pkgs ...string) platform {
	return platform{arch: arch, variant: variant, layers: [][]file{
		{{"etc/os-release", osRelease}, {"usr/share/doc/readme", "base " + arch}},
		{{"var/lib/dpkg/status", status(pkgs...)}},
	}}
}

func reviewedEntry(id, image string) catalog.Entry {
	return catalog.Entry{Name: id + ".yaml", Data: `id: ` + id + `
name: ` + id + `
homepage: https://example.org/` + id + `
images: [{match: "` + image + `"}]
version:
  scheme: semver
  sources:
    - tag: '^v?(?P<v>\d+\.\d+\.\d+)$'
advisories: {coverage: partial, github_repos: [x/` + id + `]}
maintainers_of_entry: [someone]
verified: 2026-11-08
`}
}

func generatedEntry(id, image string) catalog.Entry {
	return catalog.Entry{Name: id + ".yaml", Data: `id: ` + id + `
name: ` + id + `
homepage: https://github.com/x/` + id + `
images: [{match: "` + image + `"}]
version: {scheme: semver}
advisories: {coverage: partial, github_repos: [x/` + id + `]}
maintainers_of_entry: [generator]
verified: 2026-11-12
`}
}

// labelEntry reads its version from a label only: no release tag.
func labelEntry(id, image string) catalog.Entry {
	e := reviewedEntry(id, image)
	e.Data = strings.Replace(e.Data, `    - tag: '^v?(?P<v>\d+\.\d+\.\d+)$'`, `    - label: org.opencontainers.image.version`, 1)
	return e
}

func newCatalog(t *testing.T, reviewed, generated []catalog.Entry) *catalog.Catalog {
	t.Helper()
	c, err := catalog.BuildLayered(reviewed, catalog.OriginFeed, generated, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := c.DroppedGenerated(); len(d) > 0 {
		t.Fatalf("dropped: %v", d)
	}
	return c
}

// regHost is the registry the catalog names; the reader asks the test
// server instead.
const regHost = "registry.test"

var now0 = time.Date(2026, 11, 12, 4, 0, 0, 0, time.UTC)

func newReader(t *testing.T, f *fakeRegistry) (*Reader, *store.Store) {
	t.Helper()
	s, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "builder.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return &Reader{Store: s, Registry: f.client, Now: func() time.Time { return now0 },
		registryRepo: func(image string) string { return strings.Replace(image, regHost, f.host, 1) }}, s
}

func run(t *testing.T, r *Reader, cat *catalog.Catalog, order ...string) ([]feed.ReleaseLine, Stats) {
	t.Helper()
	lines, st, err := r.Run(t.Context(), cat, order)
	if err != nil {
		t.Fatal(err)
	}
	return lines, st
}

func pkgList(l feed.ReleaseLine) string {
	var out []string
	for _, p := range l.Packages {
		out = append(out, p.Manager+":"+p.Name+"="+p.Version)
	}
	return strings.Join(out, ",")
}

// Both platforms of a multi-arch release are read, each from its own
// layers; a single-platform image gives one line without an index digest;
// an app whose version is never read from a tag is not asked for.
func TestBothPlatforms(t *testing.T) {
	f := newRegistry(t)
	f.repo("org/app").tags = []string{"latest", "1.0.0"}
	f.push(t, "org/app", "1.0.0", false, debian("amd64", "", "bash=5.1"), debian("arm64", "v8", "bash=5.1"))
	idx := f.push(t, "org/app", "1.1.0", false, debian("amd64", "", "bash=5.2-amd"), debian("arm64", "v8", "bash=5.2-arm", "zlib=1.3"))
	single := f.push(t, "org/gen", "v2.0.1", true, debian("amd64", "", "curl=8.0"))
	f.push(t, "org/label", "3.0.0", false, debian("amd64", "", "x=1"))
	cat := newCatalog(t,
		[]catalog.Entry{reviewedEntry("app", regHost+"/org/app"), labelEntry("label", regHost+"/org/label")},
		[]catalog.Entry{generatedEntry("gh-x-gen", regHost+"/org/gen")})
	r, _ := newReader(t, f)
	lines, st := run(t, r, cat)
	if len(lines) != 3 || st.Read != 2 || st.Lines != 3 || st.Images != 2 || st.Partial != 0 {
		t.Fatalf("stats %+v lines %+v", st, lines)
	}
	if n := count(f.take(), "/org/label/"); n != 0 {
		t.Fatalf("%d requests for an app without a tag source", n)
	}
	byKey := map[string]feed.ReleaseLine{}
	for _, l := range lines {
		byKey[l.AppID+" "+l.Platform.Arch] = l
	}
	amd, arm, gen := byKey["app amd64"], byKey["app arm64"], byKey["gh-x-gen amd64"]
	if amd.Tag != "1.1.0" || amd.Version != "1.1.0" || amd.IndexDigest != idx || amd.Distro != "debian-12" || amd.Partial || !amd.Read.Equal(now0) || amd.Image != regHost+"/org/app" {
		t.Fatalf("amd64 line %+v", amd)
	}
	if got := pkgList(amd); got != "dpkg:bash=5.2-amd" {
		t.Fatalf("amd64 packages %s", got)
	}
	if arm.Platform != (feed.ReleasePlatform{OS: "linux", Arch: "arm64", Variant: "v8"}) || arm.ManifestDigest == amd.ManifestDigest {
		t.Fatalf("arm64 line %+v", arm)
	}
	if got := pkgList(arm); got != "dpkg:bash=5.2-arm,dpkg:zlib=1.3" {
		t.Fatalf("arm64 packages %s", got)
	}
	if gen.Tag != "v2.0.1" || gen.Version != "2.0.1" || gen.IndexDigest != "" || gen.ManifestDigest != single || pkgList(gen) != "dpkg:curl=8.0" {
		t.Fatalf("single-platform line %+v", gen)
	}
	for _, l := range lines {
		if err := l.Validate(); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
	}
}

// A release whose tag still names the digest read before is not read
// again: only the tag list and a HEAD request reach the registry, and the
// stored lines ship with a renewed read time.
func TestDigestUnchangedSkips(t *testing.T) {
	f := newRegistry(t)
	f.push(t, "org/app", "1.1.0", false, debian("amd64", "", "bash=5.2"), debian("arm64", "", "bash=5.2"))
	cat := newCatalog(t, []catalog.Entry{reviewedEntry("app", regHost+"/org/app")}, nil)
	r, _ := newReader(t, f)
	first, _ := run(t, r, cat)
	f.take()
	r.Now = func() time.Time { return now0.Add(24 * time.Hour) }
	second, st := run(t, r, cat)
	reqs := f.take()
	if st.Unchanged != 1 || st.Read != 0 || st.Manifests != 0 || len(second) != 2 {
		t.Fatalf("stats %+v", st)
	}
	if count(reqs, "GET /v2/org/app/manifests/") != 0 || count(reqs, "/blobs/") != 0 || count(reqs, "HEAD /v2/org/app/manifests/1.1.0") != 1 {
		t.Fatalf("requests %v", reqs)
	}
	for i := range second {
		if !second[i].Read.Equal(now0.Add(24*time.Hour)) || pkgList(second[i]) != pkgList(first[i]) || second[i].ManifestDigest != first[i].ManifestDigest {
			t.Fatalf("line %+v, first %+v", second[i], first[i])
		}
	}
	// A new release is read.
	f.push(t, "org/app", "1.2.0", false, debian("amd64", "", "bash=5.3"), debian("arm64", "", "bash=5.3"))
	third, st := run(t, r, cat)
	if st.Read != 1 || third[0].Tag != "1.2.0" || pkgList(third[0]) != "dpkg:bash=5.3" {
		t.Fatalf("stats %+v lines %+v", st, third)
	}
}

// A release read again (its tag moved to a new index of the same images)
// takes its configs and layers from the cache: no blob request at all.
func TestReusesLayerCache(t *testing.T) {
	f := newRegistry(t)
	f.push(t, "org/app", "1.1.0", false, debian("amd64", "", "bash=5.2"), debian("arm64", "v8", "bash=5.2", "zlib=1.3"))
	cat := newCatalog(t, []catalog.Entry{reviewedEntry("app", regHost+"/org/app")}, nil)
	r, s := newReader(t, f)
	first, _ := run(t, r, cat)
	if n := count(f.take(), "/blobs/"); n != 6 {
		t.Fatalf("first run: %d blob requests, want 2 configs and 4 layers", n)
	}
	// The same platform manifests under a new index (an annotation added).
	rp := f.repos["org/app"]
	index := bytes.Replace(rp.manifests["1.1.0"], []byte(`"manifests"`), []byte(`"annotations":{"x":"y"},"manifests"`), 1)
	f.mu.Lock()
	rp.manifests["1.1.0"], rp.manifests[digestOf(index)] = index, index
	f.mu.Unlock()
	second, st := run(t, r, cat)
	reqs := f.take()
	if n := count(reqs, "/blobs/"); n != 0 {
		t.Fatalf("second run: %d blob requests: %v", n, reqs)
	}
	if st.Read != 1 || len(second) != 2 || second[0].IndexDigest != digestOf(index) {
		t.Fatalf("stats %+v lines %+v", st, second)
	}
	for i := range second {
		if pkgList(second[i]) != pkgList(first[i]) || second[i].Partial != first[i].Partial || second[i].Distro != first[i].Distro {
			t.Fatalf("from the cache %+v, read %+v", second[i], first[i])
		}
	}
	// The cache holds a record per layer, under its chain key.
	m := rp.manifests
	var doc struct {
		Manifests []struct{ Digest string } `json:"manifests"`
	}
	if err := json.Unmarshal(index, &doc); err != nil {
		t.Fatal(err)
	}
	var pm struct {
		Layers []registry.Layer `json:"layers"`
	}
	if err := json.Unmarshal(m[doc.Manifests[0].Digest], &pm); err != nil {
		t.Fatal(err)
	}
	keys, err := imagelayers.LayerKeys(pm.Layers, imagelayers.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg := readCfg(t, r, f, doc.Manifests[0].Digest); cfg.Labels["a"] != "b" {
		t.Fatalf("cached config %+v", cfg)
	}
	for _, k := range keys {
		if _, _, ok, err := s.LayerRead(t.Context(), k); err != nil || !ok {
			t.Fatalf("no layer record under %s: %v", k, err)
		}
	}
}

// readCfg returns the config the reader keeps for a platform manifest.
func readCfg(t *testing.T, r *Reader, f *fakeRegistry, manifest string) docker.ImageConfig {
	t.Helper()
	var m struct {
		Config struct{ Digest string } `json:"config"`
	}
	if err := json.Unmarshal(f.repos["org/app"].manifests[manifest], &m); err != nil {
		t.Fatal(err)
	}
	c, err := r.config(t.Context(), regHost+"/org/app", m.Config.Digest)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A spent budget stops new reads: what was read ships, an app not started
// keeps its earlier line with its old read time, and its registry is not
// asked.
func TestBudgetStopsNewReads(t *testing.T) {
	f := newRegistry(t)
	// a's layers are larger than the byte budget of the second case.
	noisy := func(arch string) platform {
		p := debian(arch, "", "a=1")
		p.layers = append(p.layers, []file{{"usr/share/doc/noise", noise(40 << 10)}})
		return p
	}
	f.push(t, "org/a", "1.0.0", false, noisy("amd64"), noisy("arm64"))
	f.push(t, "org/b", "2.0.0", false, debian("amd64", "", "b=2"), debian("arm64", "", "b=2"))
	cat := newCatalog(t, []catalog.Entry{reviewedEntry("a", regHost+"/org/a"), reviewedEntry("b", regHost+"/org/b")}, nil)

	t.Run("manifests", func(t *testing.T) {
		r, s := newReader(t, f)
		old := feed.ReleaseLine{AppID: "b", Image: regHost + "/org/b", Tag: "1.0.0", Version: "1.0.0",
			Platform: feed.ReleasePlatform{OS: "linux", Arch: "amd64"}, ManifestDigest: digestOf([]byte("m")),
			Read: now0.Add(-40 * 24 * time.Hour), Packages: nil}
		b, _ := json.Marshal(old)
		if err := s.PutReleaseRead(t.Context(), "b", old.Image, "linux/amd64", "1.0.0", digestOf([]byte("i")), b, old.Read); err != nil {
			t.Fatal(err)
		}
		f.take()
		r.MaxManifests = manifestsPerImage
		// b first by order: still after nothing, so b is read and a is not.
		lines, st := run(t, r, cat, "b", "a")
		reqs := f.take()
		if !st.BudgetSpent || st.NotStarted != 1 || st.Read != 1 || st.Stale != 0 {
			t.Fatalf("stats %+v", st)
		}
		if count(reqs, "/org/a/") != 0 || len(lines) != 2 || lines[0].AppID != "b" || lines[0].Tag != "2.0.0" {
			t.Fatalf("requests %v lines %+v", reqs, lines)
		}
		// Now a goes first: b is not started and its line ships as read.
		lines, st = run(t, r, cat, "a", "b")
		if !st.BudgetSpent || st.NotStarted != 1 || len(lines) != 4 {
			t.Fatalf("stats %+v lines %d", st, len(lines))
		}
	})

	t.Run("bytes", func(t *testing.T) {
		f.push(t, "org/c", "1.0.0", false, debian("amd64", "", "c=1"), debian("arm64", "", "c=1"))
		cat := newCatalog(t, []catalog.Entry{reviewedEntry("a", regHost+"/org/a"), reviewedEntry("b", regHost+"/org/b"), reviewedEntry("c", regHost+"/org/c")}, nil)
		r, s := newReader(t, f)
		old := feed.ReleaseLine{AppID: "b", Image: regHost + "/org/b", Tag: "1.0.0", Version: "1.0.0",
			Platform: feed.ReleasePlatform{OS: "linux", Arch: "amd64"}, ManifestDigest: digestOf([]byte("m")),
			Read: now0.Add(-40 * 24 * time.Hour)}
		b, _ := json.Marshal(old)
		if err := s.PutReleaseRead(t.Context(), "b", old.Image, "linux/amd64", "1.0.0", digestOf([]byte("i")), b, old.Read); err != nil {
			t.Fatal(err)
		}
		f.take()
		// a fits a whole budget, not what c leaves of it.
		r.MaxBytes = 86 << 10
		lines, st := run(t, r, cat, "c", "a", "b")
		reqs := f.take()
		if !st.BudgetSpent || st.Read != 1 || st.TooLarge != 0 || st.NotStarted != 2 || st.Stale != 1 || st.Lines != 3 {
			t.Fatalf("stats %+v requests %v", st, reqs)
		}
		for _, req := range reqs {
			if strings.Contains(req, "/org/a/blobs/") && !configBlob(f, req) {
				t.Fatalf("layer fetched past the budget: %s", req)
			}
		}
		if count(reqs, "/org/b/") != 0 || len(lines) != 3 || lines[2].AppID != "b" || !lines[2].Read.Equal(old.Read) || lines[2].Tag != "1.0.0" {
			t.Fatalf("requests %v lines %+v", reqs, lines)
		}
	})
}

// noise returns n bytes gzip does not shrink.
func noise(n int) string {
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return string(b)
}

// configBlob reports whether a blob request is for an image config.
func configBlob(f *fakeRegistry, req string) bool {
	_, d, _ := strings.Cut(req, "/blobs/")
	for _, r := range f.repos {
		if b, ok := r.blobs[d]; ok {
			return bytes.HasPrefix(b, []byte(`{"os"`))
		}
	}
	return false
}

// An incomplete read is marked Partial: an image that names its release
// but has no package database Varde reads, and a view cut at a limit.
// A complete read is not.
func TestPartialMarked(t *testing.T) {
	f := newRegistry(t)
	f.push(t, "org/nodb", "1.0.0", false, platform{arch: "amd64", layers: [][]file{{{"etc/os-release", osRelease}}}})
	f.push(t, "org/big", "1.0.0", false, platform{arch: "amd64", layers: [][]file{
		{{"etc/os-release", osRelease}, {"var/lib/dpkg/status", status("bash=5.2")}},
		{{"usr/share/doc/big", strings.Repeat("x", 64<<10)}},
	}})
	f.push(t, "org/ok", "1.0.0", false, debian("amd64", "", "bash=5.2"))
	cat := newCatalog(t, []catalog.Entry{
		reviewedEntry("nodb", regHost+"/org/nodb"), reviewedEntry("big", regHost+"/org/big"), reviewedEntry("ok", regHost+"/org/ok"),
	}, nil)
	r, _ := newReader(t, f)
	r.Limits = imagelayers.Limits{LayerBytes: 32 << 10}
	lines, st := run(t, r, cat)
	if len(lines) != 3 || st.Partial != 2 {
		t.Fatalf("stats %+v lines %+v", st, lines)
	}
	for _, l := range lines {
		if want := l.AppID != "ok"; l.Partial != want {
			t.Errorf("%s: partial %v, want %v", l.AppID, l.Partial, want)
		}
	}
	// Same limits: nothing is read again.
	if _, st = run(t, r, cat); st.Unchanged != 3 || st.Read != 0 {
		t.Fatalf("same limits: %+v", st)
	}
	// Other limits read the read that stopped at a limit again; complete
	// reads and reads incomplete for another reason are not affected...
	r.Limits = imagelayers.Limits{}
	lines, st = run(t, r, cat)
	if st.Read != 2 || st.Unchanged != 1 || st.Partial != 1 {
		t.Fatalf("other limits: %+v", st)
	}
	for _, l := range lines {
		if want := l.AppID == "nodb"; l.Partial != want {
			t.Errorf("%s under the default limits: partial %v, want %v", l.AppID, l.Partial, want)
		}
	}
}

// Images on the same base layers share the base's records whatever their
// config: a second image reads only its own layer.
func TestSharedBaseAcrossConfigs(t *testing.T) {
	f := newRegistry(t)
	withTop := func(cmd, workDir string, top ...file) platform {
		p := debian("amd64", "", "bash=5.2")
		p.cmd, p.workDir = cmd, workDir
		p.layers = append(p.layers, top)
		return p
	}
	f.push(t, "org/x", "1.0.0", false, withTop("nginx", "/", file{"etc/nginx/nginx.conf", "x"}))
	f.push(t, "org/y", "2.0.0", false, withTop("node", "/app", file{"app/package.json", `{"name":"y","version":"2.0.0"}`}))
	r, _ := newReader(t, f)
	run(t, r, newCatalog(t, []catalog.Entry{reviewedEntry("x", regHost+"/org/x")}, nil))
	f.take()
	lines, st := run(t, r, newCatalog(t, []catalog.Entry{reviewedEntry("x", regHost+"/org/x"), reviewedEntry("y", regHost+"/org/y")}, nil))
	reqs := f.take()
	if st.Read != 1 || st.Unchanged != 1 {
		t.Fatalf("stats %+v", st)
	}
	// y's config and its own layer, not the two base layers.
	if n := count(reqs, "/org/y/blobs/"); n != 2 {
		t.Fatalf("%d blob requests for y: %v", n, reqs)
	}
	for _, l := range lines {
		if l.AppID == "y" && pkgList(l) != "npm:y=2.0.0,dpkg:bash=5.2" {
			t.Fatalf("y packages %s", pkgList(l))
		}
	}
}

// Lines of a superseded read are not shipped: a platform the newest
// release dropped no longer appears, now or in a later unchanged run.
func TestSupersededNotShipped(t *testing.T) {
	f := newRegistry(t)
	f.push(t, "org/app", "1.0.0", false, debian("amd64", "", "bash=5.1"), debian("arm64", "", "bash=5.1"))
	cat := newCatalog(t, []catalog.Entry{reviewedEntry("app", regHost+"/org/app")}, nil)
	r, _ := newReader(t, f)
	if lines, _ := run(t, r, cat); len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	f.push(t, "org/app", "1.1.0", false, debian("amd64", "", "bash=5.2"))
	for i, wantRead := range []int{1, 0} {
		r.Now = func() time.Time { return now0.Add(time.Duration(i+1) * time.Hour) }
		lines, st := run(t, r, cat)
		if st.Read != wantRead || len(lines) != 1 || lines[0].Tag != "1.1.0" || lines[0].Platform.Arch != "amd64" {
			t.Fatalf("run %d: stats %+v lines %+v", i, st, lines)
		}
	}
}

// An image whose layers alone exceed the byte budget is skipped; the run
// goes on with the next image.
func TestLargeImageSkipped(t *testing.T) {
	f := newRegistry(t)
	big := debian("amd64", "", "a=1")
	big.layers = append(big.layers, []file{{"usr/share/doc/noise", noise(24 << 10)}}, []file{{"usr/share/doc/noise2", noise(24 << 10)[1:]}})
	f.push(t, "org/big", "1.0.0", false, big)
	f.push(t, "org/small", "1.0.0", false, debian("amd64", "", "b=1"))
	cat := newCatalog(t, []catalog.Entry{reviewedEntry("big", regHost+"/org/big"), reviewedEntry("small", regHost+"/org/small")}, nil)
	r, _ := newReader(t, f)
	r.MaxBytes = 40 << 10
	lines, st := run(t, r, cat, "big", "small")
	if st.TooLarge != 1 || st.BudgetSpent || st.Read != 1 || len(lines) != 1 || lines[0].AppID != "small" {
		t.Fatalf("stats %+v lines %+v", st, lines)
	}
	// Layers past LayerBytes are never fetched, so they do not count.
	r2, _ := newReader(t, f)
	r2.MaxBytes = 40 << 10
	r2.Limits = imagelayers.Limits{LayerBytes: 8 << 10}
	if _, st := run(t, r2, cat, "big", "small"); st.TooLarge != 0 || st.Read != 2 {
		t.Fatalf("with a layer limit: %+v", st)
	}
}

// A line that fails validation is left out and counted; the run goes on.
func TestInvalidLineSkipped(t *testing.T) {
	f := newRegistry(t)
	bad := debian("amd64", "", "bash=5.2")
	bad.layers[0][0].body = "NAME=" + strings.Repeat("n", 200) + "\nID=debian\nVERSION_ID=12\n"
	f.push(t, "org/bad", "1.0.0", false, bad)
	f.push(t, "org/ok", "1.0.0", false, debian("amd64", "", "bash=5.2"))
	cat := newCatalog(t, []catalog.Entry{reviewedEntry("bad", regHost+"/org/bad"), reviewedEntry("ok", regHost+"/org/ok")}, nil)
	r, _ := newReader(t, f)
	lines, st := run(t, r, cat)
	if len(lines) != 1 || lines[0].AppID != "ok" || st.Invalid != 1 {
		t.Fatalf("stats %+v lines %+v", st, lines)
	}
}

// Reviewed apps are read before generated ones, whatever order says.
func TestPriority(t *testing.T) {
	cat := newCatalog(t,
		[]catalog.Entry{reviewedEntry("zeta", "docker.io/x/zeta"), reviewedEntry("alpha", "docker.io/x/alpha")},
		[]catalog.Entry{generatedEntry("gh-x-light", "docker.io/x/light"), generatedEntry("gh-x-heavy", "docker.io/x/heavy")})
	got := Priority(cat, map[string]int64{"gh-x-heavy": 9, "gh-x-light": 1})
	if strings.Join(got, ",") != "alpha,zeta,gh-x-heavy,gh-x-light" {
		t.Fatalf("priority %v", got)
	}
	r := &Reader{}
	var ids []string
	for _, j := range r.jobs(cat, []string{"gh-x-light", "zeta"}) {
		ids = append(ids, j.app.ID)
	}
	if strings.Join(ids, ",") != "zeta,alpha,gh-x-light,gh-x-heavy" {
		t.Fatalf("jobs %v", ids)
	}
}
