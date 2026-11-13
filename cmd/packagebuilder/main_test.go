// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/catgen"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pkgbuild"
	"github.com/bifrost0x/varde/internal/releases"
	"github.com/bifrost0x/varde/internal/store"
)

const widgetEntry = `id: widget
name: Widget
homepage: https://widget.example
images: [{match: ghcr.io/acme/widget}]
version: {scheme: semver}
advisories: {coverage: full, github_repos: [acme/widget]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`

type harness struct {
	t        *testing.T
	srv      *httptest.Server
	requests atomic.Int64
	// advisories is how many advisories acme/widget has.
	advisories atomic.Int64
	feedKey    ed25519.PrivateKey
	keyPEM     string
	cfg        config
	now        time.Time
}

func pemOf(t *testing.T, k ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, now: time.Date(2026, 11, 11, 2, 17, 0, 0, time.UTC)}
	h.advisories.Store(20)
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.requests.Add(1)
		switch {
		case r.URL.Path == "/kev":
			var b strings.Builder
			b.WriteString(`{"vulnerabilities":[`)
			for i := range 150 {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"cveID":"CVE-2025-%04d","dateAdded":"2025-06-01","knownRansomwareCampaignUse":"Unknown"}`, i)
			}
			b.WriteString(`]}`)
			_, _ = w.Write([]byte(b.String()))
		case r.URL.Path == "/epss":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case strings.HasPrefix(r.URL.Path, "/repos/acme/widget/"):
			items := []map[string]any{}
			for i := range h.advisories.Load() {
				items = append(items, map[string]any{"ghsa_id": fmt.Sprintf("GHSA-aaaa-aaaa-%04d", i), "summary": "test", "severity": "high",
					"published_at": "2026-11-01T00:00:00Z", "updated_at": "2026-11-01T00:00:00Z"})
			}
			w.Header().Set("X-RateLimit-Remaining", "900")
			_ = json.NewEncoder(w).Encode(items)
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	t.Cleanup(h.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(h.srv.Certificate())

	rootKey, _ := feed.NewKey()
	h.feedKey, _ = feed.NewKey()
	h.keyPEM = pemOf(t, h.feedKey)
	root, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: h.now.Add(365 * 24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{h.feedKey.Public().(ed25519.PublicKey)},
		RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.json")
	if err := os.WriteFile(rootFile, root, 0o600); err != nil {
		t.Fatal(err)
	}
	catDir := filepath.Join(dir, "catalog")
	if err := os.MkdirAll(catDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(catDir, "widget.yaml"), []byte(widgetEntry), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := applists.Unmarshal([]byte("docker.io/other/tool\tgithub.com/other/tool\thub,readme\n"))
	if err != nil {
		t.Fatal(err)
	}
	h.cfg = config{db: filepath.Join(dir, "cache", "builder.db"), out: filepath.Join(dir, "work", "feed"), root: rootFile, catalogDir: catDir,
		valid: 7 * 24 * time.Hour, maxWait: time.Minute, githubURL: h.srv.URL, kevURL: h.srv.URL + "/kev", epssURL: h.srv.URL + "/epss",
		http: httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second}), now: func() time.Time { return h.now }, table: table,
		allowDevelopment: true}
	return h
}

func (h *harness) run(key string) (string, error) {
	var out bytes.Buffer
	err := run(context.Background(), h.cfg, func(k string) string {
		if k == "VARDE_FEED_KEY" {
			return key
		}
		return ""
	}, &out)
	return out.String(), err
}

func TestBuildEndToEnd(t *testing.T) {
	h := newHarness(t)
	out, err := h.run(h.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// The catalog app's advisories twice (its ID and the derived one).
	if !strings.Contains(out, "2 repositories (0 failed), 40 advisories, 150 KEV") || !strings.Contains(out, "1 index rows") {
		t.Fatalf("summary: %s", out)
	}
	for _, f := range []string{"v1/root.json", "v1/manifest.json", "v1/manifest.json.sig", "stats.json"} {
		if _, err := os.Stat(filepath.Join(h.cfg.out, f)); err != nil {
			t.Errorf("%s missing from the package: %v", f, err)
		}
	}
	counts, have, err := pkgbuild.ReadCounts(h.cfg.out)
	if err != nil || !have || counts.Advisories != 40 || counts.Sequence != h.now.Unix() {
		t.Fatalf("stats.json: %+v, %v, %v", counts, have, err)
	}
	// Nothing of the staging directory is left beside it.
	entries, _ := os.ReadDir(filepath.Dir(h.cfg.out))
	if len(entries) != 1 {
		t.Errorf("left beside the package: %v", entries)
	}

	// The next day's build is checked against this one.
	h.cfg.previous, h.cfg.out = h.cfg.out, filepath.Join(filepath.Dir(h.cfg.out), "next")
	h.now = h.now.Add(24 * time.Hour)
	h.advisories.Store(10)
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "advisories fell from 40 to 20") {
		t.Fatalf("shrunken build: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.out, "v1", "manifest.json")); err == nil {
		t.Fatal("a refused build left a package behind")
	}
	h.cfg.force = true
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatalf("forced build: %v", err)
	}
}

func TestRefusesBeforeAskingAnyone(t *testing.T) {
	other, _ := feed.NewKey()
	rsa := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	for name, tc := range map[string]struct {
		key  string
		want string
	}{
		"no key":                       {"", "VARDE_FEED_KEY is not set"},
		"not PEM":                      {"c2VjcmV0LWtleS1tYXRlcmlhbA==", "is not PEM"},
		"not a key":                    {rsa, "is not a PKCS#8 private key"},
		"a key the root does not list": {"", "is not a feed key of trust root version 1"},
	} {
		h := newHarness(t)
		key := tc.key
		if name == "a key the root does not list" {
			key = pemOf(t, other)
		}
		_, err := h.run(key)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
			continue
		}
		if key != "" && (strings.Contains(err.Error(), key) || strings.Contains(err.Error(), strings.TrimSpace(strings.Split(key, "\n")[min(1, strings.Count(key, "\n"))]))) {
			t.Errorf("%s: the error repeats the key", name)
		}
		if n := h.requests.Load(); n != 0 {
			t.Errorf("%s: %d requests were made before the refusal", name, n)
		}
		if _, err := os.Stat(h.cfg.db); err == nil {
			t.Errorf("%s: the store was created before the refusal", name)
		}
	}
}

func TestRefusesWithoutRoot(t *testing.T) {
	if feed.EmbeddedRoot() != nil {
		t.Skip("a production root is embedded")
	}
	h := newHarness(t)
	h.cfg.root = ""
	_, err := h.run(h.keyPEM)
	if err == nil || !strings.Contains(err.Error(), "no production root embedded: run the key ceremony (docs/data-package.md)") {
		t.Fatalf("err = %v", err)
	}
	if h.requests.Load() != 0 {
		t.Error("requests were made without a root")
	}
}

func TestRefusesTooManyFailures(t *testing.T) {
	h := newHarness(t)
	upstream := h.srv.Config.Handler
	h.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		upstream.ServeHTTP(w, r)
	})
	_, err := h.run(h.keyPEM)
	if err == nil || !strings.Contains(err.Error(), "2 of 2 repositories could not be read") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.out, "v1", "manifest.json")); err == nil {
		t.Fatal("a refused build left a package behind")
	}
}

func TestRefusesToOverwriteAPackage(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "already holds a package") {
		t.Fatalf("err = %v", err)
	}
}

// rotate signs root version 2 with the harness's first root key and a new
// feed key, and makes the harness build with it.
func (h *harness) rotate(rootKey ed25519.PrivateKey, version int64) {
	h.t.Helper()
	h.feedKey, _ = feed.NewKey()
	h.keyPEM = pemOf(h.t, h.feedKey)
	root, err := feed.SignRoot(feed.RootSpec{Version: version, Expires: h.now.Add(365 * 24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{h.feedKey.Public().(ed25519.PublicKey)},
		RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.cfg.root, root, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// The branch is replaced with every build, so the builder has to carry
// the earlier roots along: an installation that missed a rotation walks
// the chain version by version.
func TestRootChainIsCarried(t *testing.T) {
	h := newHarness(t)
	rootKey, _ := feed.NewKey()
	h.rotate(rootKey, 1)
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatal(err)
	}
	// Every rotation here brings a new feed key, so the old baseline no
	// longer verifies: the maintainer builds with -force that day.
	h.cfg.force = true
	for v := int64(2); v <= 3; v++ {
		h.cfg.previous, h.cfg.out = h.cfg.out, filepath.Join(filepath.Dir(h.cfg.out), fmt.Sprintf("v%d", v))
		h.now = h.now.Add(24 * time.Hour)
		h.rotate(rootKey, v)
		if _, err := h.run(h.keyPEM); err != nil {
			t.Fatalf("build with root %d: %v", v, err)
		}
	}
	for _, f := range []string{"v1/root/1.json", "v1/root/2.json", "v1/root/3.json", "v1/root.json"} {
		if _, err := os.Stat(filepath.Join(h.cfg.out, f)); err != nil {
			t.Errorf("%s missing after two rotations: %v", f, err)
		}
	}
	latest, _ := os.ReadFile(filepath.Join(h.cfg.out, "v1", "root.json"))
	third, _ := os.ReadFile(filepath.Join(h.cfg.out, "v1", "root", "3.json"))
	if !bytes.Equal(latest, third) {
		t.Error("root.json is not the newest root")
	}

	// A root older than the published one would make every installation
	// refuse the mirror; one that skips a version breaks the chain.
	h.cfg.previous, h.cfg.out = h.cfg.out, filepath.Join(filepath.Dir(h.cfg.out), "older")
	h.now = h.now.Add(24 * time.Hour)
	h.rotate(rootKey, 2)
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "older than the published") {
		t.Fatalf("older root: %v", err)
	}
	h.rotate(rootKey, 5)
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "skips") {
		t.Fatalf("skipped version: %v", err)
	}
	h.rotate(rootKey, 3) // version 3 again, but other bytes
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "differs from the published") {
		t.Fatalf("same version, other root: %v", err)
	}
	if h.requests.Load() == 0 {
		t.Fatal("no requests at all")
	}
}

// nextBuild points the harness at a new output directory with the last
// one as the published package, a day later.
func (h *harness) nextBuild(name string) {
	h.cfg.previous, h.cfg.out = h.cfg.out, filepath.Join(filepath.Dir(h.cfg.out), name)
	h.now = h.now.Add(24 * time.Hour)
}

// The store comes back from the published branch, which more people and
// tokens can write than can sign. A store the feed key did not sign is
// thrown away: the builder asks the sources again instead of signing what
// someone put there.
func TestTamperedStoreIsNotTrusted(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.cfg.db + ".sig"); err != nil {
		t.Fatalf("the store was not signed: %v", err)
	}
	// Someone replaces the store: every source "not due", one advisory added.
	st, err := store.Open(context.Background(), h.cfg.db)
	if err != nil {
		t.Fatal(err)
	}
	far := h.now.Add(1000 * time.Hour)
	for _, key := range [][2]string{{"github", "acme/widget"}, {"github", "other/tool"}, {"kev", "catalog"}, {"epss", "scores"}} {
		if err := st.PutSourceState(context.Background(), store.SourceState{Source: key[0], Key: key[1], LastSuccess: h.now, NextRun: far}); err != nil {
			t.Fatal(err)
		}
	}
	evil := []store.AdvisoryRecord{{AppID: "gh-acme-widget", Vuln: advisory.Vulnerability{SchemaVersion: "1.6.0", ID: "GHSA-evil-evil-9999", Modified: h.now}}}
	if err := st.ReplaceAdvisories(context.Background(), "gh-acme-widget", "github:acme/widget", evil, h.now); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	h.nextBuild("second")
	before := h.requests.Load()
	out, err := h.run(h.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if h.requests.Load()-before < 3 {
		t.Fatalf("the builder trusted the store: %d requests\n%s", h.requests.Load()-before, out)
	}
	if !strings.Contains(out, "40 advisories") {
		t.Fatalf("summary: %s", out)
	}
	// An untouched, signed store is used: the next build asks conditionally
	// and still publishes the same advisories.
	h.nextBuild("third")
	if out, err = h.run(h.keyPEM); err != nil || !strings.Contains(out, "40 advisories") {
		t.Fatalf("third build: %v\n%s", err, out)
	}
}

// The baseline for the shrink check is signed too.
func TestUnsignedBaselineIsRefused(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatal(err)
	}
	stats := filepath.Join(h.cfg.out, "stats.json")
	if err := os.WriteFile(stats, []byte(`{"sequence": 1, "advisories": 1, "kev": 1, "epss": 0, "index": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.nextBuild("second")
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("tampered baseline: %v", err)
	}
	h.cfg.force = true
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatalf("forced build without a baseline: %v", err)
	}
}

// Nothing but real root files is carried from the published branch: a
// symlink there could point at the builder's own environment, which holds
// the key.
func TestCarriedRootsAreCheckedFiles(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("VARDE_FEED_KEY=very-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(h.cfg.out, "v1", "root", "7.json")); err != nil {
		t.Skip("no symlinks here")
	}
	h.nextBuild("second")
	_, err := h.run(h.keyPEM)
	if err == nil || !strings.Contains(err.Error(), "7.json") {
		t.Fatalf("a symlink among the published roots: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(h.cfg.out, "v1")); statErr == nil {
		t.Fatal("a package was written")
	}
	// A file that is not the root its name says is refused as well.
	link := filepath.Join(h.cfg.previous, "v1", "root", "7.json")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte(`{"not":"a root"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "7.json") {
		t.Fatalf("a junk file among the published roots: %v", err)
	}
}

// A rotation the published root does not endorse would strand every
// installation; the builder refuses to publish it.
func TestUnendorsedRotationIsRefused(t *testing.T) {
	h := newHarness(t)
	rootKey, _ := feed.NewKey()
	h.rotate(rootKey, 1)
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatal(err)
	}
	h.nextBuild("second")
	stranger, _ := feed.NewKey()
	h.rotate(stranger, 2) // signed by a key root 1 does not know
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "not endorsed") {
		t.Fatalf("unendorsed rotation: %v", err)
	}
	h.rotate(rootKey, 2)
	h.cfg.force = true // a new feed key: the old baseline cannot be verified
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatalf("endorsed rotation: %v", err)
	}
}

func TestRefusesANonEmptyOutputDirectory(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(h.cfg.out, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(h.cfg.out, "something.txt")
	if err := os.WriteFile(keep, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("the builder deleted a file in a mistyped output directory")
	}
}

// A package signed under a development root must never be published by
// accident: installations refuse such a root, and a mirror that serves
// one stops them all.
func TestRefusesADevelopmentRoot(t *testing.T) {
	h := newHarness(t)
	h.cfg.allowDevelopment = false
	_, err := h.run(h.keyPEM)
	if err == nil || !strings.Contains(err.Error(), "development root") {
		t.Fatalf("err = %v", err)
	}
	if h.requests.Load() != 0 {
		t.Error("requests were made before the refusal")
	}
	h.cfg.allowDevelopment = true
	out, err := h.run(h.keyPEM)
	if err != nil || !strings.Contains(out, "DEVELOPMENT trust root") {
		t.Fatalf("allowed development build: %v\n%s", err, out)
	}
}

// genRegistry, genGitHub and genHub serve the generator in tests.
type genRegistry struct{ tags map[string][]string }

func (r genRegistry) AllTags(_ context.Context, repository string) ([]string, bool, error) {
	t, ok := r.tags[repository]
	if !ok {
		return nil, false, catgen.ErrNotFound
	}
	return t, true, nil
}

func (r genRegistry) Digest(_ context.Context, repository, tag string) (string, error) {
	if repository == "docker.io/other/tool" && tag == "1.2.0" {
		return "sha256:" + strings.Repeat("a", 64), nil
	}
	return "", catgen.ErrNotFound
}

type genGitHub struct{ releases map[string][]catgen.Release }

func (g *genGitHub) Releases(_ context.Context, repo, etag string) ([]catgen.Release, string, bool, error) {
	rels, ok := g.releases[repo]
	if !ok {
		return nil, "", false, catgen.ErrNotFound
	}
	cur := fmt.Sprintf(`"%d"`, len(rels))
	if etag == cur {
		return nil, cur, true, nil
	}
	return rels, cur, false, nil
}

type genHub struct{}

func (genHub) PullCount(context.Context, string) (int64, error) { return 5000, nil }

func readGenerated(t *testing.T, dir string) (genState, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "catalog", "generated.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s genState
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(dir, "catalog", "generated.md"))
	if err != nil {
		t.Fatal(err)
	}
	return s, string(md)
}

func TestBuildWritesGeneratedFiles(t *testing.T) {
	h := newHarness(t)
	gh := &genGitHub{releases: map[string][]catgen.Release{"other/tool": {{Tag: "1.2.0"}, {Tag: "1.1.0"}, {Tag: "1.0.0"}}}}
	h.cfg.generate, h.cfg.releases = true, true
	h.cfg.sources = &genSources{registry: genRegistry{tags: map[string][]string{"docker.io/other/tool": {"latest", "1.0.0", "1.1.0", "1.2.0"}}},
		github: gh, hub: genHub{}}
	var order []string
	h.cfg.readReleases = func(_ context.Context, cat *catalog.Catalog, o []string) ([]feed.ReleaseLine, releases.Stats, error) {
		order = o
		if a, ok := cat.App("gh-other-tool"); ok && a.Origin != catalog.OriginGenerated {
			t.Errorf("generated entry read as %s", a.Origin)
		}
		return []feed.ReleaseLine{{AppID: "widget", Image: "ghcr.io/acme/widget", Tag: "v2.0.0", Version: "2.0.0",
				Platform: feed.ReleasePlatform{OS: "linux", Arch: "amd64"}, ManifestDigest: "sha256:" + strings.Repeat("b", 64), Read: h.now,
				Packages: []inventory.Package{{Manager: "dpkg", Name: "openssl", Version: "3.0.15-1", Distro: "debian-12", Source: "openssl"}}}},
			releases.Stats{Images: 2, Read: 1, Lines: 1}, nil
	}
	work := filepath.Dir(h.cfg.out)

	out, err := h.run(h.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Reviewed apps first, then the generated ones.
	if len(order) != 2 || order[0] != "widget" || order[1] != "gh-other-tool" {
		t.Errorf("release order = %v", order)
	}
	if !strings.Contains(out, "generated: 1 entries (1 new, 0 changed, 0 dropped images; 0 failed, 0 not checked)") || !strings.Contains(out, "releases: 1 lines") {
		t.Errorf("summary: %s", out)
	}
	counts, _, err := pkgbuild.ReadCounts(h.cfg.out)
	if err != nil || counts.Generated != 1 || counts.Releases != 1 || counts.ReleasesBytes == 0 {
		t.Fatalf("counts = %+v, %v", counts, err)
	}
	s, md := readGenerated(t, work)
	if len(s.Entries) != 1 || s.Entries[0].ID != "gh-other-tool" || !strings.Contains(s.Entries[0].YAML, "maintainers_of_entry: [generator]") {
		t.Fatalf("entries = %+v", s.Entries)
	}
	if len(s.Images) != 1 || s.Images[0].Status != genShipped || s.Images[0].Entry != "gh-other-tool" || len(s.Images[0].Checks) != 6 ||
		s.Images[0].Checks[5] != (genCheck{"C6", checkPass}) || s.Images[0].Hash == "" {
		t.Fatalf("images = %+v", s.Images)
	}
	for _, want := range []string{"| Entries shipped | 1 |", "| New | 1 |", "## New\n\n- docker.io/other/tool\n", "no list published before"} {
		if !strings.Contains(md, want) {
			t.Errorf("generated.md lacks %q:\n%s", want, md)
		}
	}

	// The next day: a project that fails C3 joins; the shipped one stays
	// and is compared with the list published before.
	h.cfg.previous, h.cfg.out = h.cfg.out, filepath.Join(work, "next")
	h.now = h.now.Add(24 * time.Hour)
	table, err := applists.Unmarshal([]byte("docker.io/other/tool\tgithub.com/other/tool\thub,readme\ndocker.io/third/app\tgithub.com/third/app\thub,readme\n"))
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.table = table
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatal(err)
	}
	s, md = readGenerated(t, work)
	if len(s.Images) != 2 || s.Images[1].Image != "docker.io/third/app" || s.Images[1].Status != genFailed || s.Images[1].FailedCheck != "C3" ||
		s.Images[1].Checks[2] != (genCheck{"C3", checkFail}) || s.Images[1].Checks[3] != (genCheck{"C4", checkNotRun}) {
		t.Fatalf("images = %+v", s.Images)
	}
	for _, want := range []string{"Compared with the list of the build of 2026-11-11 02:17 UTC", "| New | 0 |", "| Failed C3 | 1 |",
		"## Failures\n\n- docker.io/third/app: C3: "} {
		if !strings.Contains(md, want) {
			t.Errorf("generated.md lacks %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "## New") {
		t.Errorf("unchanged entry listed as new:\n%s", md)
	}

	// A new GitHub release the tags do not follow fails C4: the only
	// entry drops, which the guard refuses without -force. The list
	// published before stays as it was.
	gh.releases["other/tool"] = append([]catgen.Release{{Tag: "2.0.0"}}, gh.releases["other/tool"]...)
	h.cfg.previous, h.cfg.out = h.cfg.out, filepath.Join(work, "third")
	h.now = h.now.Add(24 * time.Hour)
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "generated entries fell from 1 to 0") {
		t.Fatalf("dropped entries: %v", err)
	}
	if again, _ := readGenerated(t, work); again.Sequence != s.Sequence {
		t.Fatal("a refused build replaced the published list")
	}
	h.cfg.force = true
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatalf("forced build: %v", err)
	}
	s, md = readGenerated(t, work)
	if len(s.Entries) != 0 || !strings.Contains(md, "## Dropped\n\n- docker.io/other/tool\n") || !strings.Contains(md, "| Dropped | 1 |") {
		t.Fatalf("after the drop: %+v\n%s", s.Entries, md)
	}

	// Without the generator no list is left to be published as this
	// build's.
	h.cfg.generate = false
	h.cfg.previous, h.cfg.out = h.cfg.out, filepath.Join(work, "fourth")
	h.now = h.now.Add(24 * time.Hour)
	if _, err := h.run(h.keyPEM); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"generated.json", "generated.md"} {
		if _, err := os.Stat(filepath.Join(work, "catalog", f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left from an earlier build: %v", f, err)
		}
	}
}

// The release lines that do not fit the budget go, the lowest priority
// first, and the store keeps only the reads that ship; the summary gives
// the sizes of the releases blob and of the store.
func TestReleasesFitTheBudget(t *testing.T) {
	h := newHarness(t)
	h.cfg.releases = true
	line := func(app string) feed.ReleaseLine {
		return feed.ReleaseLine{AppID: app, Image: "ghcr.io/acme/" + app, Tag: "v2.0.0", Version: "2.0.0",
			Platform: feed.ReleasePlatform{OS: "linux", Arch: "amd64"}, ManifestDigest: "sha256:" + strings.Repeat("b", 64), Read: h.now,
			Packages: []inventory.Package{{Manager: "dpkg", Name: app, Version: "3.0.15-1", Distro: "debian-12", Source: app}}}
	}
	lines := []feed.ReleaseLine{line("widget"), line("second"), line("third")}
	one, size, err := feed.FitReleases(lines[:1], 1<<30)
	if err != nil || len(one) != 1 {
		t.Fatal(err)
	}
	h.cfg.releasesBudget = size + 10
	h.cfg.readReleases = func(context.Context, *catalog.Catalog, []string) ([]feed.ReleaseLine, releases.Stats, error) {
		return lines, releases.Stats{Lines: 3}, nil
	}
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Dir(h.cfg.db), 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, h.cfg.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if err := st.PutReleaseRead(ctx, l.AppID, l.Image, "linux/amd64", l.Tag, "sha256:i", []byte(`{}`), h.now); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// A store the feed key did not sign is dropped: sign this one.
	if err := pkgbuild.Seal(h.cfg.db, pkgbuild.PurposeStore, h.feedKey); err != nil {
		t.Fatal(err)
	}
	out, err := h.run(h.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "releases: 1 lines, ") || !strings.Contains(out, "2 lines over the size budget") || !strings.Contains(out, "store: builder.db.gz ") ||
		!strings.Contains(out, "pruned 2 release reads") {
		t.Fatalf("summary: %s", out)
	}
	counts, _, err := pkgbuild.ReadCounts(h.cfg.out)
	if err != nil || counts.Releases != 1 {
		t.Fatalf("counts %+v, %v", counts, err)
	}
	st, err = store.Open(ctx, h.cfg.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for _, l := range lines {
		_, _, _, ok, err := st.ReleaseRead(ctx, l.AppID, l.Image, "linux/amd64")
		if err != nil || ok != (l.AppID == "widget") {
			t.Errorf("release read of %s kept %v (%v)", l.AppID, ok, err)
		}
	}
}

// A store over the limit drops its layer reads; one still over the limit
// is refused and nothing is published.
func TestStoreSizeGuard(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "builder.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	noise := make([]byte, 1<<20)
	for i := range noise {
		noise[i] = byte(i*7919 + i/13)
	}
	for i := range 3 {
		if err := st.PutLayerRead(ctx, fmt.Sprintf("layer-%d", i), noise, false, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	full, err := gzipSize(path)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	if size, dropped, err := fitStore(ctx, path, full, logger); err != nil || size != full || dropped != 0 {
		t.Fatalf("under the limit: %d, %d, %v", size, dropped, err)
	}
	size, dropped, err := fitStore(ctx, path, full-1, logger)
	if err != nil || dropped != 3 || size >= full {
		t.Fatalf("over the limit: %d of %d, %d dropped, %v", size, full, dropped, err)
	}
	if _, _, err := fitStore(ctx, path, 1, logger); err == nil || !strings.Contains(err.Error(), "over the limit") {
		t.Fatalf("still over the limit: %v", err)
	}

	h := newHarness(t)
	h.cfg.storeLimit = 1
	if _, err := h.run(h.keyPEM); err == nil || !strings.Contains(err.Error(), "builder's store") {
		t.Fatalf("store over the limit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.out, "v1", "manifest.json")); err == nil {
		t.Fatal("a refused build left a package behind")
	}
	if _, err := os.Stat(h.cfg.db + ".sig"); err == nil {
		t.Fatal("a refused store was signed")
	}
}
