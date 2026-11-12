// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/advisory/sources"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/datapkg"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/pipeline"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/uplink"
)

// uplinkGate serves a development feed and, like the real gate, answers
// only requests that carry a license.
type uplinkGate struct {
	srv        *httptest.Server
	mu         sync.Mutex
	requests   int
	withAuth   int
	rootFile   string
	caFile     string
	licenseKey ed25519.PrivateKey
	feedKey    ed25519.PrivateKey
	rootData   []byte
}

// packageDir publishes a data package under the gate's trust root into a
// directory of its own and returns its file:// mirror.
func (g *uplinkGate) packageDir(t *testing.T, seq int64, index string) string {
	t.Helper()
	dir := t.TempDir()
	if err := feed.WriteRoot(dir, 1, g.rootData); err != nil {
		t.Fatal(err)
	}
	immich, err := os.ReadFile(filepath.Join("..", "..", "catalog", "apps", "immich.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	line := func(id string) feed.AdvisoryLine {
		return feed.AdvisoryLine{AppID: "immich", CVSS: 7.5, Severity: "high",
			OSV: advisory.Vulnerability{SchemaVersion: "1.6.0", ID: id, Modified: now}}
	}
	if _, err := feed.WriteSnapshot(dir, feed.Snapshot{Channel: feed.ChannelPackage, Sequence: seq, CreatedAt: now, ExpiresAt: now.Add(time.Hour), CatalogVersion: "pkg",
		Catalog:    []catalog.Entry{{Name: "immich.yaml", Data: string(immich)}},
		Advisories: []feed.AdvisoryLine{line("GHSA-pkg0-test-0001"), line("GHSA-pkg0-test-0002")},
		Index:      []byte(index),
	}, g.feedKey); err != nil {
		t.Fatal(err)
	}
	return "file://" + filepath.ToSlash(dir)
}

func newUplinkGate(t *testing.T) *uplinkGate {
	t.Helper()
	g := &uplinkGate{}
	pubKey := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	rootKey, _ := feed.NewKey()
	feedKey, _ := feed.NewKey()
	g.feedKey = feedKey
	g.licenseKey, _ = feed.NewKey()
	now := time.Now().UTC()
	dir := t.TempDir()
	rootData, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: now.Add(24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{pubKey(rootKey)}, FeedKeys: []ed25519.PublicKey{pubKey(feedKey)},
		LicenseKeys: []ed25519.PublicKey{pubKey(g.licenseKey)}, RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	g.rootData = rootData
	if err := feed.WriteRoot(dir, 1, rootData); err != nil {
		t.Fatal(err)
	}
	immich, err := os.ReadFile(filepath.Join("..", "..", "catalog", "apps", "immich.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := feed.WriteSnapshot(dir, feed.Snapshot{Channel: feed.ChannelUplink, Sequence: 200, CreatedAt: now, ExpiresAt: now.Add(time.Hour), CatalogVersion: "e2e",
		Catalog: []catalog.Entry{{Name: "immich.yaml", Data: string(immich)}},
		Advisories: []feed.AdvisoryLine{{AppID: "immich", CVSS: 9.1, Severity: "critical",
			OSV: advisory.Vulnerability{SchemaVersion: "1.6.0", ID: "GHSA-e2e0-test-0001", Modified: now}}},
	}, feedKey); err != nil {
		t.Fatal(err)
	}
	files := http.FileServer(http.Dir(dir))
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.requests++
		ok := strings.HasPrefix(r.Header.Get("Authorization"), "Varde-License ")
		if ok {
			g.withAuth++
		}
		g.mu.Unlock()
		if !ok {
			http.Error(w, "license required", http.StatusUnauthorized)
			return
		}
		files.ServeHTTP(w, r)
	}))
	t.Cleanup(g.srv.Close)
	g.rootFile = filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(g.rootFile, rootData, 0o600); err != nil {
		t.Fatal(err)
	}
	g.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(g.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *uplinkGate) counts() (requests, withAuth int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests, g.withAuth
}

func (g *uplinkGate) license(t *testing.T, valid time.Duration) []byte {
	t.Helper()
	now := time.Now().UTC()
	doc, err := feed.IssueLicense(feed.License{ID: "lic_e2e0e2e0e2e0e2e0e2e0", Plan: feed.PlanUplink,
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(valid)}, g.licenseKey)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

type uplinkInstall struct {
	st        *store.Store
	analysis  *pipeline.Pipeline
	refresher *sources.Refresher
	mgr       *uplink.Manager
	pkg       *datapkg.Manager
	set       *settings.Service
}

// startUplinkInstall wires the advisory side of a server as serve does.
func startUplinkInstall(t *testing.T, env map[string]string) *uplinkInstall {
	t.Helper()
	ctx := context.Background()
	if env["VARDE_DATA_DIR"] == "" {
		env["VARDE_DATA_DIR"] = t.TempDir()
	}
	// These tests are about an installation without a data package unless
	// they name one.
	if _, ok := env["VARDE_PACKAGE_URLS"]; !ok {
		env["VARDE_PACKAGE_URLS"] = ""
	}
	// No request may leave for the public sources during the test.
	env["VARDE_EGRESS_ALLOWLIST"] = "127.0.0.1"
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	cat, local, err := loadCatalog(cfg.CatalogDir, logger)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, "varde.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	set, err := settings.New(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	analysis := pipeline.New(cat, st, logger, pipeline.Options{
		Exposure: set.Exposure,
		Policy:   func() policy.Thresholds { return set.Get().Policy },
		Scope:    func() discovery.Scope { return set.Get().Networks },
	})
	refresher, mgr, pkg, err := newRefresher(ctx, cfg, st, analysis, set, local, logger)
	if err != nil {
		t.Fatal(err)
	}
	return &uplinkInstall{st: st, analysis: analysis, refresher: refresher, mgr: mgr, pkg: pkg, set: set}
}

func (i *uplinkInstall) sourceNames() string {
	var names []string
	picked := i.refresher.Sources
	if i.refresher.Pick != nil {
		picked = i.refresher.Pick()
	}
	for _, s := range picked {
		names = append(names, s.Name())
	}
	return strings.Join(names, ",")
}

func (i *uplinkInstall) feedAdvisories(t *testing.T) int {
	t.Helper()
	recs, err := i.st.Advisories(context.Background(), "immich")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range recs {
		if r.Source == store.FeedSource {
			n++
		}
	}
	return n
}

func (i *uplinkInstall) immichOrigin() catalog.Origin {
	app, ok := i.analysis.Catalog().Current().App("immich")
	if !ok {
		return ""
	}
	return app.Origin
}

// The whole path of the uplink switch: free by default, on with a license,
// back to free when the license runs out.
func TestUplinkE2E(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	in := startUplinkInstall(t, map[string]string{
		"VARDE_FEED_URLS": g.srv.URL, "VARDE_FEED_ROOT_FILE": g.rootFile,
		"VARDE_FEED_ALLOW_DEVELOPMENT_ROOT": "true", "VARDE_CA_BUNDLE_FILE": g.caFile,
	})

	// Free: the direct sources, and nothing reaches the uplink.
	if s := in.mgr.Status(); s.State != uplink.Off || !s.Development || s.Locked {
		t.Fatalf("fresh install: %+v", s)
	}
	// Nothing is downloaded to recognise apps: no app store list source.
	if names := in.sourceNames(); strings.Contains(names, "applists") {
		t.Fatalf("an installation must not fetch app store lists: %s", names)
	}
	if names := in.sourceNames(); strings.Contains(names, "feed") || !strings.Contains(names, "github") || !strings.Contains(names, "kev") {
		t.Fatalf("free sources: %s", names)
	}
	in.refresher.RunOnce(ctx)
	if n, _ := g.counts(); n != 0 {
		t.Fatalf("%d requests reached the uplink while it was off", n)
	}
	if in.immichOrigin() != catalog.OriginBuiltin || in.feedAdvisories(t) != 0 {
		t.Fatalf("free state: origin %q, feed advisories %d", in.immichOrigin(), in.feedAdvisories(t))
	}

	// On: the license goes with every request, the feed is installed.
	if err := in.mgr.Enable(ctx, g.license(t, 2*time.Second), "admin"); err != nil {
		t.Fatalf("switch on: %v", err)
	}
	requests, withAuth := g.counts()
	if requests == 0 || requests != withAuth {
		t.Fatalf("uplink requests %d, with license %d", requests, withAuth)
	}
	if names := in.sourceNames(); !strings.HasPrefix(names, "feed,") || strings.Contains(names, "kev") {
		t.Fatalf("uplink sources: %s", names)
	}
	if in.immichOrigin() != catalog.OriginFeed || in.feedAdvisories(t) != 1 {
		t.Fatalf("uplink state: origin %q, feed advisories %d", in.immichOrigin(), in.feedAdvisories(t))
	}
	in.refresher.RunOnce(ctx)
	if in.feedAdvisories(t) != 1 {
		t.Fatal("feed advisories lost by a refresh")
	}

	// The license runs out: back to free on its own.
	deadline := time.Now().Add(10 * time.Second)
	for in.mgr.Active() {
		if time.Now().After(deadline) {
			t.Fatal("license did not expire")
		}
		time.Sleep(50 * time.Millisecond)
	}
	before, _ := g.counts()
	in.refresher.RunOnce(ctx)
	if s := in.mgr.Status(); s.State != uplink.Expired {
		t.Fatalf("after expiry: %+v", s)
	}
	if names := in.sourceNames(); strings.Contains(names, "feed") {
		t.Fatalf("sources after expiry: %s", names)
	}
	if after, _ := g.counts(); after != before {
		t.Errorf("%d requests reached the uplink after expiry", after-before)
	}
	if in.immichOrigin() != catalog.OriginBuiltin || in.feedAdvisories(t) != 0 {
		t.Fatalf("after expiry: origin %q, feed advisories %d", in.immichOrigin(), in.feedAdvisories(t))
	} // The user is told on the overview, not only in the settings.
	notices, err := in.st.ActiveNotices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	told := false
	for _, n := range notices {
		told = told || (n.Kind == store.NoticeUplink && strings.Contains(n.Title, "expired"))
	}
	if !told {
		t.Errorf("no system notice that the uplink ended by itself: %+v", notices)
	}
}

// A development root is refused without the explicit opt-in; Varde then
// runs free and says why the uplink cannot be used.
func TestUplinkE2EDevelopmentRootRefused(t *testing.T) {
	g := newUplinkGate(t)
	in := startUplinkInstall(t, map[string]string{
		"VARDE_FEED_URLS": g.srv.URL, "VARDE_FEED_ROOT_FILE": g.rootFile, "VARDE_CA_BUNDLE_FILE": g.caFile,
	})
	s := in.mgr.Status()
	if s.State != uplink.Unavailable || !strings.Contains(s.Reason, "development root") {
		t.Fatalf("status: %+v", s)
	}
	if err := in.mgr.Enable(context.Background(), g.license(t, time.Hour), "admin"); err == nil {
		t.Fatal("switched on with a refused root")
	}
	if in.refresher.Pick != nil {
		t.Error("the refresher can switch although the uplink is unavailable")
	}
	if n, _ := g.counts(); n != 0 {
		t.Errorf("%d requests reached the uplink", n)
	}
}

// VARDE_MODE keeps today's behaviour and locks the switch.
func TestUplinkE2ELockedByMode(t *testing.T) {
	in := startUplinkInstall(t, map[string]string{"VARDE_MODE": "direct"})
	if s := in.mgr.Status(); !s.Locked {
		t.Fatalf("status: %+v", s)
	}
	if in.refresher.Pick != nil || len(in.refresher.Sources) == 0 {
		t.Error("explicit direct mode must use the static direct sources")
	}
}
