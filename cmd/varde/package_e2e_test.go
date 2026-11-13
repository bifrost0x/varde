// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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

	"github.com/bifrost0x/varde/internal/advisory/sources"
	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/uplink"
)

const e2eIndex = "ghcr.io/acme/widget\tgithub.com/acme/widget\tghcr,readme\n"

func packageEnv(g *uplinkGate, mirror string) map[string]string {
	return map[string]string{
		"VARDE_PACKAGE_URLS": mirror, "VARDE_FEED_ROOT_FILE": g.rootFile, "VARDE_FEED_ALLOW_DEVELOPMENT_ROOT": "true",
	}
}

// source returns the picked source of that name.
func (i *uplinkInstall) source(t *testing.T, name string) sources.Source {
	t.Helper()
	for _, s := range i.refresher.Pick() {
		if s.Name() == name {
			return s
		}
	}
	t.Fatalf("no source %q among %s", name, i.sourceNames())
	return nil
}

// With a trust root the data package is the only thing an installation
// asks: one mirror, no public source.
func TestPackageIsDefaultWithRoot(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	in := startUplinkInstall(t, packageEnv(g, g.packageDir(t, 150, e2eIndex)))
	if st := in.pkg.Status(ctx); !st.Available {
		t.Fatalf("package status: %+v", st)
	}
	// KEV comes with the package; EPSS is listed but switched off (see
	// TestEPSSOutsideThePackage).
	if names := in.sourceNames(); !strings.HasPrefix(names, "feed") || strings.Contains(names, "kev") {
		t.Fatalf("sources: %s", names)
	}
	in.refresher.RunOnce(ctx)
	if in.immichOrigin() != catalog.OriginFeed || in.feedAdvisories(t) != 2 {
		t.Fatalf("after the first run: origin %q, advisories %d", in.immichOrigin(), in.feedAdvisories(t))
	}
	st := in.pkg.Status(ctx)
	if st.Channel != feed.ChannelPackage || st.Sequence != 150 || st.LastError != "" {
		t.Fatalf("package status: %+v", st)
	}
	// Direct queries are off: the GitHub source does nothing, whatever app
	// it is handed.
	local := &catalog.App{ID: "mine", Origin: catalog.OriginLocal, Advisories: catalog.Advisories{GitHubRepos: []string{"me/mine"}}}
	res, err := in.source(t, "github").Refresh(ctx, []*catalog.App{local})
	if err != nil || res.Requests != 0 {
		t.Fatalf("github source with direct queries off: %+v, %v", res, err)
	}
	if n, _ := g.counts(); n != 0 {
		t.Fatalf("%d requests reached the uplink", n)
	}
	// The uplink has no mirror here, so it is not available.
	if s := in.mgr.Status(); s.State != uplink.Unavailable {
		t.Fatalf("uplink: %+v", s)
	}
}

// A build with the production trust root reads the data package without
// any configuration: the default mirror, no public source.
func TestEmbeddedRootMakesThePackageTheDefault(t *testing.T) {
	if feed.EmbeddedRoot() == nil {
		t.Skip("this build embeds no trust root")
	}
	ctx := context.Background()
	// No root file, no mirror: only what the binary brings. The harness
	// allows no outbound host, so the check of the default mirror fails
	// here; what counts is which sources are chosen.
	in := startUplinkInstall(t, map[string]string{"VARDE_PACKAGE_URLS": config.DefaultPackageURL})
	if st := in.pkg.Status(ctx); !st.Available {
		t.Fatalf("package status: %+v", st)
	}
	if names := in.sourceNames(); !strings.HasPrefix(names, "feed") || strings.Contains(names, "kev") {
		t.Fatalf("sources: %s", names)
	}
	local := &catalog.App{ID: "mine", Origin: catalog.OriginLocal, Advisories: catalog.Advisories{GitHubRepos: []string{"me/mine"}}}
	if res, err := in.source(t, "github").Refresh(ctx, []*catalog.App{local}); err != nil || res.Requests != 0 {
		t.Fatalf("github asked by default: %+v, %v", res, err)
	}
	if _, err := in.pkg.UpdateNow(ctx); err == nil {
		t.Fatal("the default mirror was reached from a test")
	}
}

// Without a trust root nothing changes: Varde asks the public sources.
func TestNoRootBehavesAsBefore(t *testing.T) {
	if feed.EmbeddedRoot() != nil {
		t.Skip("this build embeds a trust root; see TestEmbeddedRootMakesThePackageTheDefault")
	}
	g := newUplinkGate(t)
	in := startUplinkInstall(t, map[string]string{"VARDE_PACKAGE_URLS": g.packageDir(t, 100, "")})
	st := in.pkg.Status(context.Background())
	if st.Available || !strings.Contains(st.Reason, "trust root") {
		t.Fatalf("package status: %+v", st)
	}
	if names := in.sourceNames(); strings.Contains(names, "feed") || !strings.Contains(names, "github") || !strings.Contains(names, "kev") {
		t.Fatalf("sources: %s", names)
	}
	if _, err := in.pkg.UpdateNow(context.Background()); err == nil {
		t.Fatal("update without a package succeeded")
	}
}

// With direct queries on, only apps the package does not cover are asked
// about at the public sources.
func TestDirectSwitchAsksOnlyUncovered(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	in := startUplinkInstall(t, packageEnv(g, g.packageDir(t, 100, e2eIndex)))
	in.refresher.RunOnce(ctx)
	if err := in.set.Update(ctx, map[string]string{settings.KeyDirectQueries: "true"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	gh := in.source(t, "github")
	fromFeed := &catalog.App{ID: "immich", Origin: catalog.OriginFeed, Advisories: catalog.Advisories{GitHubRepos: []string{"immich-app/immich"}}}
	covered := &catalog.App{ID: "gh-acme-widget", Origin: catalog.OriginDerived, Advisories: catalog.Advisories{GitHubRepos: []string{"Acme/Widget"}}}
	for _, a := range []*catalog.App{fromFeed, covered} {
		res, err := gh.Refresh(ctx, []*catalog.App{a})
		if err != nil || res.Requests != 0 {
			t.Errorf("%s is covered by the package but was asked about: %+v, %v", a.ID, res, err)
		}
	}
	// A local entry is not in the package: it is asked about. The egress
	// allowlist of the test stops the request, which shows it was made.
	local := &catalog.App{ID: "mine", Origin: catalog.OriginLocal, Advisories: catalog.Advisories{GitHubRepos: []string{"me/mine"}}}
	res, err := gh.Refresh(ctx, []*catalog.App{local})
	if err == nil && res.Requests == 0 {
		t.Errorf("an uncovered app was not asked about with direct queries on: %+v", res)
	}
}

func TestUncovered(t *testing.T) {
	table, err := applists.Unmarshal([]byte(e2eIndex))
	if err != nil {
		t.Fatal(err)
	}
	c := &pkgCoverage{index: func() *applists.Table { return table }}
	app := func(origin catalog.Origin, repos ...string) *catalog.App {
		return &catalog.App{Origin: origin, Advisories: catalog.Advisories{GitHubRepos: repos}}
	}
	for _, tc := range []struct {
		name string
		app  *catalog.App
		want bool
	}{
		{"feed entry", app(catalog.OriginFeed, "x/y"), false},
		{"derived, in the index", app(catalog.OriginDerived, "acme/widget"), false},
		{"derived, in the index, other case", app(catalog.OriginDerived, "ACME/Widget"), false},
		{"derived, not in the index", app(catalog.OriginDerived, "acme/other"), true},
		// The package stores a generated app's advisories under its ID,
		// the derived ID of its indexed repository.
		{"generated, in the index", app(catalog.OriginGenerated, "acme/widget"), false},
		{"generated, not in the index", app(catalog.OriginGenerated, "acme/other"), true},
		{"generated without a repository", app(catalog.OriginGenerated), true},
		{"local entry", app(catalog.OriginLocal, "me/mine"), true},
		// The package's advisories for that repository are stored under
		// the derived ID, not under the ID of a local or built-in entry.
		{"local entry of an indexed repository", app(catalog.OriginLocal, "acme/widget"), true},
		{"built-in entry of an indexed repository", app(catalog.OriginBuiltin, "acme/widget"), true},
		{"local entry without a repository", app(catalog.OriginLocal), true},
		{"two repositories, one outside", app(catalog.OriginDerived, "acme/widget", "acme/other"), true},
	} {
		if got := c.uncovered(tc.app); got != tc.want {
			t.Errorf("%s: uncovered = %v, want %v", tc.name, got, tc.want)
		}
	}
	none := &pkgCoverage{index: func() *applists.Table { return nil }}
	if !none.uncovered(app(catalog.OriginDerived, "acme/widget")) {
		t.Error("without an index in the package a derived app counts as covered")
	}
}

// A package that cannot be fetched keeps the data in use and never makes
// Varde ask the public sources by itself.
func TestPackageFailureKeepsData(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	mirror := g.packageDir(t, 100, "")
	in := startUplinkInstall(t, packageEnv(g, mirror))
	in.refresher.RunOnce(ctx)
	if in.feedAdvisories(t) != 2 {
		t.Fatalf("advisories = %d", in.feedAdvisories(t))
	}
	if err := os.RemoveAll(strings.TrimPrefix(mirror, "file://")); err != nil {
		t.Fatal(err)
	}
	if _, err := in.pkg.UpdateNow(ctx); err == nil {
		t.Fatal("update from a removed mirror succeeded")
	}
	in.refresher.RunOnce(ctx)
	if in.feedAdvisories(t) != 2 || in.immichOrigin() != catalog.OriginFeed {
		t.Fatalf("after the failure: advisories %d, origin %q", in.feedAdvisories(t), in.immichOrigin())
	}
	if names := in.sourceNames(); !strings.HasPrefix(names, "feed") || strings.Contains(names, "kev") {
		t.Fatalf("sources after the failure: %s", names)
	}
	if st := in.pkg.Status(ctx); st.LastError == "" || st.Sequence != 100 {
		t.Fatalf("status: %+v", st)
	}
}

// A restart with the uplink off must not wipe the installed package.
func TestLeaveOnlyLeavesUplinkChannel(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	env := packageEnv(g, g.packageDir(t, 100, ""))
	env["VARDE_FEED_URLS"], env["VARDE_CA_BUNDLE_FILE"] = g.srv.URL, g.caFile
	env["VARDE_DATA_DIR"] = t.TempDir()
	in := startUplinkInstall(t, env)
	in.refresher.RunOnce(ctx)
	if in.feedAdvisories(t) != 2 {
		t.Fatalf("advisories = %d", in.feedAdvisories(t))
	}
	_ = in.st.Close()
	again := startUplinkInstall(t, env)
	if again.feedAdvisories(t) != 2 || again.immichOrigin() != catalog.OriginFeed {
		t.Fatalf("after the restart: advisories %d, origin %q", again.feedAdvisories(t), again.immichOrigin())
	}
	if st := again.pkg.Status(ctx); st.Channel != feed.ChannelPackage {
		t.Fatalf("status after the restart: %+v", st)
	}
}

// Uplink on replaces the package, uplink off brings the package back,
// although its sequence is lower.
func TestUplinkOffReturnsToPackage(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	env := packageEnv(g, g.packageDir(t, 100, ""))
	env["VARDE_FEED_URLS"], env["VARDE_CA_BUNDLE_FILE"] = g.srv.URL, g.caFile
	in := startUplinkInstall(t, env)
	in.refresher.RunOnce(ctx)
	if n, _ := g.counts(); n != 0 {
		t.Fatalf("%d requests reached the uplink while it was off", n)
	}
	if err := in.mgr.Enable(ctx, g.license(t, time.Hour), "admin"); err != nil {
		t.Fatalf("switch on: %v", err)
	}
	if st := in.pkg.Status(ctx); st.Channel != feed.ChannelUplink || st.Sequence != 200 || in.feedAdvisories(t) != 1 {
		t.Fatalf("uplink on: %+v, advisories %d", st, in.feedAdvisories(t))
	}
	if err := in.mgr.Disable(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	// Nothing is wiped on the way: the uplink's verified data stays in use
	// until the package has replaced it.
	if in.feedAdvisories(t) != 1 || in.immichOrigin() != catalog.OriginFeed {
		t.Fatalf("between uplink and package: advisories %d, origin %q", in.feedAdvisories(t), in.immichOrigin())
	}
	before, _ := g.counts()
	in.refresher.RunOnce(ctx)
	if st := in.pkg.Status(ctx); st.Channel != feed.ChannelPackage || st.Sequence != 100 {
		t.Fatalf("after switching off: %+v", st)
	}
	if in.feedAdvisories(t) != 2 || in.immichOrigin() != catalog.OriginFeed {
		t.Fatalf("after switching off: advisories %d, origin %q", in.feedAdvisories(t), in.immichOrigin())
	}
	if after, _ := g.counts(); after != before {
		t.Errorf("%d requests reached the uplink after it was switched off", after-before)
	}
	// The package mirror never sees the license.
	notices, err := in.st.ActiveNotices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range notices {
		if n.Kind == store.NoticeFeedStale {
			t.Errorf("stale notice after returning to the package: %+v", n)
		}
	}
}

// The table of the package is asked before the one built into the binary.
func TestPackageIndexWinsOverEmbedded(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	in := startUplinkInstall(t, packageEnv(g, g.packageDir(t, 100, e2eIndex)))
	if _, _, _, ok := in.analysis.ImageIndex("ghcr.io/acme/widget"); ok {
		t.Fatal("the test image is in the embedded index; pick another")
	}
	in.refresher.RunOnce(ctx)
	repo, _, confirmed, ok := in.analysis.ImageIndex("ghcr.io/acme/widget")
	if !ok || repo != "github.com/acme/widget" || !confirmed {
		t.Fatalf("lookup = %q, confirmed %v, ok %v", repo, confirmed, ok)
	}
	// An image only the embedded table knows is still found.
	if _, _, _, ok := in.analysis.ImageIndex("docker.io/11notes/adguard"); !ok {
		t.Fatal("the embedded index is no longer asked")
	}
}

// The direct-queries switch is about asking GitHub for single apps. The
// sources with a switch of their own (osv.dev with the distribution data,
// NVD, endoflife.date) are not in the package and keep working as set.
func TestOwnSwitchesStayIndependent(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	in := startUplinkInstall(t, packageEnv(g, g.packageDir(t, 100, "")))
	in.refresher.RunOnce(ctx)
	if in.set.Get().DirectQueries {
		t.Fatal("direct queries are on")
	}
	if err := in.set.Update(ctx, map[string]string{settings.KeyDirectOSV: "true"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	app, ok := in.analysis.Catalog().Current().App("immich")
	if !ok {
		t.Fatal("no immich entry")
	}
	probe := *app
	probe.Advisories.OSVPackages = []catalog.OSVPackage{{Ecosystem: "npm", Name: "immich"}}
	// The egress allowlist of the test stops the request: an error or a
	// counted request shows the source tried.
	res, err := in.source(t, "osv").Refresh(ctx, []*catalog.App{&probe})
	if err == nil && res.Requests == 0 {
		t.Errorf("osv.dev is switched on but was not asked with direct queries off: %+v", res)
	}
	// GitHub still is not asked.
	res, err = in.source(t, "github").Refresh(ctx, []*catalog.App{{ID: "mine", Origin: catalog.OriginLocal,
		Advisories: catalog.Advisories{GitHubRepos: []string{"me/mine"}}}})
	if err != nil || res.Requests != 0 {
		t.Errorf("github asked with direct queries off: %+v, %v", res, err)
	}
}

// Which stored advisories still count while a feed channel is in use.
func TestSuperseded(t *testing.T) {
	table, err := applists.Unmarshal([]byte(e2eIndex))
	if err != nil {
		t.Fatal(err)
	}
	inUse := true
	ch := &channels{cov: &pkgCoverage{index: func() *applists.Table { return table }}, used: func() bool { return inUse }}
	feedApp := &catalog.App{Origin: catalog.OriginFeed, Advisories: catalog.Advisories{GitHubRepos: []string{"immich-app/immich"}}}
	derived := &catalog.App{Origin: catalog.OriginDerived, Advisories: catalog.Advisories{GitHubRepos: []string{"acme/widget"}}}
	local := &catalog.App{Origin: catalog.OriginLocal, Advisories: catalog.Advisories{GitHubRepos: []string{"acme/widget"}}}
	generated := &catalog.App{Origin: catalog.OriginGenerated, Advisories: catalog.Advisories{GitHubRepos: []string{"acme/widget"}}}
	for _, tc := range []struct {
		name   string
		app    *catalog.App
		source string
		want   bool
	}{
		{"feed app, old GitHub record", feedApp, "github:immich-app/immich", true},
		{"feed app, feed record", feedApp, store.FeedSource, false},
		{"feed app, osv.dev record", feedApp, "osv", false},
		{"feed app, NVD record", feedApp, "nvd", false},
		{"covered derived app, old GitHub record", derived, "github:acme/widget", true},
		{"covered derived app, feed record", derived, store.FeedSource, false},
		{"local entry, GitHub record", local, "github:acme/widget", false},
		{"covered generated app, old GitHub record", generated, "github:acme/widget", true},
		{"covered generated app, feed record", generated, store.FeedSource, false},
		{"unknown app", nil, "github:x/y", false},
	} {
		if got := ch.superseded(tc.app, tc.source); got != tc.want {
			t.Errorf("%s: superseded = %v, want %v", tc.name, got, tc.want)
		}
	}
	inUse = false
	if ch.superseded(feedApp, "github:immich-app/immich") != true || ch.superseded(feedApp, "osv") != true {
		t.Error("with no channel in use the old rule applies: a feed entry is judged by the feed alone")
	}
}

// Switching the package off removes what it installed: advisories nobody
// refreshes any more must not keep counting.
func TestPackageOffClearsItsData(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	env := packageEnv(g, g.packageDir(t, 100, ""))
	env["VARDE_DATA_DIR"] = t.TempDir()
	in := startUplinkInstall(t, env)
	in.refresher.RunOnce(ctx)
	if in.feedAdvisories(t) != 2 {
		t.Fatalf("advisories = %d", in.feedAdvisories(t))
	}
	_ = in.st.Close()
	off := map[string]string{"VARDE_DATA_DIR": env["VARDE_DATA_DIR"], "VARDE_PACKAGE_URLS": ""}
	in = startUplinkInstall(t, off)
	if in.feedAdvisories(t) != 0 || in.immichOrigin() != catalog.OriginBuiltin {
		t.Fatalf("package off: advisories %d, origin %q", in.feedAdvisories(t), in.immichOrigin())
	}
	_ = in.st.Close()
	// Back on: the same package installs again.
	in = startUplinkInstall(t, env)
	in.refresher.RunOnce(ctx)
	if in.feedAdvisories(t) != 2 {
		t.Fatalf("package on again: advisories = %d", in.feedAdvisories(t))
	}
}

// Direct mode forgets the release package lists of the package with its
// advisories: no page may claim a release fix from data nobody refreshes.
func TestForgetFeedClearsReleasePackages(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "varde.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	row := store.ReleasePackageRow{AppID: "immich", Image: "ghcr.io/immich-app/immich-server", Platform: "linux/amd64", Tag: "v1", Version: "1", Line: []byte("{}")}
	if err := st.ReplaceReleasePackages(ctx, "sha256:m", []store.ReleasePackageRow{row}); err != nil {
		t.Fatal(err)
	}
	forgetFeed(ctx, config.Config{Mode: "direct", DataDir: dir}, st, slog.New(slog.DiscardHandler))
	if got, err := st.ReleasePackagesFor(ctx, row.AppID, row.Image); err != nil || len(got) != 0 {
		t.Fatalf("release packages after forgetting the feed: %q, %v", got, err)
	}
	if m, err := st.ReleasePackagesMarker(ctx); err != nil || m != "" {
		t.Fatalf("marker after forgetting the feed = %q, %v", m, err)
	}
}

// An installation with the uplink but without the data package has no
// switch for direct queries on its settings page: there the uplink asks
// GitHub about uncovered apps as it always did.
func TestUplinkWithoutPackageAsksGitHub(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	in := startUplinkInstall(t, map[string]string{
		"VARDE_FEED_URLS": g.srv.URL, "VARDE_FEED_ROOT_FILE": g.rootFile,
		"VARDE_FEED_ALLOW_DEVELOPMENT_ROOT": "true", "VARDE_CA_BUNDLE_FILE": g.caFile,
	})
	if err := in.mgr.Enable(ctx, g.license(t, time.Hour), "admin"); err != nil {
		t.Fatal(err)
	}
	local := &catalog.App{ID: "mine", Origin: catalog.OriginLocal, Advisories: catalog.Advisories{GitHubRepos: []string{"me/mine"}}}
	res, err := in.source(t, "github").Refresh(ctx, []*catalog.App{local})
	if err == nil && res.Requests == 0 {
		t.Errorf("an uncovered app was not asked about: %+v", res)
	}
	if in.pkg.NoSource(local) {
		t.Error("the app is asked about but shown as without a source")
	}
}

// EPSS scores for CVEs outside the package are fetched only when a source
// that brings such CVEs is switched on.
func TestEPSSOutsideThePackage(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	in := startUplinkInstall(t, packageEnv(g, g.packageDir(t, 100, "")))
	in.refresher.RunOnce(ctx)
	epss, ok := in.source(t, "epss").(sources.Toggle)
	if !ok {
		t.Fatalf("the EPSS source is not switched: %T", in.source(t, "epss"))
	}
	if epss.Enabled() {
		t.Fatal("EPSS is asked with every direct source off")
	}
	for _, key := range []string{settings.KeyDirectNVD, settings.KeyDirectOSV, settings.KeyDirectQueries} {
		if err := in.set.Update(ctx, map[string]string{key: "true"}, "admin", time.Now()); err != nil {
			t.Fatal(err)
		}
		if !epss.Enabled() {
			t.Errorf("EPSS is not asked although %s is on", key)
		}
		if err := in.set.Update(ctx, map[string]string{key: "false"}, "admin", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

// The license runs out while the package is there to return to: the
// switch must still notice, say so and stop showing an active uplink.
func TestUplinkExpiryIsNoticedWithPackage(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	env := packageEnv(g, g.packageDir(t, 100, ""))
	env["VARDE_FEED_URLS"], env["VARDE_CA_BUNDLE_FILE"] = g.srv.URL, g.caFile
	in := startUplinkInstall(t, env)
	if err := in.mgr.Enable(ctx, g.license(t, 2*time.Second), "admin"); err != nil {
		t.Fatalf("switch on: %v", err)
	}
	time.Sleep(2500 * time.Millisecond)
	in.refresher.RunOnce(ctx) // an ordinary scheduled run, nothing else
	if s := in.mgr.Status(); s.State != uplink.Expired {
		t.Fatalf("after expiry: %+v", s)
	}
	notices, err := in.st.ActiveNotices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	told := false
	for _, n := range notices {
		told = told || (n.Kind == store.NoticeUplink && strings.Contains(n.Detail, "Varde reads the data package again."))
	}
	if !told {
		t.Errorf("no notice that the uplink ended: %+v", notices)
	}
	if st := in.pkg.Status(ctx); st.Channel != feed.ChannelPackage {
		t.Fatalf("package not back after expiry: %+v", st)
	}
}

// Switching the package off also withdraws what it said about itself: a
// failed check and the stale notice are about a feed nobody uses.
func TestPackageOffClearsItsHealthState(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	mirror := g.packageDir(t, 100, "")
	env := packageEnv(g, mirror)
	env["VARDE_DATA_DIR"] = t.TempDir()
	in := startUplinkInstall(t, env)
	if err := os.RemoveAll(strings.TrimPrefix(mirror, "file://")); err != nil {
		t.Fatal(err)
	}
	in.refresher.RunOnce(ctx) // fails: a failed check and "no feed installed yet"
	if st, _ := in.st.SourceState(ctx, "feed", "manifest"); st.LastError == "" {
		t.Fatal("the failed check was not recorded")
	}
	_ = in.st.Close()
	in = startUplinkInstall(t, map[string]string{"VARDE_DATA_DIR": env["VARDE_DATA_DIR"], "VARDE_PACKAGE_URLS": ""})
	if st, _ := in.st.SourceState(ctx, "feed", "manifest"); st.LastError != "" || !st.LastAttempt.IsZero() {
		t.Errorf("source state of the feed kept: %+v", st)
	}
	notices, err := in.st.ActiveNotices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range notices {
		if n.Kind == store.NoticeFeedStale {
			t.Errorf("stale notice of a feed that is not in use: %+v", n)
		}
	}
}

// The license goes to the uplink and to nobody else: the package mirror,
// which anyone may run, must never see it, across switching the uplink on
// and off. Two things keep it so: the package mirrors get no license
// function at all, and while the uplink is on they are not asked. This
// test watches the outcome at the mirror; it does not tell the two apart.
func TestLicenseNeverReachesThePackageMirror(t *testing.T) {
	g := newUplinkGate(t)
	ctx := context.Background()
	dir := strings.TrimPrefix(g.packageDir(t, 100, ""), "file://")
	var mu sync.Mutex
	requests, withAuth := 0, 0
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		if r.Header.Get("Authorization") != "" {
			withAuth++
		}
		mu.Unlock()
		http.FileServer(http.Dir(dir)).ServeHTTP(w, r)
	}))
	defer mirror.Close()
	// One CA bundle for both test servers.
	gateCA, err := os.ReadFile(g.caFile)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	gateCA = append(gateCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mirror.Certificate().Raw})...)
	if err := os.WriteFile(bundle, gateCA, 0o600); err != nil {
		t.Fatal(err)
	}
	in := startUplinkInstall(t, map[string]string{
		"VARDE_PACKAGE_URLS": mirror.URL, "VARDE_FEED_URLS": g.srv.URL, "VARDE_FEED_ROOT_FILE": g.rootFile,
		"VARDE_FEED_ALLOW_DEVELOPMENT_ROOT": "true", "VARDE_CA_BUNDLE_FILE": bundle,
	})
	in.refresher.RunOnce(ctx)
	if in.feedAdvisories(t) != 2 {
		t.Fatalf("package not installed over https: %d advisories", in.feedAdvisories(t))
	}
	if err := in.mgr.Enable(ctx, g.license(t, time.Hour), "admin"); err != nil {
		t.Fatal(err)
	}
	in.refresher.RunOnce(ctx)
	if err := in.mgr.Disable(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	in.refresher.RunOnce(ctx)
	if _, err := in.pkg.UpdateNow(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests == 0 || withAuth != 0 {
		t.Fatalf("package mirror: %d requests, %d with an Authorization header", requests, withAuth)
	}
	if _, gateAuth := g.counts(); gateAuth == 0 {
		t.Fatal("the uplink never saw the license; the test proves nothing")
	}
}

// With an egress allowlist that lacks the package mirror, every check
// fails; the start says so by name.
func TestMirrorsOutsideTheAllowlist(t *testing.T) {
	for _, tc := range []struct {
		allow, mirrors []string
		want           string
	}{
		{nil, []string{"https://raw.githubusercontent.com/x/y"}, ""},
		{[]string{"api.github.com"}, []string{"https://raw.githubusercontent.com/x/y"}, "raw.githubusercontent.com"},
		{[]string{"RAW.githubusercontent.com"}, []string{"https://raw.githubusercontent.com/x/y"}, ""},
		{[]string{"api.github.com"}, []string{"file:///data/pkg.tar"}, ""},
		{[]string{"a.example"}, []string{"https://a.example/f", "https://b.example:8443/f"}, "b.example"},
	} {
		if got := strings.Join(mirrorsOutsideAllowlist(tc.allow, tc.mirrors), ","); got != tc.want {
			t.Errorf("allow %v, mirrors %v: %q, want %q", tc.allow, tc.mirrors, got, tc.want)
		}
	}
}
