// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/datapkg"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/pipeline"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/uplink"
)

// packageInterval is the time between two scheduled checks of the data
// package: it is built once a day.
const packageInterval = 24 * time.Hour

// channels is the feed client with its two channels (ADR 0038, 0039): the
// data package every installation reads and the uplink of subscribers.
type channels struct {
	uplink *uplink.Manager
	pkg    *datapkg.Manager
	// src is the feed source, nil when neither channel can be used.
	src *feed.Source
	// hasPackage reports that the installation reads the data package.
	hasPackage bool
	// cov knows which apps the feed in use covers.
	cov *pkgCoverage
	// used reports that advisories come from the feed client now.
	used func() bool
	// direct reports that GitHub is asked about apps the feed in use does
	// not cover.
	direct func() bool
}

// inUse reports that advisories come from the feed client now.
func (c *channels) inUse() bool { return c.used != nil && c.used() }

// superseded reports that the stored advisories of source no longer count
// for app (pipeline.Pipeline.Superseded). With the package or the uplink
// in use, the feed takes the place of GitHub for every app it covers:
// what GitHub answered earlier is not refreshed any more. The sources with
// a switch of their own (osv.dev, NVD) are not in the feed and still
// count. Without a channel in use the old rule holds.
func (c *channels) superseded(app *catalog.App, source string) bool {
	if app == nil {
		return false
	}
	if !c.inUse() {
		return app.Origin == catalog.OriginFeed && source != store.FeedSource
	}
	return strings.HasPrefix(source, "github:") && !c.cov.uncovered(app)
}

// forgetFeed removes what a feed channel installed, for an installation
// that uses none (any more): advisories nobody refreshes must not keep
// counting, and a later return has to install afresh.
func forgetFeed(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) {
	if cfg.Mode != "direct" {
		return // the static feed modes use the same directory
	}
	dir := filepath.Join(cfg.DataDir, "feed")
	err := errors.Join(feed.Forget(dir), st.ClearFeed(ctx),
		// What the feed said about itself is about a feed nobody uses.
		st.SyncNotices(ctx, store.NoticeFeedStale, nil, time.Now()),
		st.DeleteSourceStates(ctx, (&feed.Source{}).Name()))
	if err != nil {
		logger.Error("data of a feed no longer in use could not be removed", "err", err)
	}
}

// newChannels prepares the data package and the uplink switch. With
// VARDE_MODE in the environment both are out of the picture. Without a
// trust root, or without mirrors, a channel is unavailable and says why;
// Varde then asks the public sources itself, as it always did.
func newChannels(ctx context.Context, cfg config.Config, st *store.Store, analysis *pipeline.Pipeline, hc *httpx.Client,
	localCatalog fs.FS, logger *slog.Logger, directQueries func() bool, onChange func(),
) (*channels, error) {
	none := func(uplinkReason, pkgReason string, locked bool) *channels {
		forgetFeed(ctx, cfg, st, logger)
		return &channels{
			uplink: uplink.New(uplink.Options{Locked: locked, Log: logger, Unavailable: uplinkReason}),
			pkg:    datapkg.New(datapkg.Options{Unavailable: pkgReason}),
		}
	}
	if cfg.ModeSet {
		return none("", "The mode is fixed with VARDE_MODE in the environment.", true), nil
	}
	if len(cfg.FeedURLs) == 0 && len(cfg.PackageURLs) == 0 {
		return none("", "It is switched off with VARDE_PACKAGE_URLS.", false), nil
	}
	initial := feed.EmbeddedRoot()
	if cfg.FeedRootFile != "" {
		data, err := os.ReadFile(cfg.FeedRootFile)
		if err != nil {
			return nil, errors.New("read feed root: " + err.Error())
		}
		initial = data
	}

	var mgr *uplink.Manager
	authorization := func() string {
		if mgr == nil {
			return ""
		}
		return mgr.Authorization()
	}
	// The license goes to the uplink mirrors only.
	uplinkMirrors, err := fetchers(cfg.FeedURLs, hc, authorization)
	if err != nil {
		return nil, err
	}
	pkgMirrors, err := fetchers(cfg.PackageURLs, hc, nil)
	if err != nil {
		return nil, err
	}
	if outside := mirrorsOutsideAllowlist(cfg.EgressAllowlist, cfg.PackageURLs); len(outside) > 0 {
		logger.Warn("the data package mirror is not in VARDE_EGRESS_ALLOWLIST; every check will fail until it is added", "hosts", strings.Join(outside, ","))
	}
	client := &feed.Client{Dir: filepath.Join(cfg.DataDir, "feed"), Store: st, Catalog: analysis.Catalog(),
		LocalDir: localCatalog, Log: logger, AllowDevelopment: cfg.FeedAllowDevelopmentRoot}
	root, err := client.Init(initial)
	if err != nil {
		reason := err.Error()
		switch {
		case errors.Is(err, feed.ErrDevelopmentRoot):
			reason = "The trust root is a development root. It is only accepted with VARDE_FEED_ALLOW_DEVELOPMENT_ROOT=true, for tests."
		case len(initial) == 0:
			reason = "This build has no trust root for it yet."
		}
		logger.Warn("no usable trust root; Varde asks the public sources itself", "err", err)
		pkgReason := reason
		if len(pkgMirrors) == 0 {
			pkgReason = "It is switched off with VARDE_PACKAGE_URLS."
		}
		uplinkReason := reason
		if len(uplinkMirrors) == 0 {
			uplinkReason = ""
		}
		return none(uplinkReason, pkgReason, false), nil
	}
	if root.Environment != feed.EnvProduction {
		logger.Warn("feed trust root is a development root; use it only for tests", "version", root.Version)
	}

	ch := &channels{hasPackage: len(pkgMirrors) > 0}
	ch.used = func() bool {
		// Active first, package or not: asking is what notices an expired
		// license, switches the uplink off and tells the user.
		active := ch.uplink != nil && ch.uplink.Active()
		return ch.hasPackage || active
	}
	// The switch for direct queries is on the settings page of the data
	// package. An installation with the uplink alone has no such switch:
	// there GitHub is asked about uncovered apps, as before.
	ch.direct = func() bool { return !ch.hasPackage || directQueries() }
	uplinkInUse := func() bool { return mgr != nil && mgr.InUse() }
	client.Pick = func() feed.Channel {
		if uplinkInUse() {
			return feed.Channel{Name: feed.ChannelUplink, Mirrors: uplinkMirrors}
		}
		return feed.Channel{Name: feed.ChannelPackage, Mirrors: pkgMirrors}
	}
	// A refresh chosen just before a switch-off must not bring the uplink
	// feed back; the package is always in use where it exists.
	client.InUse = func() bool { return ch.hasPackage || uplinkInUse() }
	ch.src = &feed.Source{Client: client, Store: st, StaleAfter: cfg.FeedStaleAfter,
		MinInterval: func() time.Duration {
			// Only an installed package waits for its daily build; the
			// uplink changes more often, and after a switch the package
			// is fetched at once.
			if uplinkInUse() || client.ActiveChannel(context.Background()) != feed.ChannelPackage {
				return 0
			}
			return packageInterval
		}}

	if len(uplinkMirrors) == 0 {
		mgr = uplink.New(uplink.Options{Log: logger})
	} else {
		box, err := integrations.OpenBox(filepath.Join(cfg.DataDir, "keys", "integrations.key"))
		if err != nil {
			return nil, err
		}
		after := ""
		if ch.hasPackage {
			after = "Varde reads the data package again."
		}
		mgr = uplink.New(uplink.Options{
			Feed: &uplinkFeed{src: ch.src, local: localCatalog, development: root.Environment != feed.EnvProduction, hasPackage: ch.hasPackage},
			Box:  box, Store: st, Log: logger, OnChange: onChange, Notices: st, After: after,
		})
		mgr.Load(ctx)
	}
	ch.uplink = mgr
	ch.cov = &pkgCoverage{index: client.Index}
	// Nothing is asked about an app the feed in use does not cover while
	// direct queries are off; the pages say so instead of showing it as
	// checked.
	noSource := func(app *catalog.App) bool { return ch.inUse() && !ch.direct() && ch.cov.uncovered(app) }
	if !ch.hasPackage {
		ch.pkg = datapkg.New(datapkg.Options{Unavailable: "It is switched off with VARDE_PACKAGE_URLS.", NoSource: noSource})
		return ch, nil
	}
	ch.pkg = datapkg.New(datapkg.Options{Source: ch.src, Store: st, OnChange: onChange, NoSource: noSource})
	if !mgr.Active() {
		// The package installed before the restart is in use at once.
		if err := client.LoadActive(ctx); err != nil {
			logger.Error("installed data package could not be loaded; the next check installs it again", "err", err)
		}
	}
	return ch, nil
}

// mirrorsOutsideAllowlist names the hosts of https mirrors an egress
// allowlist would block. Without an allowlist nothing is blocked.
func mirrorsOutsideAllowlist(allow, mirrors []string) []string {
	if len(allow) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, h := range allow {
		allowed[strings.ToLower(h)] = true
	}
	var out []string
	for _, m := range mirrors {
		u, err := url.Parse(m)
		if err != nil || u.Scheme != "https" {
			continue
		}
		if host := strings.ToLower(u.Hostname()); !allowed[host] {
			out = append(out, host)
		}
	}
	return out
}

func fetchers(urls []string, hc *httpx.Client, authorization func() string) ([]feed.Fetcher, error) {
	var out []feed.Fetcher
	for _, u := range urls {
		f, err := feed.NewFetcher(u, hc, authorization)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// pkgCoverage answers which apps the installed package does not cover: those
// are the only ones the public sources are asked about, and only when the
// user switched that on.
type pkgCoverage struct {
	index func() *applists.Table

	mu    sync.Mutex
	table *applists.Table
	repos map[string]bool
}

// uncovered reports that the package holds no advisories for app. Covered
// are the entries of the package's catalog, and derived apps whose
// repositories are all in the package's index: the package stores the
// advisories of an indexed repository under the derived ID. A local or
// built-in entry for the same repository has another ID and gets none.
func (c *pkgCoverage) uncovered(app *catalog.App) bool {
	if app.Origin == catalog.OriginFeed {
		return false
	}
	if app.Origin != catalog.OriginDerived || len(app.Advisories.GitHubRepos) == 0 {
		return true
	}
	repos := c.indexed()
	for _, r := range app.Advisories.GitHubRepos {
		if !repos["github.com/"+strings.ToLower(r)] {
			return true
		}
	}
	return false
}

// indexed returns the repositories of the package's index; the set is
// built once per table.
func (c *pkgCoverage) indexed() map[string]bool {
	t := c.index()
	c.mu.Lock()
	defer c.mu.Unlock()
	if t != c.table || c.repos == nil {
		c.table, c.repos = t, map[string]bool{}
		for _, e := range t.Entries() {
			c.repos[e.Repo] = true
		}
	}
	return c.repos
}
