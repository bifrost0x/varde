// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/fleet"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/notify"
	"github.com/bifrost0x/varde/internal/pipeline"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
)

// newAgentListener loads or creates the internal CA and returns the mTLS
// listener for agents, or nil when it is switched off.
func newAgentListener(cfg config.Config, st *store.Store, analysis *pipeline.Pipeline, network *integrations.Manager,
	binaries *fleet.Binaries, readImages func() bool, logger *slog.Logger,
) (*fleet.CA, *http.Server, error) {
	if cfg.AgentListenAddr == "off" {
		return nil, nil, nil
	}
	ca, err := fleet.LoadOrCreateCA(filepath.Join(cfg.DataDir, "ca"), time.Now)
	if err != nil {
		return nil, nil, err
	}
	srv := fleet.NewServer(ca, st, logger, analysis.RunLogged)
	srv.Inventory, srv.Binaries, srv.ReadImages = network.StoreAgentInventory, binaries, readImages
	if p := binaries.Available(); len(p) > 0 {
		logger.Info("agent binaries available", "platforms", p)
	}
	return ca, srv.HTTPServer(cfg.AgentListenAddr), nil
}

// wireCoverage keeps the system notices current: public routes Varde cannot
// assess after every analysis, stale agents once a minute.
func wireCoverage(st *store.Store, set *settings.Service, analysis *pipeline.Pipeline, logger *slog.Logger) {
	analysis.Covered = func(ctx context.Context, ws []inventory.Workload, results []identify.Result) {
		ids := make(map[string]identify.Result, len(results))
		for _, r := range results {
			ids[r.WorkloadID] = r
		}
		// Without the marks every unassessed public route is reported:
		// a spurious notice is safer than a missing one.
		marked, err := st.NotAnApp(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Error("reading not-an-app marks failed", "err", err)
		}
		notices := coverage.PublicRouteNotices(ws, ids, set.Get().PublicDomains, marked)
		if err := st.SyncNotices(ctx, store.NoticePublicRoute, notices, time.Now()); err != nil && ctx.Err() == nil {
			logger.Error("updating coverage notices failed", "err", err)
		}
	}
}

func runLiveness(ctx context.Context, st *store.Store, scope func() discovery.Scope, interval func(kind string) time.Duration, logger *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		now := time.Now()
		if err := coverage.RefreshHosts(ctx, st, now); err != nil && ctx.Err() == nil {
			logger.Error("host liveness check failed", "err", err)
		}
		if err := coverage.RefreshIntegrations(ctx, st, now, interval); err != nil && ctx.Err() == nil {
			logger.Error("integration health check failed", "err", err)
		}
		if err := coverage.RefreshSources(ctx, st, now); err != nil && ctx.Err() == nil {
			logger.Error("advisory source health check failed", "err", err)
		}
		if err := coverage.RefreshAssets(ctx, st, scope(), now, interval); err != nil && ctx.Err() == nil {
			logger.Error("asset identity refresh failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pendingNotices adapts stored notices for the daily digest.
func pendingNotices(st *store.Store) (func(context.Context) ([]notify.Notice, error), func(context.Context, []string) error) {
	load := func(ctx context.Context) ([]notify.Notice, error) {
		ns, err := st.ActiveNotices(ctx)
		if err != nil {
			return nil, err
		}
		var out []notify.Notice
		for _, n := range ns {
			if n.NotifiedAt == nil {
				out = append(out, notify.Notice{Key: n.Key, Title: n.Title, Detail: n.Detail})
			}
		}
		return out, nil
	}
	sent := func(ctx context.Context, keys []string) error {
		return st.MarkNoticesNotified(ctx, keys, time.Now())
	}
	return load, sent
}

func caPin(ca *fleet.CA) string {
	if ca == nil {
		return ""
	}
	return ca.Pin()
}

// newFeedClient builds the feed client and its advisory source and
// establishes the trust root, without activating an installed feed.
// authorization is sent to https:// mirrors (the uplink license) and may
// be nil.
func newFeedClient(cfg config.Config, st *store.Store, analysis *pipeline.Pipeline, hc *httpx.Client,
	localCatalog fs.FS, logger *slog.Logger, authorization func() string,
) (*feed.Source, *feed.Root, error) {
	var mirrors []feed.Fetcher
	for _, u := range cfg.FeedURLs {
		f, err := feed.NewFetcher(u, hc, authorization)
		if err != nil {
			return nil, nil, err
		}
		mirrors = append(mirrors, f)
	}
	client := &feed.Client{Mirrors: mirrors, Dir: filepath.Join(cfg.DataDir, "feed"), Store: st,
		Catalog: analysis.Catalog(), LocalDir: localCatalog, Log: logger, AllowDevelopment: cfg.FeedAllowDevelopmentRoot}
	var initial []byte
	if cfg.FeedRootFile != "" {
		data, err := os.ReadFile(cfg.FeedRootFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read feed root: %w", err)
		}
		initial = data
	}
	root, err := client.Init(initial)
	if err != nil {
		return nil, nil, err
	}
	if root.Environment != feed.EnvProduction {
		logger.Warn("feed trust root is a development root; use it only for tests", "version", root.Version)
	}
	return &feed.Source{Client: client, Store: st, StaleAfter: cfg.FeedStaleAfter}, root, nil
}

// newFeedSource is the feed source of the static feed and hybrid modes
// (VARDE_MODE): the installed feed is activated at once.
func newFeedSource(ctx context.Context, cfg config.Config, st *store.Store, analysis *pipeline.Pipeline, hc *httpx.Client,
	localCatalog fs.FS, logger *slog.Logger,
) (*feed.Source, error) {
	src, _, err := newFeedClient(cfg, st, analysis, hc, localCatalog, logger, nil)
	if err != nil {
		return nil, err
	}
	if err := src.Client.LoadActive(ctx); err != nil {
		// The next update installs a fresh feed; until then direct data
		// already in the database stays in use.
		logger.Error("installed feed could not be loaded", "err", err)
	}
	return src, nil
}
