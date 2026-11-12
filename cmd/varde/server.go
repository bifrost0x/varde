// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/index"
	"github.com/bifrost0x/varde/internal/advisory/sources"
	"github.com/bifrost0x/varde/internal/agent"
	"github.com/bifrost0x/varde/internal/api"
	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/datapkg"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/fleet"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/notify"
	"github.com/bifrost0x/varde/internal/pipeline"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/settings"
	findingstatus "github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/uplink"
	"github.com/bifrost0x/varde/internal/web"
)

// defaultSocketPath is where a directly mounted Docker socket would appear.
const defaultSocketPath = "/var/run/docker.sock"

// serverDeps holds what tests need to replace.
type serverDeps struct {
	socketPath string
}

// serve runs the server until ctx is cancelled, then shuts everything down
// gracefully within shutdownTimeout.
func serve(ctx context.Context, cfg config.Config, logger *slog.Logger, deps serverDeps) error {
	if err := checkDirectSocket(deps.socketPath, cfg.AllowDirectSocket, logger); err != nil {
		return err
	}

	cat, localCatalog, err := loadCatalog(cfg.CatalogDir, logger)
	if err != nil {
		return err
	}

	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, "varde.db"))
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			logger.Error("closing database", "err", err)
		}
	}()

	settingsSvc, err := settings.New(ctx, st, cfg)
	if err != nil {
		return err
	}

	runCtx, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()
	analysis := pipeline.New(cat, st, logger, pipeline.Options{
		Exposure: settingsSvc.Exposure,
		Policy:   func() policy.Thresholds { return settingsSvc.Get().Policy },
		Scope:    func() discovery.Scope { return settingsSvc.Get().Networks },
		BaseURL:  cfg.BaseURL,
	})

	caPool, err := rootCAs(cfg)
	if err != nil {
		return err
	}
	refresher, uplinkMgr, packageMgr, err := newRefresher(ctx, cfg, st, analysis, settingsSvc, localCatalog, logger)
	if err != nil {
		return err
	}
	analysis.AppsChanged = refresher.Trigger

	notifier := newNotifier(cfg, st, analysis, settingsSvc, logger)
	analysis.Assessed = func(ctx context.Context) {
		if err := notifier.Evaluate(ctx); err != nil && ctx.Err() == nil {
			logger.Error("notification evaluation failed", "err", err)
		}
	}
	wireCoverage(st, settingsSvc, analysis, logger)

	// One reader for the local host and the Docker integrations: an image
	// is read once, wherever it runs.
	packages := &docker.PackageReader{
		Store: st, Enabled: func() bool { return settingsSvc.Get().ContainerPackages },
		Changed: analysis.RunLogged, Log: logger, Now: time.Now,
	}
	var syncer *inventory.Syncer
	if cfg.DockerEnabled() {
		client, err := docker.New(cfg.DockerHost)
		if err != nil {
			return err
		}
		collector := docker.NewCollector(client, logger)
		collector.Packages = packages
		syncer = inventory.NewSyncer(inventory.SyncerConfig{
			HostID:    inventory.LocalHostID,
			HostKind:  inventory.HostDocker,
			Source:    inventory.SourceLocal,
			Collector: collector,
			Store:     st,
			Log:       logger,
			Resync:    cfg.ResyncInterval,
			// Varde's own addresses tie the local host to the device the
			// network scan finds for it.
			Addresses: append(ownAddresses(logger), cfg.HostAddresses...),
			OnChange:  func(inventory.Changes) { analysis.RunLogged(runCtx) },
		})
	} else {
		logger.Warn("local Docker collector disabled", "env", buildinfo.EnvPrefix+"DOCKER_HOST="+config.DockerHostOff)
		// Manual entries still need analysis with the current catalog.
		analysis.RunLogged(runCtx)
	}

	network, err := integrations.New(integrations.Options{
		Store: st, DataDir: cfg.DataDir, Log: logger,
		Scope:     func() discovery.Scope { return settingsSvc.Get().Networks },
		Changed:   analysis.RunLogged,
		Catalog:   func() *catalog.Catalog { return analysis.Catalog().Current() },
		ScanEvery: func() time.Duration { return settingsSvc.Get().ScanEvery },
		Packages:  packages,
		SNMP:      snmpCredentials(cfg),
	})
	if err != nil {
		return err
	}

	binaries, err := fleet.LoadBinaries(cfg.AgentBinaryDir)
	if err != nil {
		return err
	}
	ca, agentSrv, err := newAgentListener(cfg, st, analysis, network, binaries,
		func() bool { return settingsSvc.Get().ContainerPackages }, logger)
	if err != nil {
		return err
	}

	if err := ensureSetupToken(ctx, st, logger); err != nil {
		return err
	}
	handler, err := newHandler(cfg, st, analysis.Catalog(), settingsSvc, analysis, notifier, syncer, refresher, ca, network, binaries, uplinkMgr, packageMgr, logger)
	if err != nil {
		return err
	}
	srv := web.NewServer(cfg.ListenAddr, logger, handler)

	var workers sync.WaitGroup
	if syncer != nil {
		workers.Go(func() { syncer.Run(runCtx) })
	}
	workers.Go(func() { refresher.Run(runCtx) })
	resolver := &registry.Resolver{
		Client: registry.New(httpx.New(httpx.Options{AllowHosts: cfg.EgressAllowlist, Timeout: 20 * time.Second, RootCAs: caPool})),
		Store:  st, Catalog: func() *catalog.Catalog { return analysis.Catalog().Current() },
		Enabled: func() bool { return settingsSvc.Get().RegistryTags },
		Changed: analysis.RunLogged, Log: logger, Now: time.Now,
	}
	workers.Go(func() { resolver.Run(runCtx, 30*time.Minute) })
	workers.Go(func() { network.Run(runCtx) })
	workers.Go(func() { notifier.Run(runCtx) })
	workers.Go(func() { housekeeping(runCtx, st, analysis, logger) })
	workers.Go(func() {
		runLiveness(runCtx, st, func() discovery.Scope { return settingsSvc.Get().Networks }, network.Interval, logger)
	})

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr, "version", buildinfo.Version)
		errCh <- srv.ListenAndServe()
	}()
	agentErr := make(chan error, 1)
	if agentSrv != nil {
		go func() {
			logger.Info("agent listener (mTLS)", "addr", cfg.AgentListenAddr, "ca_pin", ca.Pin())
			agentErr <- agentSrv.ListenAndServeTLS("", "")
		}()
	}

	var runErr error
	select {
	case err := <-errCh:
		runErr = fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	case err := <-agentErr:
		runErr = fmt.Errorf("agent listener on %s: %w", cfg.AgentListenAddr, err)
		_ = srv.Close()
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		if agentSrv != nil {
			if err := agentSrv.Shutdown(shutdownCtx); err != nil {
				logger.Warn("agent listener shutdown", "err", err)
			}
		}
		if err := srv.Shutdown(shutdownCtx); err != nil {
			runErr = fmt.Errorf("graceful shutdown: %w", err)
		} else if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
		}
	}

	stopWorkers()
	workers.Wait()
	return runErr
}

// ensureSetupToken creates a one-time setup token while no account exists
// and prints it once. The token is stored only as a hash.
func ensureSetupToken(ctx context.Context, st *store.Store, logger *slog.Logger) error {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	token, err := auth.RandomToken(24)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := st.CreateSetupToken(ctx, auth.HashToken(token), now, now.Add(24*time.Hour)); err != nil {
		return err
	}
	logger.Warn("no account exists yet: open the web UI and complete setup with this one-time token (valid 24 hours, shown only now)",
		"setup_token", token)
	return nil
}

// newHandler builds the authentication components, the API and the UI.
func newHandler(cfg config.Config, st *store.Store, cat *catalog.Live, set *settings.Service, analysis *pipeline.Pipeline,
	notifier *notify.Service, syncer *inventory.Syncer, refresher *sources.Refresher, ca *fleet.CA, network *integrations.Manager,
	binaries *fleet.Binaries, uplinkMgr *uplink.Manager, packageMgr *datapkg.Manager, logger *slog.Logger,
) (http.Handler, error) {
	proxies, err := auth.NewProxies(cfg.TrustedProxies, cfg.BehindTLSProxy)
	if err != nil {
		return nil, err
	}
	mode := auth.CookieMode(cfg.CookieSecure)
	if cfg.BehindTLSProxy {
		mode = auth.CookieAlways
	}
	if mode == auth.CookieNever {
		logger.Warn("session cookies without the Secure attribute; use only on a trusted local network")
	}
	sessions := auth.NewSessions(st, mode, proxies)
	apiAuth := &auth.APIAuth{Tokens: st, Static: string(cfg.APIToken), Sessions: sessions}
	scan := func() {
		if syncer != nil {
			syncer.Trigger()
		}
		network.Trigger()
		refresher.Trigger()
	}
	lastScan := func() time.Time {
		if syncer != nil {
			return syncer.LastSync()
		}
		return time.Time{}
	}
	// The API status uses the same counts and the same host merge as the
	// overview (internal/status, internal/coverage).
	status := func(ctx context.Context) (any, error) {
		fs, err := st.Findings(ctx, store.FindingFilter{})
		if err != nil {
			return nil, err
		}
		hosts, err := st.Hosts(ctx)
		if err != nil {
			return nil, err
		}
		devs, err := st.Devices(ctx)
		if err != nil {
			return nil, err
		}
		ins, err := st.Integrations(ctx)
		if err != nil {
			return nil, err
		}
		ms := coverage.Machines(coverage.MachineInput{Hosts: hosts, Devices: devs, Integrations: ins, Scope: set.Get().Networks,
			Now: time.Now(), Interval: network.Interval})
		owner, err := st.AssetIDs(ctx)
		if err != nil {
			return nil, err
		}
		coverage.ApplyAssetIDs(ms, owner)
		counts := findingstatus.Count(fs)
		out := map[string]any{
			"status": counts.State(), "open": counts.Open(), "new": counts.New, "acknowledged": counts.Acknowledged,
			"hosts": coverage.CountMachines(ms), "version": buildinfo.Version,
		}
		if t := coverage.LastInventory(ms); !t.IsZero() {
			out["last_inventory_sync"] = t
		}
		return out, nil
	}
	channels := []string{}
	if notifier.Enabled() {
		channels = notifier.ChannelNames()
	}
	ready := func(ctx context.Context) error {
		if err := st.Ping(ctx); err != nil {
			return err
		}
		if syncer != nil {
			return syncer.Ready()
		}
		return nil
	}
	return web.New(web.Deps{
		Store: st, Catalog: cat, Settings: set, Sessions: sessions, Throttle: auth.NewThrottle(), Proxies: proxies, APIAuth: apiAuth,
		API: api.New(api.Options{
			Store: st, Authenticate: apiAuth.Authenticate, Log: logger,
			Changed:  func(ctx context.Context) { analysis.RunLogged(ctx) },
			Notifier: optionalNotifier(notifier), Status: status, Scan: scan,
			Scope: func() discovery.Scope { return set.Get().Networks }, Interval: network.Interval,
		}),
		Ready: ready, Analyze: analysis.RunLogged, Scan: scan, Notifier: optionalNotifier(notifier), Channels: channels,
		LastScan: lastScan, AllowDirectSocket: cfg.AllowDirectSocket, CookieNever: mode == auth.CookieNever,
		BehindTLS: cfg.BehindTLSProxy, GitHubToken: cfg.GitHubToken != "", Log: logger,
		AgentCAPin: caPin(ca), AgentListenAddr: cfg.AgentListenAddr, HostAddresses: cfg.HostAddresses, AgentBinaries: binaries, Network: network, Mode: cfg.Mode, Uplink: uplinkMgr, Package: packageMgr, LocalDocker: syncer != nil,
	})
}

// newNotifier builds the configured notification channels.
func newNotifier(cfg config.Config, st *store.Store, analysis *pipeline.Pipeline, set *settings.Service, logger *slog.Logger) *notify.Service {
	n := cfg.Notify
	// Notification endpoints are configured explicitly by the operator and
	// often live in the LAN without TLS, so plain http is allowed here.
	// The bundle was read once at startup already (newRefresher fails on a
	// broken one), so an error here cannot happen.
	pool, _ := rootCAs(cfg)
	hc := httpx.New(httpx.Options{AllowHosts: cfg.EgressAllowlist, AllowHTTP: true, Timeout: 20 * time.Second, RootCAs: pool})
	var channels []notify.Channel
	if n.NtfyURL != "" {
		channels = append(channels, &notify.Ntfy{HTTP: hc, URL: n.NtfyURL, Token: string(n.NtfyToken)})
	}
	if n.GotifyURL != "" {
		channels = append(channels, &notify.Gotify{HTTP: hc, URL: n.GotifyURL, Token: string(n.GotifyToken)})
	}
	if n.WebhookURL != "" {
		channels = append(channels, &notify.Webhook{HTTP: hc, URL: n.WebhookURL, Secret: string(n.WebhookSecret)})
	}
	if n.DiscordWebhookURL != "" {
		channels = append(channels, &notify.Discord{HTTP: hc, URL: string(n.DiscordWebhookURL)})
	}
	if n.TelegramToken != "" {
		channels = append(channels, &notify.Telegram{HTTP: hc, Token: string(n.TelegramToken), ChatID: n.TelegramChatID})
	}
	if n.SMTPHost != "" {
		channels = append(channels, &notify.SMTP{Host: n.SMTPHost, Port: n.SMTPPort, Username: n.SMTPUsername,
			Password: string(n.SMTPPassword), From: n.SMTPFrom, To: n.SMTPTo, TLSMode: n.SMTPTLS})
	}
	for _, u := range []string{n.NtfyURL, n.GotifyURL, n.WebhookURL} {
		if strings.HasPrefix(u, "http://") {
			logger.Warn("notification endpoint uses plain http; tokens and finding details travel unencrypted", "url", u)
		}
	}
	if len(channels) == 0 {
		logger.Warn("no notification channel configured; findings are only visible via the API")
	} else {
		names := make([]string, 0, len(channels))
		for _, c := range channels {
			names = append(names, c.Name())
		}
		logger.Info("notification channels configured", "channels", strings.Join(names, ","))
	}
	notices, noticesSent := pendingNotices(st)
	return notify.NewService(notify.Config{
		Channels:    channels,
		Store:       st,
		Candidates:  analysis.Candidates,
		Log:         logger,
		Notices:     notices,
		NoticesSent: noticesSent,
		Schedule: func() (int, time.Weekday) {
			e := set.Get()
			return e.DigestHour, e.DigestWeekday
		},
	})
}

// optionalNotifier hides an unconfigured notifier from the API so that the
// test endpoint reports "not configured".
func optionalNotifier(n *notify.Service) api.Notifier {
	if n == nil || !n.Enabled() {
		return nil
	}
	return n
}

// housekeeping applies retention and re-evaluates time-based state
// (snooze and suppression expiry) hourly.
func housekeeping(ctx context.Context, st *store.Store, analysis *pipeline.Pipeline, logger *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			if err := st.PurgeLogs(ctx, now); err != nil {
				logger.Warn("retention purge failed", "err", err)
			}
			if err := st.PurgeSessions(ctx, now, auth.IdleTimeout); err != nil {
				logger.Warn("session purge failed", "err", err)
			}
			// Removed workloads of every source, also when local Docker is
			// off (its syncer purges them too, on its own schedule).
			if _, err := st.PurgeRemoved(ctx, now.Add(-90*24*time.Hour)); err != nil {
				logger.Warn("removed workload purge failed", "err", err)
			}
			analysis.RunLogged(ctx)
		}
	}
}

// rootCAs is the system pool with VARDE_CA_BUNDLE_FILE added, nil without
// a bundle. Every outbound client uses it: advisory sources, notification
// channels and registries.
func rootCAs(cfg config.Config) (*x509.CertPool, error) {
	if cfg.CABundleFile == "" {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(cfg.CABundleFile)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contains no PEM certificates", cfg.CABundleFile)
	}
	return pool, nil
}

// newRefresher builds the direct-mode advisory sources.
func newRefresher(ctx context.Context, cfg config.Config, st *store.Store, analysis *pipeline.Pipeline, set *settings.Service,
	localCatalog fs.FS, logger *slog.Logger,
) (*sources.Refresher, *uplink.Manager, *datapkg.Manager, error) {
	pool, err := rootCAs(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	hc := httpx.New(httpx.Options{AllowHosts: cfg.EgressAllowlist, RootCAs: pool})
	deps := sources.Deps{HTTP: hc, Store: st}
	github := &sources.GitHub{Deps: deps, Token: string(cfg.GitHubToken)}
	// Sources with a switch of their own. None of their data is in the
	// data package, so they work the same with and without it.
	optional := []sources.Source{
		// Opt-in sources can be switched in the UI; they check on every run.
		sources.Toggle{Source: &sources.OSV{Deps: deps}, Enabled: func() bool { return set.Get().DirectOSV }},
		// Distribution security data also comes from osv.dev and reveals
		// package names and releases the same way, so one switch covers both.
		sources.Toggle{Source: &sources.Distro{Deps: deps, Packages: func(ctx context.Context) (map[string][]distro.Package, error) {
			ws, err := st.Workloads(ctx, store.WorkloadFilter{Kind: inventory.KindPackage})
			if err != nil {
				return nil, err
			}
			return identify.DistroPackages(analysis.Catalog().Current(), ws), nil
		}}, Enabled: func() bool { return set.Get().DirectOSV }},
		// Every system package of every host, the same way (ADR 0032).
		sources.Toggle{Source: &sources.SystemPackages{Deps: deps, Stored: st.SystemAdvisoryApps, Packages: func(ctx context.Context) ([]distro.Package, error) {
			return checkedPackages(ctx, st)
		}}, Enabled: func() bool { return set.Get().DirectOSV }},
		sources.Toggle{Source: &sources.EOL{Deps: deps, EOLStore: st}, Enabled: func() bool { return set.Get().EOLData }},
		sources.Toggle{Source: &sources.NVD{Deps: deps, APIKey: string(cfg.NVDAPIKey)}, Enabled: func() bool { return set.Get().DirectNVD }},
	}
	// Apps the catalog does not know are recognised through the embedded
	// first-party index (ADR 0038). An installation downloads nothing for
	// this: the table ships with the binary.
	if embedded, err := index.Table(); err != nil {
		logger.Error("embedded index could not be read; images are recognised without it", "err", err)
	} else if embedded.Len() > 0 {
		analysis.ImageIndex = func(image string) (string, []string, bool, bool) {
			e, ok := embedded.Lookup(image)
			return e.Repo, e.Lists, e.Confirmed(), ok
		}
		logger.Info("first-party index loaded", "images", embedded.Len())
	}
	// Enrichment last: EPSS needs the CVE IDs of freshly stored advisories.
	directSet := append(append([]sources.Source{github}, optional...), &sources.KEV{Deps: deps}, &sources.EPSS{Deps: deps})

	var refresher *sources.Refresher
	ch, err := newChannels(ctx, cfg, st, analysis, hc, localCatalog, logger, func() bool { return set.Get().DirectQueries }, func() {
		// The data changed or the mode did: analyse with the catalog that
		// applies now and fetch from the sources that apply now. Not in
		// the caller's time: a switch from the settings page answers
		// within its request.
		go analysis.RunLogged(ctx)
		if refresher != nil {
			refresher.Trigger()
		}
	})
	if err != nil {
		return nil, nil, nil, err
	}
	// With the data package or the uplink in use, GitHub is asked only
	// about apps the feed does not cover (local catalog entries, images
	// recognised by their label alone), and only when the user switched
	// that on. KEV comes from the feed. So does EPSS for the feed's own
	// CVEs; CVEs the other sources bring get their score from FIRST, last,
	// and only while one of those sources is on.
	channelSet := func(fsrc *feed.Source) []sources.Source {
		out := []sources.Source{fsrc, sources.Toggle{Source: sources.Only{Source: github, Keep: ch.cov.uncovered}, Enabled: ch.direct}}
		out = append(out, optional...)
		// Only for CVEs the feed did not bring: it carries their scores.
		outside := func(ctx context.Context) ([]string, error) { return st.AdvisoryCVEsExcept(ctx, store.FeedSource) }
		return append(out, sources.Toggle{Source: &sources.EPSS{Deps: deps, CVEs: outside}, Enabled: func() bool {
			eff := set.Get()
			return ch.direct() || eff.DirectOSV || eff.DirectNVD
		}})
	}
	// The static hybrid mode (VARDE_MODE): the direct sources cover the
	// apps the feed does not.
	hybridSet := func(fsrc sources.Source) []sources.Source {
		notFromFeed := func(a *catalog.App) bool { return a.Origin != catalog.OriginFeed }
		out := []sources.Source{fsrc}
		for _, s := range append([]sources.Source{github}, optional...) {
			out = append(out, sources.Only{Source: s, Keep: notFromFeed})
		}
		return out
	}
	if ch.src != nil {
		analysis.Superseded = ch.superseded
		// The table of the package is newer than the one in the binary.
		embedded := analysis.ImageIndex
		analysis.ImageIndex = func(image string) (string, []string, bool, bool) {
			if e, ok := ch.src.Client.Index().Lookup(image); ok {
				return e.Repo, e.Lists, e.Confirmed(), true
			}
			if embedded == nil {
				return "", nil, false, false
			}
			return embedded(image)
		}
	}

	r := sources.Refresher{Apps: analysis.Apps, OnChange: analysis.RunLogged, Log: logger, Interval: cfg.AdvisoryRefresh}
	switch {
	case ch.src != nil:
		// Package or uplink, chosen per run (ADR 0038).
		set := channelSet(ch.src)
		r.Pick = func() []sources.Source {
			if ch.inUse() {
				return set
			}
			return directSet
		}
	case cfg.Mode == "direct":
		r.Sources = directSet
	default:
		fsrc, err := newFeedSource(ctx, cfg, st, analysis, hc, localCatalog, logger)
		if err != nil {
			return nil, nil, nil, err
		}
		r.Sources = []sources.Source{fsrc}
		if cfg.Mode == "hybrid" {
			r.Sources = hybridSet(fsrc)
		}
	}
	if cfg.GitHubToken == "" && cfg.Mode == "direct" && !ch.hasPackage {
		logger.Info("no GitHub token configured; using the anonymous rate limit of 60 requests per hour")
	}
	logger.Info("advisory mode", "mode", cfg.Mode, "data package", ch.pkg.Available(), "uplink", ch.uplink.Status().State)
	refresher = sources.NewRefresher(r)
	return refresher, ch.uplink, ch.pkg, nil
}

// loadCatalog loads the built-in catalog plus local entries from dir, if
// the directory exists.
func loadCatalog(dir string, logger *slog.Logger) (*catalog.Catalog, fs.FS, error) {
	var local fs.FS
	switch fi, err := os.Stat(dir); {
	case err == nil && fi.IsDir():
		local = os.DirFS(dir)
	case err == nil:
		return nil, nil, fmt.Errorf("catalog directory %s is not a directory", dir)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, nil, fmt.Errorf("catalog directory %s: %w", dir, err)
	}
	cat, err := catalog.Load(catalogdata.FS(), local)
	if err != nil {
		return nil, nil, fmt.Errorf("load catalog: %w", err)
	}
	localCount := 0
	for _, a := range cat.Apps() {
		if a.Origin == catalog.OriginLocal {
			localCount++
		}
	}
	logger.Info("catalog loaded", "apps", cat.Len(), "local", localCount)
	return cat, local, nil
}

// checkDirectSocket refuses to run with the Docker socket mounted into the
// container: even unused, it hands root on the host to anyone who
// compromises this process (ADR 0006).
func checkDirectSocket(path string, allow bool, logger *slog.Logger) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		logger.Debug("cannot inspect docker socket path", "path", path, "err", err)
		return nil
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return nil
	}
	if !allow {
		return fmt.Errorf("the Docker socket is mounted at %s; this grants root on the host. "+
			"Remove the mount and use a read-only socket proxy, or set %sALLOW_DIRECT_SOCKET=true to accept the risk",
			path, buildinfo.EnvPrefix)
	}
	logger.Warn("running with a directly mounted Docker socket; a compromise of Varde gives root on the host", "path", path)
	return nil
}

// ownAddresses lists the unicast addresses of this process's network
// interfaces. In a container these are the container's addresses, which is
// what the scan sees when it reaches Varde over a Docker network; the Docker
// host's own LAN address is not visible from inside.
func ownAddresses(logger *slog.Logger) []string {
	addrs, err := agent.InterfaceAddresses()
	if err != nil {
		logger.Warn("reading own addresses failed", "err", err)
	}
	return addrs
}

// checkedPackages are the distribution packages checked against their
// distributions' security data: the system packages of hosts (ADR 0032)
// and the source packages of the images containers run (ADR 0033).
func checkedPackages(ctx context.Context, st *store.Store) ([]distro.Package, error) {
	ws, err := st.Workloads(ctx, store.WorkloadFilter{})
	if err != nil {
		return nil, err
	}
	out := identify.SystemPackages(ws)
	var ids []string
	seen := map[string]bool{}
	for _, w := range ws {
		if c := w.Container; c != nil && w.RemovedAt == nil && c.ImageID != "" && !seen[c.ImageID] {
			seen[c.ImageID] = true
			ids = append(ids, c.ImageID)
		}
	}
	imgs, err := st.ImagePackages(ctx, ids)
	if err != nil {
		return nil, err
	}
	have := map[distro.Package]bool{}
	for _, p := range out {
		have[p] = true
	}
	for _, ip := range imgs {
		for _, p := range identify.ImageCheckedPackages(&inventory.Container{Distro: ip.Distro, Packages: ip.Packages}) {
			if !have[p] {
				have[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// snmpCredentials is what scans send to read device descriptions; nil
// when none is configured.
func snmpCredentials(cfg config.Config) *discovery.SNMP {
	c := &discovery.SNMP{Community: string(cfg.SNMPCommunity), User: cfg.SNMPUser, Auth: string(cfg.SNMPAuth), Privacy: string(cfg.SNMPPrivacy)}
	if !c.Enabled() {
		return nil
	}
	return c
}
