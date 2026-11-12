// SPDX-License-Identifier: Apache-2.0

// Package pipeline runs the analysis stages over the stored inventory:
// identification and version resolution, then matching against stored
// advisories; exposure and policy join in later. Each run recomputes
// everything from the current state, which keeps it idempotent and cheap at
// homelab scale.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/exposure"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/notify"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/store"
)

// Store is the persistence the pipeline needs.
type Store interface {
	Workloads(ctx context.Context, f store.WorkloadFilter) ([]inventory.Workload, error)
	ReplaceIdentifications(ctx context.Context, rs []identify.Result, now time.Time) error
	Advisories(ctx context.Context, appID string) ([]store.AdvisoryRecord, error)
	KEV(ctx context.Context) (map[string]bool, error)
	EPSS(ctx context.Context) (map[string]float64, error)
	SyncFindingsSeen(ctx context.Context, current []store.FindingInput, seen map[string]string, now time.Time) (store.FindingChanges, error)
	Findings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	SetAssessments(ctx context.Context, as []store.Assessment) error
	ExpireSnoozes(ctx context.Context, now time.Time) (int64, error)
	ApplySuppressions(ctx context.Context, now time.Time) error
	Hosts(ctx context.Context) ([]inventory.Host, error)
	ImageTags(ctx context.Context) (map[string]store.ImageTag, error)
	ImagePackagesFor(ctx context.Context, refs []store.ImageRef) (map[store.ImageRef]inventory.ImagePackages, error)
	Integrations(ctx context.Context) ([]store.Integration, error)
	Devices(ctx context.Context) ([]store.StoredDevice, error)
	HostSurfaces(ctx context.Context) (map[string]store.HostSurface, error)
	AssetIDs(ctx context.Context) (map[string]string, error)
	ReplacePaths(ctx context.Context, ps []paths.Path, now time.Time) error
}

// Options configures the later stages. Exposure and Policy are read on
// every run so that settings changes apply without a restart.
type Options struct {
	Exposure func() *exposure.Detector
	Policy   func() policy.Thresholds
	// Scope are the networks Varde may scan: scanned devices outside them
	// do not count for the attack paths.
	Scope func() discovery.Scope
	// BaseURL, when set, is used to link findings in notifications.
	BaseURL string
}

// Pipeline analyses the inventory.
type Pipeline struct {
	cat   *catalog.Live
	store Store
	log   *slog.Logger
	now   func() time.Time
	opts  Options

	// AppsChanged, if set, is called when the set of identified apps
	// differs from the previous run (so advisory data can be fetched).
	AppsChanged func()
	// ImageLookup, if set, returns a second table of images and their
	// repositories whose evidence adds to the embedded index, or nil. It
	// is reserved for a table the uplink feed delivers (ADR 0037): no
	// installation downloads lists itself.
	ImageLookup func() coverage.ImageLookup
	// Superseded, if set, reports that the stored advisories of source no
	// longer count for app, because that source is not refreshed for it
	// any more. The default drops every source but the feed for apps
	// whose catalog entry comes from the feed.
	Superseded func(app *catalog.App, source string) bool
	// ImageIndex, if set, is the lookup in the embedded first-party index
	// (ADR 0038); it needs no connection and is always used.
	ImageIndex coverage.ImageLookup
	// Assessed, if set, is called after findings were prioritised (the
	// notifier evaluates them).
	Assessed func(ctx context.Context)
	// Covered, if set, is called with the analysed workloads and their
	// identifications (coverage notices are derived from them).
	Covered func(ctx context.Context, ws []inventory.Workload, ids []identify.Result)

	mu       sync.Mutex  // runs are serialised
	gate     sync.Mutex  // RunLogged: the run under way
	queued   atomic.Bool // RunLogged: a run waits for gate
	lastApps string
	apps     []*catalog.App
}

// New returns a pipeline over cat and st.
func New(cat *catalog.Catalog, st Store, log *slog.Logger, opts Options) *Pipeline {
	if opts.Exposure == nil {
		d := exposure.New(exposure.Config{})
		opts.Exposure = func() *exposure.Detector { return d }
	}
	if opts.Policy == nil {
		opts.Policy = policy.Defaults
	}
	if opts.Scope == nil {
		opts.Scope = func() discovery.Scope { return discovery.Scope{} }
	}
	return &Pipeline{cat: catalog.NewLive(cat), store: st, log: log, now: time.Now, opts: opts}
}

// Summary counts the outcome of a run.
type Summary struct {
	Workloads      int
	Identified     int
	Weak           int
	VersionUnknown int
	// SystemPackages are the system packages checked (ADR 0032),
	// ImagePackages the source packages of container images (ADR 0033).
	SystemPackages int
	ImagePackages  int
	Affected       int
	Unverified     int
	Changes        store.FindingChanges
}

// Run analyses all active workloads.
func (p *Pipeline) Run(ctx context.Context) (Summary, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	start := p.now()

	ws, err := p.store.Workloads(ctx, store.WorkloadFilter{})
	if err != nil {
		return Summary{}, fmt.Errorf("load workloads: %w", err)
	}
	// Apps the catalog does not know yet are derived from their images'
	// source labels on every run, so a new app needs no catalog release.
	lookups := coverage.Lookups{Index: p.ImageIndex}
	if p.ImageLookup != nil {
		lookups.Lists = p.ImageLookup()
	}
	if err := p.cat.SetDerived(coverage.DeriveAppsWith(p.cat.Current(), lookups, ws)); err != nil {
		p.log.Warn("derived catalog entries rejected", "err", err)
	}
	cat := p.cat.Current()
	tags, err := p.store.ImageTags(ctx)
	if err != nil {
		return Summary{}, fmt.Errorf("load image tags: %w", err)
	}
	var refs []store.ImageRef
	for i := range ws {
		if c := ws[i].Container; c != nil {
			if ref, err := imageref.Parse(c.ImageRef); err == nil {
				if t := tags[ref.Repository+"@"+registry.RepoDigest(c, ref.Repository)]; t.Tag != "" {
					c.ResolvedTag = t.Tag
				}
			}
			if c.ImageID != "" {
				refs = append(refs, store.ImageRef{ImageID: c.ImageID, HostID: ws[i].HostID})
			}
		}
	}
	pkgs, err := p.store.ImagePackagesFor(ctx, refs)
	if err != nil {
		return Summary{}, fmt.Errorf("load image packages: %w", err)
	}
	// read are the containers whose image packages were read completely.
	read := map[string]bool{}
	for i := range ws {
		if c := ws[i].Container; c != nil {
			if ip, ok := pkgs[store.ImageRef{ImageID: c.ImageID, HostID: ws[i].HostID}]; ok {
				c.Distro, c.Packages = ip.Distro, ip.Packages
				read[ws[i].ID] = ip.Error == "" && !ip.Partial
			}
		}
	}
	results := make([]identify.Result, 0, len(ws))
	var sum Summary
	appSet := map[string]*catalog.App{}
	// System packages are matched against their distribution's records
	// under an app of their own, which no other source refreshes.
	systemApps := map[string]*catalog.App{}
	for _, w := range ws {
		r := identify.Identify(cat, w)
		results = append(results, r)
		if identify.IsSystem(w) {
			sum.SystemPackages++
			if r.Confidence.Notifiable() {
				systemApps[r.AppID] = &catalog.App{ID: r.AppID, Name: w.Name}
			}
			continue
		}
		sum.Workloads++
		switch {
		case r.Confidence.Notifiable():
			sum.Identified++
			if !r.VersionKnown() {
				sum.VersionUnknown++
			}
			if app, ok := cat.App(r.AppID); ok {
				appSet[app.ID] = app
			}
		case r.Confidence == identify.Weak:
			sum.Weak++
		}
	}
	// The packages of each container's image are checked the same way, as
	// findings of the container (ADR 0033).
	var images []imageTarget
	for _, w := range ws {
		if w.Container == nil || w.RemovedAt != nil {
			continue
		}
		for _, pkg := range identify.ImageCheckedPackages(w.Container) {
			id := distro.SystemAppID(pkg.Ecosystem, pkg.Name)
			if systemApps[id] == nil {
				systemApps[id] = &catalog.App{ID: id, Name: pkg.Name}
			}
			images = append(images, imageTarget{workloadID: w.ID, pkg: pkg})
		}
	}
	sum.ImagePackages = len(images)
	all := make(map[string]*catalog.App, len(appSet)+len(systemApps))
	for id, a := range appSet {
		all[id] = a
	}
	for id, a := range systemApps {
		all[id] = a
	}
	findings, unfixed, err := p.match(ctx, results, images, all)
	if err != nil {
		return Summary{}, err
	}
	// Issues of a system package without a fix are kept with its
	// identification, for the system's page; they are not findings.
	for i := range results {
		results[i].Unfixed = unfixed[results[i].WorkloadID]
	}
	if err := p.store.ReplaceIdentifications(ctx, results, start); err != nil {
		return Summary{}, err
	}
	for _, f := range findings {
		if f.MatchState == string(match.Affected) {
			sum.Affected++
		} else {
			sum.Unverified++
		}
	}
	if sum.Changes, err = p.store.SyncFindingsSeen(ctx, findings, seenVersions(results, images, read), start); err != nil {
		return Summary{}, err
	}
	if _, err := p.store.ExpireSnoozes(ctx, start); err != nil {
		return Summary{}, err
	}
	if err := p.store.ApplySuppressions(ctx, start); err != nil {
		return Summary{}, err
	}
	if err := p.assess(ctx, ws); err != nil {
		return Summary{}, err
	}

	p.updateApps(appSet)
	if p.Covered != nil {
		p.Covered(ctx, ws, results)
	}
	p.log.Info("analysis complete", "workloads", sum.Workloads, "system_packages", sum.SystemPackages, "image_packages", sum.ImagePackages, "identified", sum.Identified,
		"weak", sum.Weak, "version_unknown", sum.VersionUnknown, "affected", sum.Affected, "unverified", sum.Unverified,
		"new", len(sum.Changes.New), "resolved", len(sum.Changes.Resolved),
		"duration", p.now().Sub(start).Round(time.Millisecond))
	if p.Assessed != nil {
		p.Assessed(ctx)
	}
	return sum, nil
}

// assess computes exposure and priority for every non-resolved finding.
func (p *Pipeline) assess(ctx context.Context, ws []inventory.Workload) error {
	fs, err := p.store.Findings(ctx, store.FindingFilter{})
	if err != nil {
		return err
	}
	byID := make(map[string]inventory.Workload, len(ws))
	for _, w := range ws {
		byID[w.ID] = w
	}
	detector, thresholds := p.opts.Exposure(), p.opts.Policy()
	ins, err := p.store.Integrations(ctx)
	if err != nil {
		return err
	}
	hosts, err := p.store.Hosts(ctx)
	if err != nil {
		return err
	}
	detector = detector.WithRoutes(coverage.ProxyRoutes(ins, hosts))
	exp := containerExposures(ws, detector)
	details := make(map[string]match.Finding, len(fs))
	for _, f := range fs {
		if _, ok := exp[f.WorkloadID]; !ok {
			exp[f.WorkloadID] = detector.Detect(byID[f.WorkloadID])
		}
		var m match.Finding
		if err := json.Unmarshal(f.Detail, &m); err != nil {
			return fmt.Errorf("decode finding %s: %w", f.ID, err)
		}
		details[f.ID] = m
	}
	res, err := p.analysePaths(ctx, pathState{ws: ws, hosts: hosts, ins: ins, detector: detector, exp: exp}, fs, details)
	if err != nil {
		return fmt.Errorf("attack paths: %w", err)
	}
	as := make([]store.Assessment, 0, len(fs))
	for _, f := range fs {
		e, m := exp[f.WorkloadID], details[f.ID]
		prio, reason := thresholds.Assess(policy.Input{
			Affected: f.MatchState == string(match.Affected), KEV: m.KEV, CVSS: m.CVSS, EPSS: m.EPSS, Exposure: e.Exposure,
		})
		pl := res.Placements[f.ID]
		prio, reason = pathPriority(prio, reason, pl, m, e.Exposure)
		as = append(as, store.Assessment{ID: f.ID, Priority: string(prio), Reason: reason, Exposure: string(e.Exposure), ExposureEvidence: e.Evidence,
			PathClass: string(pl.Class), PathReason: pl.Reason})
	}
	if err := p.store.SetAssessments(ctx, as); err != nil {
		return err
	}
	return p.store.ReplacePaths(ctx, res.Paths, p.now())
}

// Candidates returns all non-resolved findings prepared for notification
// decisions and rendering.
func (p *Pipeline) Candidates(ctx context.Context) ([]notify.Candidate, error) {
	all, err := p.store.Findings(ctx, store.FindingFilter{IncludeResolved: true})
	if err != nil {
		return nil, err
	}
	// Resolved findings count for the weekly digest's "resolved" part, for
	// two weeks; older ones are left out.
	cutoff := p.now().Add(-14 * 24 * time.Hour)
	fs := all[:0]
	for _, f := range all {
		if f.State != store.StateResolved || (f.ResolvedAt != nil && f.ResolvedAt.After(cutoff)) {
			fs = append(fs, f)
		}
	}
	ws, err := p.store.Workloads(ctx, store.WorkloadFilter{IncludeRemoved: true})
	if err != nil {
		return nil, err
	}
	hosts, err := p.store.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	wByID := make(map[string]inventory.Workload, len(ws))
	for _, w := range ws {
		wByID[w.ID] = w
	}
	hostName := make(map[string]string, len(hosts))
	for _, h := range hosts {
		hostName[h.ID] = h.Name
	}
	out := make([]notify.Candidate, 0, len(fs))
	for _, f := range fs {
		var m match.Finding
		if err := json.Unmarshal(f.Detail, &m); err != nil {
			return nil, fmt.Errorf("decode finding %s: %w", f.ID, err)
		}
		w := wByID[f.WorkloadID]
		appName := f.AppID
		if app, ok := p.cat.Current().App(f.AppID); ok {
			appName = app.Name
		} else if name, ok := distro.SystemName(f.AppID); ok {
			appName = name
		}
		it := notify.Item{
			FindingID: f.ID, AppID: f.AppID, AppName: appName, WorkloadName: w.Name, HostName: hostName[w.HostID],
			Version: m.Evidence.Version, AdvisoryID: f.AdvisoryID, Aliases: m.Aliases, Summary: m.Summary,
			Severity: m.SeverityLabel, CVSS: m.CVSS, KEV: m.KEV, EPSS: m.EPSS, Exposure: f.Exposure,
			ExposureEvidence: f.ExposureEvidence, FixedIn: f.FixedIn, AdvisoryURL: m.URL,
			Priority: policy.Priority(f.Priority), PriorityReason: f.PriorityReason, MatchState: f.MatchState,
			Image: m.Image, PathClass: f.PathClass, PathReason: f.PathReason,
		}
		if p.opts.BaseURL != "" {
			it.FindingURL = strings.TrimRight(p.opts.BaseURL, "/") + "/findings/" + f.ID
		}
		out = append(out, notify.Candidate{
			Item: it, State: f.State, SnoozedUntil: f.SnoozedUntil, FirstSeen: f.FirstSeen,
			LastNotified: policy.Priority(f.LastNotifiedPriority), DigestPending: policy.Priority(f.DigestPending),
			ResolvedAt: f.ResolvedAt,
		})
	}
	return out, nil
}

// match evaluates every confidently identified workload. Weak or absent
// identifications never produce findings (ADR 0008).
// imageTarget is a source package of a container's image.
type imageTarget struct {
	workloadID string
	pkg        distro.Package
}

func (p *Pipeline) match(ctx context.Context, results []identify.Result, images []imageTarget, apps map[string]*catalog.App) ([]store.FindingInput, map[string]int, error) {
	unfixed := map[string]int{}
	if len(apps) == 0 {
		return nil, unfixed, nil
	}
	kev, err := p.store.KEV(ctx)
	if err != nil {
		return nil, nil, err
	}
	epss, err := p.store.EPSS(ctx)
	if err != nil {
		return nil, nil, err
	}
	enr := match.Enrichment{KEV: kev, EPSS: epss}
	advisories := map[string][]match.Advisory{}
	for id := range apps {
		recs, err := p.store.Advisories(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		advisories[id] = advisoriesFor(apps[id], recs, p.Superseded)
	}

	var out []store.FindingInput
	for _, r := range results {
		if !r.Confidence.Notifiable() {
			continue
		}
		app := apps[r.AppID]
		if app == nil {
			continue
		}
		system := strings.HasPrefix(app.ID, distro.SystemPrefix)
		for _, f := range match.Match(match.Input{App: app, Version: r.Version, VersionSource: r.VersionSource, Doubt: r.Doubt(), Distro: r.DistroPackage}, advisories[app.ID], enr) {
			// A system package is reported when an update fixes it: the
			// distribution's unfixed and minor issues would bury the
			// actionable ones (ADR 0032).
			if system && (f.FixedIn == "" || f.State != match.Affected) {
				if f.State == match.Affected {
					unfixed[r.WorkloadID]++
				}
				continue
			}
			out = append(out, store.FindingInput{
				WorkloadID: r.WorkloadID, AppID: app.ID, AdvisoryID: f.AdvisoryID,
				MatchState: string(f.State), FixedIn: f.FixedIn, Detail: f,
			})
		}
	}
	// Image packages: reported like system packages, when an update of
	// the image fixes them. A container keeps one finding per advisory.
	seen := map[string]bool{}
	for _, f := range out {
		seen[f.ID()] = true
	}
	for _, t := range images {
		app := apps[distro.SystemAppID(t.pkg.Ecosystem, t.pkg.Name)]
		if app == nil {
			continue
		}
		pkg := t.pkg
		for _, f := range match.Match(match.Input{App: app, Distro: &pkg}, advisories[app.ID], enr) {
			// The finding's own ID: a Go or npm advisory naming several
			// modules is one finding per module (store.FindingInput.ID).
			key := store.FindingInput{WorkloadID: t.workloadID, AppID: app.ID, AdvisoryID: f.AdvisoryID}.ID()
			if f.State == match.Affected && f.FixedIn == "" && !seen[key] {
				// Not fixed in any image yet: counted with the container.
				seen[key] = true
				unfixed[t.workloadID]++
				continue
			}
			if f.FixedIn == "" || f.State != match.Affected || seen[key] {
				continue
			}
			seen[key] = true
			f.Image = true
			out = append(out, store.FindingInput{
				WorkloadID: t.workloadID, AppID: app.ID, AdvisoryID: f.AdvisoryID,
				MatchState: string(f.State), FixedIn: f.FixedIn, Detail: f,
			})
		}
	}
	return out, unfixed, nil
}

// seenVersions is the version of every app and package the analysis
// checked, keyed by store.SeenKey: the version a finding's evidence names,
// so that a resolved finding tells an update from a withdrawn advisory.
func seenVersions(results []identify.Result, images []imageTarget, read map[string]bool) map[string]string {
	seen := make(map[string]string, len(results)+len(images))
	for id, ok := range read {
		if ok {
			seen[store.SeenKey(id, store.SeenImage)] = ""
		}
	}
	for _, r := range results {
		seen[store.SeenKey(r.WorkloadID, store.SeenApps)] = ""
		if !r.Confidence.Notifiable() || r.AppID == "" {
			continue
		}
		v := r.Version
		if r.DistroPackage != nil {
			v = r.DistroPackage.Version
		}
		seen[store.SeenKey(r.WorkloadID, r.AppID)] = v
	}
	for _, t := range images {
		key := store.SeenKey(t.workloadID, distro.SystemAppID(t.pkg.Ecosystem, t.pkg.Name))
		if _, ok := seen[key]; !ok {
			seen[key] = t.pkg.Version
		}
	}
	return seen
}

func (p *Pipeline) updateApps(set map[string]*catalog.App) {
	ids := make([]string, 0, len(set))
	apps := make([]*catalog.App, 0, len(set))
	for id, a := range set {
		ids = append(ids, id)
		apps = append(apps, a)
	}
	sort.Strings(ids)
	sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })
	key := strings.Join(ids, ",")
	changed := key != p.lastApps
	p.lastApps, p.apps = key, apps
	if changed && p.AppsChanged != nil {
		p.AppsChanged()
	}
}

// Apps returns the catalog apps identified in the last run.
func (p *Pipeline) Apps(context.Context) ([]*catalog.App, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*catalog.App(nil), p.apps...), nil
}

// RunLogged runs the pipeline and logs failures; for use as a callback.
//
// Requests coalesce: while one run waits for the running one, further
// requests return at once, since the waiting run will see their changes.
// A flood of reports thus keeps at most one run waiting.
func (p *Pipeline) RunLogged(ctx context.Context) {
	if !p.queued.CompareAndSwap(false, true) {
		return
	}
	p.gate.Lock()
	defer p.gate.Unlock()
	// From here on a new request queues the next run.
	p.queued.Store(false)
	if _, err := p.Run(ctx); err != nil && ctx.Err() == nil {
		p.log.Error("analysis failed", "err", err)
	}
}

// Catalog returns the live catalog holder shared with the UI.
func (p *Pipeline) Catalog() *catalog.Live { return p.cat }

// feedAlone is the default of Pipeline.Superseded: an app whose catalog
// entry comes from the feed is judged by the feed alone. The direct sources
// stop refreshing it (hybrid mode), so their earlier records would go stale
// and keep findings open.
func feedAlone(app *catalog.App, source string) bool {
	return app != nil && app.Origin == catalog.OriginFeed && source != store.FeedSource
}

// advisoriesFor are the stored advisories that count for app: all but
// those of a source that superseded says is no longer refreshed for it.
// The records stay stored and count again when that changes.
func advisoriesFor(app *catalog.App, recs []store.AdvisoryRecord, superseded func(*catalog.App, string) bool) []match.Advisory {
	if superseded == nil {
		superseded = feedAlone
	}
	out := make([]match.Advisory, 0, len(recs))
	for _, r := range recs {
		if superseded(app, r.Source) {
			continue
		}
		out = append(out, match.Advisory{Source: r.Source, Vuln: r.Vuln, CVSS: r.CVSS, SeverityLabel: r.SeverityLabel})
	}
	return out
}
