// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory/sources"
	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/exposure"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
)

// snapshot is the joined state most pages need. Machines, workload coverage
// and finding counts come from one place (internal/coverage,
// internal/status), so every page shows the same numbers.
type snapshot struct {
	workloads []inventory.Workload
	// system are the system packages (ADR 0032); byID holds them too.
	system   []inventory.Workload
	byID     map[string]inventory.Workload
	ids      map[string]identify.Result
	findings []store.Finding
	hosts    []inventory.Host
	exposure *exposure.Detector
	// marked holds the image repositories marked as not an app.
	marked map[string]bool
	// tags are the known release tags per image repository, from the
	// data package or the registry.
	tags map[string]store.RepositoryTags
	// machines are the hosts and devices merged from every source; hostOf
	// maps a stored host ID to its machine.
	machines []coverage.Machine
	hostOf   map[string]*coverage.Machine
	// devices and integrations are loaded for the machines.
	devices      []store.StoredDevice
	integrations []store.Integration
}

func (a *app) load(ctx context.Context, includeResolved bool) (*snapshot, error) {
	ws, err := a.d.Store.Workloads(ctx, store.WorkloadFilter{})
	if err != nil {
		return nil, err
	}
	ids, err := a.d.Store.Identifications(ctx)
	if err != nil {
		return nil, err
	}
	fs, err := a.d.Store.Findings(ctx, store.FindingFilter{IncludeResolved: includeResolved})
	if err != nil {
		return nil, err
	}
	hosts, err := a.d.Store.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	marked, err := a.d.Store.NotAnApp(ctx)
	if err != nil {
		return nil, err
	}
	devs, err := a.d.Store.Devices(ctx)
	if err != nil {
		return nil, err
	}
	ins, err := a.d.Store.Integrations(ctx)
	if err != nil {
		return nil, err
	}
	s := &snapshot{byID: map[string]inventory.Workload{}, ids: ids, findings: fs, hosts: hosts,
		exposure: a.d.Settings.Exposure().WithRoutes(coverage.ProxyRoutes(ins, hosts)), marked: marked, devices: devs, integrations: ins, hostOf: map[string]*coverage.Machine{}}
	// Release tags only add the note that a newer release exists: a
	// store that cannot give them does not fail the page.
	if tags, err := a.d.Store.RepositoryTags(ctx); err == nil {
		s.tags = tags
	}
	perHost := map[string]int{}
	for _, w := range ws {
		s.byID[w.ID] = w
		// System packages are part of the system's package list; they are
		// neither apps nor gaps (ADR 0032).
		if identify.IsSystem(w) {
			s.system = append(s.system, w)
			continue
		}
		s.workloads = append(s.workloads, w)
		perHost[w.HostID]++
	}
	s.machines = coverage.Machines(coverage.MachineInput{
		Hosts: hosts, Devices: devs, Integrations: ins, Scope: a.d.Settings.Get().Networks, Workloads: perHost,
		Now: a.d.Now(), Interval: a.interval,
	})
	owner, err := a.d.Store.AssetIDs(ctx)
	if err != nil {
		return nil, err
	}
	coverage.ApplyAssetIDs(s.machines, owner)
	for i := range s.machines {
		for _, id := range s.machines[i].HostIDs {
			s.hostOf[id] = &s.machines[i]
		}
	}
	return s, nil
}

// interval is how often an integration kind reads; zero without the
// network manager.
func (a *app) interval(kind string) time.Duration {
	if a.d.Network == nil {
		return 0
	}
	return a.d.Network.Interval(kind)
}

// workloadCoverage is the coverage of the snapshot's workloads.
func (a *app) workloadCoverage(s *snapshot) coverage.Workloads {
	c := coverage.AssessWorkloads(s.workloads, s.ids, a.d.Settings.Get().PublicDomains, s.marked)
	if a.d.Package == nil {
		return c
	}
	// An app nothing is asked about is identified, but not checked: it
	// must not count towards "all clear".
	for _, wl := range s.workloads {
		id := s.ids[wl.ID]
		if !coverage.Assessable(id) {
			continue
		}
		if _, skip := coverage.NotAnApp(wl, id, s.marked); skip {
			continue
		}
		if app, ok := a.d.Catalog.Current().App(id.AppID); ok && a.d.Package.NoSource(app) {
			c.Assessable--
		}
	}
	return c
}

func (a *app) appName(id string) string {
	if app, ok := a.d.Catalog.Current().App(id); ok {
		return app.Name
	}
	if name, ok := distro.SystemName(id); ok {
		return name
	}
	return id
}

// findingRow is a finding prepared for tables.
type findingRow struct {
	ID, Priority, AppName, WorkloadName, Version, AdvisoryID, Summary, FixedIn, Exposure, State, MatchState, AppID string
	// PathClass and PathReason relate the finding to the attack paths.
	PathClass, PathReason string
	KEV                   bool
	CVSS                  float64
}

func (a *app) row(s *snapshot, f store.Finding) findingRow {
	var m match.Finding
	_ = json.Unmarshal(f.Detail, &m)
	return findingRow{
		ID: f.ID, Priority: f.Priority, AppID: f.AppID, AppName: a.appName(f.AppID), WorkloadName: s.byID[f.WorkloadID].Name,
		Version: m.Evidence.Version, AdvisoryID: f.AdvisoryID, Summary: m.Summary, FixedIn: f.FixedIn, Exposure: f.Exposure,
		State: f.State, MatchState: f.MatchState, KEV: m.KEV, CVSS: m.CVSS, PathClass: f.PathClass, PathReason: f.PathReason,
	}
}

func sortRows(rows []findingRow) {
	rank := map[string]int{"P1": 0, "P2": 1, "P3": 2, "": 3}
	sort.SliceStable(rows, func(i, j int) bool {
		if rank[rows[i].Priority] != rank[rows[j].Priority] {
			return rank[rows[i].Priority] < rank[rows[j].Priority]
		}
		if rows[i].CVSS != rows[j].CVSS {
			return rows[i].CVSS > rows[j].CVSS
		}
		return rows[i].AppName < rows[j].AppName
	})
}

type overviewData struct {
	Findings status.Findings
	State    string
	// UrgentApps is the number of app versions with a new P1 finding.
	UrgentApps int
	// Todo are the updates to do first: one per container or system with
	// new P1 or P2 findings; UrgentTodo counts those with new P1 ones.
	Todo       []todoGroup
	UrgentTodo int
	// Urgent lists app versions with new P1 or P2 findings; Quiet those
	// whose P1 or P2 findings are all acknowledged.
	Urgent, Quiet []findingGroup
	// LastInventory is the newest report of any source that reads
	// workloads.
	LastInventory time.Time
	LastRefresh   time.Time
	SourceErrors  int
	Coverage      coverage.Workloads
	Machines      systemCounts
	// Notices are blind spots: hosts not reporting, public routes Varde
	// cannot assess.
	Notices []store.Notice
	// Mode is where advisories come from: direct, feed or hybrid.
	Mode string
	// Updates are the things to do, the numbers the overview leads with.
	Updates updateCounts
	// Steps are the next setup steps, ranked by what they unlock.
	Steps []step
	// Guide leads through getting started; it carries the notification
	// and HTTPS state the overview shows instead of banners.
	Guide guide
	// SetupLeft counts the guide's steps that are not done; SetupHidden is
	// set when the user hid the setup reminder.
	SetupLeft   int
	SetupHidden bool
	// SystemChecked is the number of system packages checked against
	// their distributions' security data (ADR 0032).
	SystemChecked int
	// Restarts are the systems whose updates wait for a restart.
	Restarts []systemRow
	// Apps counts the apps by what they ask for; Sections are the cards
	// of the front page, grouped by it.
	Apps     appCounts
	Sections []appSection
	// Paths are the most dangerous attack paths, PathCount all of them;
	// Noise counts the open findings no path uses (ADR 0034).
	Paths     []paths.Path
	PathCount int
	Noise     int
}

// Empty reports that Varde knows nothing installed on any system yet, so
// it cannot say that anything is safe.
func (d overviewData) Empty() bool {
	return d.Machines.Read == 0 && d.Coverage.Total == 0 && d.Findings.Open().Total() == 0
}

// Unassessed reports that no app could be checked and nothing was found:
// "all clear" would claim more than Varde knows.
func (d overviewData) Unassessed() bool {
	return d.Coverage.Assessable == 0 && d.SystemChecked == 0 && d.Findings.Open().Total() == 0
}

// NotUrgent is the number of new P2 and P3 findings: open, but not urgent
// enough to notify at once.
func (d overviewData) NotUrgent() int { return d.Findings.New.P2 + d.Findings.New.P3 }

// Acknowledged is the number of acknowledged or snoozed findings.
func (d overviewData) Acknowledged() int { return d.Findings.Acknowledged.Total() }

// Unchecked is the number of app workloads Varde cannot check against
// advisories (not identified, or version unknown).
func (d overviewData) Unchecked() int { return d.Coverage.Total - d.Coverage.Assessable }

// noticeLink is the page that explains a notice and its next step.
func noticeLink(kind string) string {
	switch kind {
	case store.NoticeHostStale:
		return "/systems"
	case store.NoticeFeedStale, store.NoticeSourceStale:
		return "/settings/sources"
	case store.NoticePublicRoute:
		return "/systems/gaps#routes"
	case store.NoticeUplink:
		return "/settings#uplink"
	case store.NoticeIntegrationFailing, store.NoticeFirmware:
		return "/connections#integrations"
	}
	return "/systems/gaps"
}

func (a *app) overview(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	s, err := a.load(ctx, false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	d := overviewData{Findings: status.Count(s.findings), Mode: a.mode(), LastInventory: coverage.LastInventory(s.machines)}
	d.State = d.Findings.State()
	var open []store.Finding
	for _, f := range s.findings {
		if status.Active(f.State) {
			open = append(open, f)
		}
	}
	for _, g := range a.groupFindings(s, open) {
		if g.Priority != "P1" && g.Priority != "P2" {
			continue
		}
		if g.New == 0 {
			d.Quiet = append(d.Quiet, g)
			continue
		}
		if g.Priority == "P1" {
			d.UrgentApps++
		}
		d.Urgent = append(d.Urgent, g)
	}
	if len(d.Urgent) > 5 {
		d.Urgent = d.Urgent[:5]
	}
	todo := a.todoGroups(s, open)
	d.Updates = countUpdates(todo)
	for _, g := range todo {
		if g.NewPriority != "P1" && g.NewPriority != "P2" {
			continue
		}
		if g.NewPriority == "P1" {
			d.UrgentTodo++
		}
		d.Todo = append(d.Todo, g)
	}
	// The urgent ones first, also when an acknowledged finding ranks
	// another update higher.
	sort.SliceStable(d.Todo, func(i, j int) bool { return priorityRank[d.Todo[i].NewPriority] < priorityRank[d.Todo[j].NewPriority] })
	if len(d.Todo) > 5 {
		d.Todo = d.Todo[:5]
	}
	if len(d.Quiet) > 5 {
		d.Quiet = d.Quiet[:5]
	}
	states, err := a.d.Store.SourceStates(ctx)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	for _, st := range states {
		if st.LastSuccess.After(d.LastRefresh) {
			d.LastRefresh = st.LastSuccess
		}
		if st.LastError != "" {
			d.SourceErrors++
		}
	}
	d.Coverage = a.workloadCoverage(s)
	if d.Machines, err = a.countSystems(ctx, s); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	rows, err := a.systemRows(ctx, s)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	for _, r := range rows {
		if r.Reboot != "" {
			d.Restarts = append(d.Restarts, r)
		}
	}
	if d.Steps = a.setupSteps(s, rows); len(d.Steps) > 3 {
		d.Steps = d.Steps[:3]
	}
	if d.Notices, err = a.d.Store.ActiveNotices(ctx); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	if a.d.Settings.Get().DirectOSV {
		d.SystemChecked = len(s.system)
	}
	ps, err := a.d.Store.Paths(ctx)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	d.PathCount = len(ps)
	if len(ps) > 3 {
		ps = ps[:3]
	}
	d.Paths = ps
	for _, f := range s.findings {
		if active(f.State) && f.PathClass == string(paths.Noise) {
			d.Noise++
		}
	}
	if d.Guide, err = a.buildGuide(ctx, r, s); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	for _, st := range d.Guide.Steps {
		if !st.Done {
			d.SetupLeft++
		}
	}
	d.SetupHidden = a.setupHidden(ctx)
	// Notifications and HTTPS are steps of the guide here, not banners.
	cards := a.appCards(s)
	d.Apps, d.Sections = countApps(cards), appSections(cards)
	v := view{Title: "Apps", Nav: "overview", Tabs: tabs("systems", "/"), Data: d, OwnSecurityNote: true}
	a.page(w, r, cur, http.StatusOK, "overview", v)
}

type findingsFilter struct{ Priority, Match, State, App, Exposure, Workload, Path string }

type appOption struct{ ID, Name string }

func (a *app) findings(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	q := r.URL.Query()
	f := findingsFilter{q.Get("priority"), q.Get("match"), q.Get("state"), q.Get("app"), q.Get("exposure"), q.Get("workload"), q.Get("path")}
	// The findings are grouped by what fixes them on which system, by app or
	// package version, or listed one per advisory.
	mode := q.Get("view")
	if mode != "list" && mode != "package" {
		mode = ""
	}
	list := mode == "list"
	s, err := a.load(r.Context(), f.State == "resolved" || f.State == "all")
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	var selected []store.Finding
	seenApps := map[string]bool{}
	var apps []appOption
	for _, fd := range s.findings {
		if !seenApps[fd.AppID] {
			seenApps[fd.AppID] = true
			apps = append(apps, appOption{fd.AppID, a.appName(fd.AppID)})
		}
		switch f.State {
		case "":
			if !active(fd.State) {
				continue
			}
		case "all":
		default:
			if fd.State != f.State {
				continue
			}
		}
		if (f.Priority != "" && fd.Priority != f.Priority) || (f.Match != "" && fd.MatchState != f.Match) ||
			(f.App != "" && fd.AppID != f.App) || (f.Exposure != "" && fd.Exposure != f.Exposure) ||
			(f.Workload != "" && fd.WorkloadID != f.Workload) || !pathFilter(f.Path, fd.PathClass) {
			continue
		}
		selected = append(selected, fd)
	}
	var rows []findingRow
	var groups []findingGroup
	var todo []todoGroup
	switch mode {
	case "list":
		for _, fd := range selected {
			rows = append(rows, a.row(s, fd))
		}
		sortRows(rows)
	case "package":
		groups = a.groupFindings(s, selected)
	default:
		todo = a.todoGroups(s, selected)
		a.withReleases(r.Context(), s, todo)
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })
	filtered := f != (findingsFilter{})
	// The updates to do as the cards of the front page, each under what
	// it asks for.
	sections := appSections(a.updateCards(s, todo, selected))
	a.page(w, r, cur, http.StatusOK, "findings", view{Title: "Updates", Nav: "findings", Tabs: tabs("findings", "/findings"), Data: struct {
		Sections []appSection
		Findings []findingRow
		Groups   []findingGroup
		Todo     []todoGroup
		Count    int
		List     bool
		View     string
		Filter   findingsFilter
		Apps     []appOption
		Filtered bool
		Query    string
	}{sections, rows, groups, todo, len(selected), list, mode, f, apps, filtered, filterQuery(f)}})
}

// filterQuery keeps the filters when switching between the grouped and the
// list view.
func filterQuery(f findingsFilter) string {
	v := url.Values{}
	for k, val := range map[string]string{"priority": f.Priority, "match": f.Match, "state": f.State, "app": f.App, "exposure": f.Exposure, "workload": f.Workload, "path": f.Path} {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v.Encode()
}

func (a *app) finding(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	f, err := a.d.Store.GetFinding(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		a.renderError(w, r, cur, http.StatusNotFound, "Finding not found", "It may have been resolved and purged.")
		return
	}
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	var m match.Finding
	_ = json.Unmarshal(f.Detail, &m)
	wl, _ := a.d.Store.Workload(ctx, f.WorkloadID)
	host := ""
	if h, err := a.d.Store.Host(ctx, wl.HostID); err == nil {
		host = h.Name
	}
	details := ""
	recs, err := a.d.Store.Advisories(ctx, f.AppID)
	if err == nil {
		for _, rec := range recs {
			if rec.Vuln.ID == m.Evidence.RecordID {
				details = truncate(strings.TrimSpace(rec.Vuln.Details), 6000)
			}
		}
	}
	a.page(w, r, cur, http.StatusOK, "finding", view{Title: f.AdvisoryID, Nav: "findings", Data: struct {
		Finding                         store.Finding
		Match                           match.Finding
		AppName, WorkloadName, HostName string
		Details                         string
		Update                          *remedy.Suggestion
		RegistryTags                    bool
		Paths                           []paths.Path
		History                         []historyEntry
		// Image is set for a flaw in a package of the container's image.
		Image *imageFinding
		// AppHref is the page of the app the flaw belongs to; empty for
		// a package of a system, which has none.
		AppHref string
	}{f, m, a.appName(f.AppID), wl.Name, host, details, a.update(r.Context(), f, m, wl), a.d.Settings.Get().RegistryTags, a.findingPaths(r, f.ID),
		a.findingHistory(r, f.ID), a.imageFinding(ctx, m, wl), appHref(wl)}})
}

// imageFinding is what the page says about a flaw in a package of a
// container's image. The versions of such a finding are the package's, not
// the app's: the page names the container and its image first and says what
// Varde can and cannot know about a fixed image.
type imageFinding struct {
	// Ref is the image the container runs.
	Ref string
	// App and AppVersion name what runs in the container, when recognised.
	App, AppVersion string
	// Floating is set when the container runs a moving tag, Pinned when
	// it is created from a digest and so never changes by a pull.
	Floating, Pinned bool
	Compose          *remedy.Compose
	// Release says what the newest release of the app fixes.
	Release *releaseView
}

func (a *app) imageFinding(ctx context.Context, m match.Finding, wl inventory.Workload) *imageFinding {
	if !m.Image || wl.Container == nil {
		return nil
	}
	v := &imageFinding{Ref: wl.Container.ImageRef, Floating: remedy.Floating(wl.Container), Pinned: remedy.Pinned(wl.Container), Compose: remedy.ComposeOf(wl.Container)}
	if ids, err := a.d.Store.Identifications(ctx); err == nil {
		if id, ok := ids[wl.ID]; ok && id.AppID != "" {
			v.App, v.AppVersion = a.appName(id.AppID), id.Version
			v.Release = a.findingRelease(ctx, m, wl, id)
		}
	}
	return v
}

// findingRelease compares the container's active image findings with the
// newest release of its app and tells what it does for finding m.
func (a *app) findingRelease(ctx context.Context, m match.Finding, wl inventory.Workload, id identify.Result) *releaseView {
	fs, err := a.d.Store.Findings(ctx, store.FindingFilter{WorkloadID: wl.ID})
	if err != nil {
		return nil
	}
	in := releaseInput{wl: wl, id: id, findings: imageFindings(fs)}
	if h, err := a.d.Store.Host(ctx, wl.HostID); err == nil {
		in.host = &h
	}
	v := a.containerReleases(ctx, []releaseInput{in})[0]
	if v == nil || !v.Fixes {
		return v
	}
	this := remedy.Flaw{AdvisoryID: m.AdvisoryID, Package: m.Evidence.Package}
	v.This, v.ThisOpen, v.ThisUnknown = slices.Contains(v.Fixed, this), slices.Contains(v.Open, this), slices.Contains(v.Unknown, this)
	return v
}

// update is the concrete update for an affected container finding: the
// version that fixes this version's advisories together, else this one.
func (a *app) update(ctx context.Context, f store.Finding, m match.Finding, wl inventory.Workload) *remedy.Suggestion {
	if f.MatchState != string(match.Affected) || wl.Container == nil {
		return nil
	}
	// The version the page names is the one the image line carries
	// (match.Step). A finding stored before the step existed has only
	// its own fixed version.
	target := f.FixedIn
	switch {
	case m.Step != nil:
		target = m.Step.Version
	case m.Target != nil && m.Target.Version != "":
		// Stored before the step: the target, or the running line's when
		// the target leaves the line. The next analysis replaces it.
		target = m.Target.Version
		if m.Target.NewLine && m.Target.Line != nil && m.Target.Line.Version != "" {
			target = m.Target.Line.Version
		}
	}
	app, ok := a.d.Catalog.Current().App(f.AppID)
	if !ok || target == "" {
		return nil
	}
	var tags []string
	if ref, err := imageref.Parse(wl.Container.ImageRef); err == nil {
		if known, err := a.d.Store.RepositoryTags(ctx); err == nil {
			tags = known[ref.Repository].Tags
		}
	}
	s, ok := remedy.Suggest(app, wl.Container, target, tags)
	if !ok {
		return nil
	}
	return &s
}

type workloadRow struct {
	ID, Name, Image, Confidence, AppID, AppName, Version, VersionSource, Note, Exposure string
	Open                                                                                int
	// Unfixed counts the open issues in the image's packages that no
	// newer image fixes yet (ADR 0033).
	Unfixed int
	Manual  bool
	// NotApp says why the workload is not counted as an app (a helper or
	// marked by the user); empty for apps.
	NotApp string
	// Trust of the version; Doubt explains a version that is not
	// confirmed.
	Trust, Doubt string
	// Stack is the Compose project of a container.
	Stack string
	// Derived marks an app Varde recognised automatically and that is not
	// confirmed: its findings do not alert until the user confirms it.
	Derived bool
	// Basis says what an automatic recognition rests on (source label,
	// GitHub's registry, app store lists); empty for reviewed apps.
	Basis string
	// Checked says what "no open finding" means for this workload: only
	// CheckedFull stands for "compared with complete advisory data and
	// nothing found". CheckNote says it in words for the others.
	Checked   string
	CheckNote string
	// Newer is the newest release of the container's image above the
	// version it runs, from the known release tags; empty when it runs
	// the newest or nothing is known.
	Newer string
	// Pulled is set when a newer image for the container's tag is pulled
	// but the container still runs the old one; Changed lists version
	// evidence files changed inside the container.
	Pulled  bool
	Changed []string
	// Distro is the security data ecosystem of a distribution package
	// ("Debian:12"), PackageVersion its installed version.
	Distro, PackageVersion string
	// EOL describes a release line past its end of life.
	EOL string
}

// What a workload without open findings was checked against.
const (
	CheckedFull    = "full"    // compared, the project publishes complete advisories
	CheckedLimited = "limited" // compared, but the project's advisory data is incomplete
	CheckedNot     = "not"     // nothing was compared
)

// checked says how far a workload was compared with advisories. "None" in
// a list must not look the same for an app with complete data, one whose
// project publishes little, and one Varde could not compare at all.
func (a *app) checked(wl inventory.Workload, id identify.Result, row workloadRow) (kind, note string) {
	app, known := a.d.Catalog.Current().App(id.AppID)
	switch {
	case row.NotApp != "":
		return CheckedLimited, "a helper without advisories of its own; the packages of its image are checked"
	case !known || id.AppID == "":
		return CheckedNot, "not recognised, so not compared with any advisory"
	case a.d.Package != nil && a.d.Package.NoSource(app):
		return CheckedNot, "no advisory source covers this app"
	case row.Distro != "":
		return CheckedFull, ""
	case id.Version == "":
		return CheckedNot, "the version is unknown, so nothing can be compared"
	case row.Derived:
		return CheckedLimited, "recognised automatically and not confirmed: findings do not alert"
	case id.Doubt() != "":
		return CheckedLimited, "the version is not confirmed: findings do not alert"
	case app.Advisories.Coverage == catalog.CoverageLimited:
		return CheckedLimited, "the project publishes no advisories a program can read; Varde relies on CVE data, which lags"
	case app.Advisories.Coverage == catalog.CoveragePartial:
		return CheckedLimited, "the project publishes only part of its flaws in a form a program can compare"
	}
	return CheckedFull, ""
}

type hostGroup struct {
	Machine   coverage.Machine
	Workloads []workloadRow
}

func (a *app) inventory(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	s, err := a.load(r.Context(), false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	open := map[string]int{}
	for _, f := range s.findings {
		if status.Active(f.State) && f.MatchState == string(match.Affected) {
			open[f.WorkloadID]++
		}
	}
	groups := map[string]*hostGroup{}
	for _, m := range s.machines {
		groups[m.ID] = &hostGroup{Machine: m}
	}
	eol, err := a.d.Store.EOL(r.Context())
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	for _, wl := range s.workloads {
		m := s.hostOf[wl.HostID]
		if m == nil {
			continue
		}
		g := groups[m.ID]
		row := a.workloadRow(s, wl, open, eol)
		g.Workloads = append(g.Workloads, row)
	}
	// Hosts without workloads (Proxmox guests Varde reads nothing on yet)
	// are counted, not shown as empty blocks; the hosts page lists them.
	var hosts []hostGroup
	empty := 0
	for _, m := range s.machines {
		g := groups[m.ID]
		switch {
		case len(g.Workloads) > 0:
			hosts = append(hosts, *g)
		case m.IsHost():
			empty++
		}
	}
	var apps []appOption
	for _, ap := range a.d.Catalog.Current().Apps() {
		apps = append(apps, appOption{ap.ID, ap.Name})
	}
	sort.Slice(apps, func(i, j int) bool { return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name) })
	a.page(w, r, cur, http.StatusOK, "inventory", view{Title: "Apps and containers", Nav: "systems", Tabs: tabs("systems", "/systems/apps"), Data: struct {
		Hosts         []hostGroup
		Apps          []appOption
		WithoutReads  int
		LocalDocker   bool
		AnyIntegrated bool
	}{hosts, apps, empty, a.d.LocalDocker, len(s.integrations) > 0}})
}

type gap struct {
	Workload, Image, AppID, AppName, Note, Host, SuggestURL string
	// Repository is the normalised image repository, used by the
	// "not an app" mark; Marked is set when the user made that mark.
	Repository string
	Marked     bool
	// On is the machine the workload runs on, for lists where the same
	// container name appears on several machines.
	On string
	// Pending is set for an unknown version Varde is still finding out by
	// itself (the registry has not been asked yet); RegistryOff when it
	// could, but asking the registry is switched off.
	Pending, RegistryOff bool
}

type coverageView struct {
	Summary        coverage.Workloads
	PublicRoutes   []gap
	Unidentified   []gap
	VersionUnknown []gap
	Weak           []gap
	// NotApps are helper containers and containers marked as not an app;
	// they are not counted in the summary.
	NotApps []gap
	Limited []struct{ Name, Coverage string }
	// NoSource are identified apps nothing is asked about: the data
	// package does not cover them and direct queries are off.
	NoSource []string
	// Machines counts the hosts whose workloads Varde reads.
	Machines systemCounts
}

// Why says why a version is unknown, without the advice the identification
// appends: the page gives its own next step, which depends on what Varde is
// still finding out.
func (g gap) Why() string {
	why := strings.TrimPrefix(g.Note, "version unknown: ")
	why = strings.TrimSuffix(why, "; set label varde.version to pin it")
	return why
}

func (a *app) toGap(g coverage.Gap) gap {
	image := ""
	if g.Workload.Container != nil {
		image = g.Workload.Container.ImageRef
	}
	return gap{Workload: g.Workload.Name, Image: image, AppID: g.ID.AppID, AppName: a.appName(g.ID.AppID), Note: g.ID.Note,
		Repository: coverage.Repository(g.Workload), Host: g.Route}
}

// coverageData decorates the workload coverage for the page: names, the
// catalog suggestion link, and one row per image for containers that are
// not in the catalog.
func (a *app) coverageData(s *snapshot) coverageView {
	c := coverageView{Summary: a.workloadCoverage(s)}
	for _, g := range c.Summary.PublicRoutes {
		pg := a.toGap(g)
		pg.SuggestURL = suggestURL(pg.Image)
		c.PublicRoutes = append(c.PublicRoutes, pg)
	}
	unidentified := map[string]int{}
	for _, g := range c.Summary.NotInCatalog {
		ug := a.toGap(g)
		// One row per image: several containers of the same image close
		// with the same step.
		if i, ok := unidentified[ug.Repository]; ok && ug.Repository != "" {
			c.Unidentified[i].Workload += ", " + ug.Workload
			continue
		}
		ug.SuggestURL = suggestURL(ug.Image)
		unidentified[ug.Repository] = len(c.Unidentified)
		c.Unidentified = append(c.Unidentified, ug)
	}
	registry := a.d.Settings.Get().RegistryTags
	asked, _ := a.d.Store.ImageTags(context.Background())
	for _, g := range c.Summary.VersionUnknown {
		vg := a.toGap(g)
		if remedy.Floating(g.Workload.Container) {
			// A moving tag: the registry tells which version the running
			// image is. The answer is kept per image digest; a container
			// whose digest is unknown cannot be asked about at all.
			digest := registrydigest(g.Workload.Container, vg.Repository)
			_, done := asked[vg.Repository+"@"+digest]
			vg.RegistryOff = !registry && digest != ""
			vg.Pending = registry && digest != "" && !done
		}
		c.VersionUnknown = append(c.VersionUnknown, vg)
	}
	for _, g := range c.Summary.Weak {
		c.Weak = append(c.Weak, a.toGap(g))
	}
	for _, g := range c.Summary.NotApps {
		ng := a.toGap(g)
		ng.Note, ng.Marked = g.NotAppKind, g.NotAppKind == coverage.KindUser
		if m := s.hostOf[g.Workload.HostID]; m != nil {
			ng.On = m.Name
		}
		c.NotApps = append(c.NotApps, ng)
	}
	limited := map[string]bool{}
	for _, wl := range s.workloads {
		id := s.ids[wl.ID]
		if !id.Confidence.Notifiable() || limited[id.AppID] {
			continue
		}
		if _, skip := coverage.NotAnApp(wl, id, s.marked); skip {
			continue
		}
		app, ok := a.d.Catalog.Current().App(id.AppID)
		if !ok {
			continue
		}
		limited[app.ID] = true
		if a.d.Package != nil && a.d.Package.NoSource(app) {
			// Not "limited": nothing at all tells Varde about this app.
			c.NoSource = append(c.NoSource, app.Name)
			continue
		}
		if app.Advisories.Coverage != catalog.CoverageFull {
			c.Limited = append(c.Limited, struct{ Name, Coverage string }{app.Name, app.Advisories.Coverage})
		}
	}
	return c
}

// registrydigest is the registry digest of the image a container runs, for
// the given repository; empty when the runtime did not report one (an image
// built locally, for example).
func registrydigest(c *inventory.Container, repository string) string {
	if c == nil {
		return ""
	}
	return registry.RepoDigest(c, repository)
}

// suggestURL opens a prefilled catalog issue. Only the image repository is
// included: no tag, no host names, nothing else about the installation.
func suggestURL(image string) string {
	repo := image
	if ref, err := imageref.Parse(image); err == nil {
		repo = ref.Repository
	}
	q := url.Values{"template": {"catalog.yml"}, "title": {"Catalog entry: " + repo}, "images": {repo}}
	return buildinfo.RepoURL + "/issues/new?" + q.Encode()
}

func (a *app) coverage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	s, err := a.load(r.Context(), false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	c := a.coverageData(s)
	if c.Machines, err = a.countSystems(r.Context(), s); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.page(w, r, cur, http.StatusOK, "coverage", view{Title: "Gaps", Nav: "systems", Tabs: tabs("systems", "/systems/gaps"), Data: c})
}

// appSources says, for one app Varde recognised, what it is compared with
// and how much is known: the answer to "is this app checked at all".
type appSources struct {
	Name string
	// Known counts the advisories stored for the app, From names where
	// they came from (data package, GitHub, NVD, osv.dev).
	Known int
	From  []string
	// Asked names what the catalog says to ask about the app.
	Asked []string
	// NoSource is set when nothing is asked about the app at all.
	NoSource bool
	// Off names the sources the catalog gives for the app that are
	// switched off; Active is set when at least one source is asked. An
	// app with sources but none active is not checked, whatever the
	// count says.
	Off    []string
	Active bool
}

// sourceNames are the stored source names in words.
var sourceNames = map[string]string{"feed": "data package", "github": "GitHub", "nvd": "NVD", "osv": "osv.dev", "local": "local catalog"}

func (a *app) appSources(ctx context.Context) ([]appSources, int, int, error) {
	s, err := a.load(ctx, false)
	if err != nil {
		return nil, 0, 0, err
	}
	counts, err := a.d.Store.AdvisoryCounts(ctx)
	if err != nil {
		return nil, 0, 0, err
	}
	eff, mode := a.d.Settings.Get(), a.mode()
	total, apps := 0, 0
	for id, by := range counts {
		if _, system := distro.SystemName(id); system {
			continue
		}
		apps++
		for _, n := range by {
			total += n
		}
	}
	seen := map[string]bool{}
	var out []appSources
	for _, wl := range s.workloads {
		id := s.ids[wl.ID]
		if id.AppID == "" || seen[id.AppID] {
			continue
		}
		app, ok := a.d.Catalog.Current().App(id.AppID)
		if !ok {
			continue
		}
		seen[id.AppID] = true
		row := appSources{Name: app.Name, NoSource: a.d.Package != nil && a.d.Package.NoSource(app)}
		for src, n := range counts[app.ID] {
			row.Known += n
			name := sourceNames[src]
			if name == "" {
				name = src
			}
			row.From = append(row.From, name)
		}
		sort.Strings(row.From)
		// A full feed carries what the optional sources would bring; in
		// direct and package mode osv.dev and the NVD are asked only when
		// switched on.
		full := mode != "direct" && mode != "package"
		for _, repo := range app.Advisories.GitHubRepos {
			row.Asked = append(row.Asked, "advisories of github.com/"+repo)
			row.Active = row.Active || !row.NoSource
		}
		for _, p := range app.Advisories.OSVPackages {
			if full || eff.DirectOSV {
				row.Asked, row.Active = append(row.Asked, "osv.dev package "+p.Name), true
			} else {
				row.Asked, row.Off = append(row.Asked, "osv.dev package "+p.Name+" (switched off)"), append(row.Off, "osv.dev")
			}
		}
		for _, c := range app.Advisories.CPE {
			name := "NVD product " + strings.TrimPrefix(c, "cpe:2.3:a:")
			if full || eff.DirectNVD {
				row.Asked, row.Active = append(row.Asked, name), true
			} else {
				row.Asked, row.Off = append(row.Asked, name+" (switched off)"), append(row.Off, "the NVD")
			}
		}
		row.Off = slices.Compact(row.Off)
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, total, apps, nil
}

func (a *app) sources(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	states, err := a.d.Store.SourceStates(r.Context())
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	apps, total, known, err := a.appSources(r.Context())
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	eff := a.d.Settings.Get()
	a.page(w, r, cur, http.StatusOK, "sources", view{Title: "Advisory data", Nav: "settings", Tabs: tabs("settings", "/settings/sources"), Data: struct {
		States      []store.SourceState
		OSV, NVD    bool
		GitHubToken bool
		Mode        string
		Direct      bool
		// Apps says per recognised app what is known; Total and KnownApps
		// count every advisory Varde holds and the apps they are about.
		Apps             []appSources
		Total, KnownApps int
	}{states, eff.DirectOSV, eff.DirectNVD, a.d.GitHubToken, a.mode(), eff.DirectQueries, apps, total, known}})
}

func (a *app) fail(w http.ResponseWriter, r *http.Request, cur *auth.Current, err error) {
	a.d.Log.Error("page failed", "path", r.URL.Path, "err", err)
	a.renderError(w, r, cur, http.StatusInternalServerError, "Something went wrong", "The error was logged. Try again in a moment.")
}

// eolNote says when the release line of an identified version reached its
// end of life; empty while it is supported or unknown.
func eolNote(cat *catalog.Catalog, eol map[string][]store.EOLRelease, id identify.Result) string {
	app, ok := cat.App(id.AppID)
	if !ok || app.EOL == "" || id.Version == "" {
		return ""
	}
	line, ok := sources.EOLLine(eol[app.EOL], id.Version)
	if !ok || !line.IsEOL {
		return ""
	}
	note := "Release line " + line.Name + " gets no more fixes"
	if line.EOLFrom != "" {
		note += " since " + line.EOLFrom
	}
	if latest := latestSupported(eol[app.EOL]); latest != "" {
		note += "; the newest supported release is " + latest
	}
	return note + "."
}

// latestSupported is the newest release of the first supported line
// (endoflife.date lists the newest line first).
func latestSupported(rel []store.EOLRelease) string {
	for _, r := range rel {
		if !r.IsEOL && r.Latest != "" {
			return r.Latest
		}
	}
	return ""
}

// derivationBasis words what an automatic recognition rests on.
func derivationBasis(d *catalog.Derivation) string {
	if d == nil {
		return "Only by a source label this image may have inherited from its base image"
	}
	switch d.Basis {
	case catalog.BasisIndex:
		text := "Stated by the project itself: " + identify.EvidenceWords(d.Evidence)
		if len(d.Lists) > 0 {
			text += "; also in app store lists (" + strings.Join(d.Lists, ", ") + ")"
		}
		return text
	case catalog.BasisLists:
		switch {
		case len(d.Lists) == 1 && d.Confirmed:
			return "Found in one app store list (" + d.Lists[0] + "), which the image's own source or registry path confirms"
		case len(d.Lists) == 1:
			return "Found in one app store list (" + d.Lists[0] + ")"
		}
		return "Found in app store lists (" + strings.Join(d.Lists, ", ") + ") that agree"
	case catalog.BasisGHCR:
		return "Guessed from its path on GitHub's registry"
	}
	return "From the image's source label"
}

// workloadRow is one workload as the inventory and the system pages show it.
func (a *app) workloadRow(s *snapshot, wl inventory.Workload, open map[string]int, eol map[string][]store.EOLRelease) workloadRow {
	id := s.ids[wl.ID]
	row := workloadRow{
		ID: wl.ID, Name: wl.Name, Confidence: string(id.Confidence), AppID: id.AppID, AppName: a.appName(id.AppID),
		Version: id.Version, VersionSource: id.VersionSource, Note: id.Note,
		Exposure: string(s.exposure.Detect(wl).Exposure), Open: open[wl.ID], Manual: wl.Kind == inventory.KindManual,
		Trust: string(id.Trust), Doubt: id.Doubt(), Derived: id.Derived, Unfixed: id.Unfixed,
	}
	if app, ok := a.d.Catalog.Current().App(id.AppID); ok && (app.Origin == catalog.OriginDerived || app.Origin == catalog.OriginGenerated) {
		// The stored identification does not carry this; the catalog does.
		var d *catalog.Derivation
		repo := ""
		if wl.Container != nil {
			if ref, err := imageref.Parse(wl.Container.ImageRef); err == nil {
				repo = ref.Repository
				d = app.DerivationFor(repo)
			}
		}
		// A manual entry names the app itself: nothing to confirm. A
		// generated entry is confirmed per image only where it stands in
		// for its derived entry (identify.ReadsAsDerived).
		if wl.Container != nil && (app.Origin == catalog.OriginDerived || identify.ReadsAsDerived(app, repo)) {
			row.Basis = derivationBasis(d)
			confirmedByUser := strings.HasPrefix(id.Rule, "label "+identify.LabelApp)
			row.Derived = !confirmedByUser && (d == nil || !d.Confirmed)
		}
	}
	if kind, skip := coverage.NotAnApp(wl, id, s.marked); skip {
		row.NotApp = kind
	}
	row.EOL = eolNote(a.d.Catalog.Current(), eol, id)
	row.Checked, row.CheckNote = a.checked(wl, id, row)
	switch {
	case wl.Container != nil:
		row.Image, row.Stack = wl.Container.ImageRef, wl.Container.ComposeProject
		if app, ok := a.d.Catalog.Current().App(id.AppID); ok && id.Doubt() == "" {
			if ref, err := imageref.Parse(wl.Container.ImageRef); err == nil {
				row.Newer = remedy.Newer(app, ref.Repository, id.Version, s.tags[ref.Repository].Tags)
			}
		}
		row.Pulled, row.Changed = wl.Container.PulledImageID != "", wl.Container.ChangedFiles
	case wl.Manual != nil:
		row.Image = "manual entry"
	case wl.Package != nil:
		row.Image = wl.Package.Manager + " package " + wl.Package.Name + " " + wl.Package.Version
		if _, m, ok := a.d.Catalog.Current().ByPackage(wl.Package.Manager, wl.Package.Name); ok {
			if dp := identify.DistroPackage(m, *wl.Package); dp != nil {
				row.Distro, row.PackageVersion = dp.Ecosystem, dp.Version
			}
		}
	case wl.Service != nil:
		row.Image = "systemd unit " + wl.Service.Unit
	case wl.Endpoint != nil:
		row.Image = wl.Endpoint.URL
	}
	return row
}
