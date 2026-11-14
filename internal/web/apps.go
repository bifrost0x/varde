// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/version"
)

// The front of Varde is a list of what runs, not of advisories: one card
// per app (a container, an installed app, the packages of a system) that
// says in plain words how it stands and names the one thing to do. The
// findings, attack paths and evidence behind a card are its details.

// App states, most pressing first. They are what a person does, in the
// words the pages use; the priorities P1 to P3 stay the names of the
// policy and of the notifications.
const (
	appNow     = "now"     // a confirmed P1 finding: update now
	appSoon    = "soon"    // P2: update soon
	appLater   = "later"   // P3: with the next regular update
	appCheck   = "check"   // only findings Varde cannot confirm
	appOK      = "ok"      // compared with complete data, nothing found
	appKnown   = "known"   // compared, but the advisory data is incomplete
	appUnknown = "unknown" // nothing could be compared
)

// appStateRank orders the states for the list.
var appStateRank = map[string]int{appNow: 0, appSoon: 1, appLater: 2, appCheck: 3, appUnknown: 4, appKnown: 5, appOK: 6}

// appCard is one app on the front page and the head of its own page.
type appCard struct {
	// Key is the workload ID, or "h:" and the host ID for the packages
	// of a system; Href is the card's own page.
	Key, Href string
	// Name is the app (or the system), Sub where it runs.
	Name, Sub string
	Version   string
	Image     string
	State     string
	// Label is the state in two words, Why the reason in one line.
	Label, Why string
	// Action is the one thing to do; Fixes says what it brings.
	Action, Fixes string
	// Rest names what the action leaves open, when it leaves something.
	Rest string
	// Line is the image line of a Compose file with the new tag, Command
	// what to run afterwards; Verified is set when the registry lists the
	// tag.
	Line, Command string
	Verified      bool
	// Compose locates the service, when the container belongs to one.
	Compose *remedy.Compose
	// Count is the number of open findings, Urgent those that make the
	// update pressing.
	Count, Urgent int
	Exposure      string
	// Newer is a newer release than the one running, when one is known.
	Newer string
	// Note says what "nothing found" rests on, when that needs saying.
	Note string
}

// appLabels are the states in the words of the pages.
var appLabels = map[string]string{
	appNow: "Update now", appSoon: "Update soon", appLater: "With the next update", appCheck: "Check yourself",
	appOK: "Nothing found", appKnown: "Nothing known", appUnknown: "Not checked",
}

// stateOfPriority maps a policy priority to the app state it asks for.
func stateOfPriority(p string) string {
	switch p {
	case "P1":
		return appNow
	case "P2":
		return appSoon
	case "P3":
		return appLater
	}
	return appCheck
}

// appCards builds one card per app: those with open findings from their
// update (todoGroups), the others from what they were checked against.
func (a *app) appCards(s *snapshot) []appCard {
	var open []store.Finding
	for _, f := range s.findings {
		if status.Active(f.State) {
			open = append(open, f)
		}
	}
	hostNames := map[string]string{}
	for _, h := range s.hosts {
		hostNames[h.ID] = h.Name
	}
	byWorkload := map[string][]store.Finding{}
	for _, f := range open {
		byWorkload[f.WorkloadID] = append(byWorkload[f.WorkloadID], f)
	}
	var out []appCard
	seen := map[string]bool{}
	for _, g := range a.todoGroups(s, open) {
		seen[g.Key] = true
		c := appCard{Key: g.Key, Name: g.Name, Count: g.Count, State: stateOfPriority(g.Priority)}
		if id, ok := strings.CutPrefix(g.Key, "w:"); ok {
			wl := s.byID[id]
			c.Key, c.Href = id, "/apps/"+id
			a.describe(&c, s, wl, hostNames)
			// The exposure the findings were prioritised with, so the
			// card gives the reason the priority has.
			for _, f := range byWorkload[id] {
				if f.Exposure == "public" || (f.Exposure == "lan" && c.Exposure != "public") {
					c.Exposure = f.Exposure
				}
			}
			a.plan(&c, s, wl, byWorkload[id], g)
		} else {
			// The packages of a system: its page lists them.
			host := strings.TrimPrefix(g.Key, "h:")
			c.Href, c.Sub = "/findings?host="+host, "packages of the system"
			if m := s.hostOf[host]; m != nil {
				c.Href = "/systems/" + m.ID + "#packages"
			}
			c.Action, c.Command = g.Action, g.Command
			c.Fixes = plural(g.Count, "flaw") + " in installed packages"
		}
		c.Label = appLabels[c.State]
		c.Why = why(c, g)
		out = append(out, c)
	}
	for _, wl := range s.workloads {
		if seen["w:"+wl.ID] || identify.IsSystem(wl) {
			continue
		}
		id := s.ids[wl.ID]
		c := appCard{Key: wl.ID, Href: "/apps/" + wl.ID}
		a.describe(&c, s, wl, hostNames)
		row := workloadRow{Derived: id.Derived}
		if kind, skip := coverage.NotAnApp(wl, id, s.marked); skip {
			row.NotApp = kind
		}
		switch kind, note := a.checked(wl, id, row); kind {
		case CheckedFull:
			c.State = appOK
		case CheckedLimited:
			c.State, c.Note = appKnown, note
		default:
			c.State, c.Note = appUnknown, note
		}
		c.Label = appLabels[c.State]
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if appStateRank[x.State] != appStateRank[y.State] {
			return appStateRank[x.State] < appStateRank[y.State]
		}
		if x.Urgent != y.Urgent {
			return x.Urgent > y.Urgent
		}
		return strings.ToLower(x.Name) < strings.ToLower(y.Name)
	})
	return out
}

// describe fills what a card says about the workload itself.
func (a *app) describe(c *appCard, s *snapshot, wl inventory.Workload, hostNames map[string]string) {
	id := s.ids[wl.ID]
	c.Name = a.appName(id.AppID)
	if id.AppID == "" || c.Name == "" {
		c.Name = wl.Name
	}
	c.Version = id.Version
	c.Exposure = string(s.exposure.Detect(wl).Exposure)
	host := hostNames[wl.HostID]
	switch {
	case wl.Container != nil:
		c.Image = wl.Container.ImageRef
		c.Sub = "container " + wl.Name
		if c.Name == wl.Name {
			c.Sub = "container"
		}
		if app, ok := a.d.Catalog.Current().App(id.AppID); ok && id.Doubt() == "" {
			if ref, err := imageref.Parse(wl.Container.ImageRef); err == nil {
				c.Newer = remedy.Newer(app, ref.Repository, id.Version, s.tags[ref.Repository].Tags)
			}
		}
	case wl.Manual != nil:
		c.Sub = "entered by hand"
	default:
		c.Sub = "installed"
	}
	if host != "" {
		c.Sub += " on " + host
	}
}

// plan chooses the one update of a container or app: the version that
// fixes every finding of the card's highest priority, and says how many
// of all its findings that version fixes.
func (a *app) plan(c *appCard, s *snapshot, wl inventory.Workload, fs []store.Finding, g todoGroup) {
	// The app as the findings name it; the identification may be gone
	// while its findings are still open. Versions of an app the catalog
	// no longer knows compare as plain numbers.
	appID := s.ids[wl.ID].AppID
	for _, f := range fs {
		if appID == "" {
			appID = f.AppID
		}
	}
	app, known := a.d.Catalog.Current().App(appID)
	scheme := version.SemVer
	if known {
		scheme = app.Version.Scheme
	}
	var target string
	type fix struct {
		fixedIn string
		top     bool
	}
	var fixes []fix
	open, noFix, image := 0, 0, 0
	var all *match.Target // the update that fixes the most, on any line
	for _, f := range fs {
		if f.MatchState != string(match.Affected) {
			continue
		}
		var m match.Finding
		if err := json.Unmarshal(f.Detail, &m); err != nil {
			continue
		}
		open++
		if m.Target != nil && m.Target.Version != "" {
			all = m.Target
		}
		top := f.Priority == g.Priority
		if top {
			c.Urgent++
		}
		switch {
		case m.Image:
			image++ // a package inside the image: a newer image brings it
		case f.FixedIn == "":
			noFix++
		default:
			// The step of the analysis; a finding stored before it
			// existed has its own fixed version.
			step := f.FixedIn
			if m.Step != nil {
				step = m.Step.Version
			}
			fixes = append(fixes, fix{f.FixedIn, top})
			if top && (target == "" || !match.AtLeast(scheme, target, step)) {
				target = step
			}
		}
	}
	if target == "" {
		// Nothing of the top priority has a fix: the update that fixes
		// the most of the rest.
		for _, f := range fixes {
			if target == "" || !match.AtLeast(scheme, target, f.fixedIn) {
				target = f.fixedIn
			}
		}
	}
	switch {
	case target != "":
		fixed := 0
		for _, f := range fixes {
			if match.AtLeast(scheme, target, f.fixedIn) {
				fixed++
			}
		}
		c.Action = "Update to " + target
		c.Fixes = "fixes " + strconv.Itoa(fixed) + " of " + plural(open, "flaw")
		if fixed == open {
			c.Fixes = "fixes " + allOf(open)
		}
		if rest := open - fixed - image; rest > 0 {
			c.Rest = plural(rest, "flaw") + " need a newer version or have no fix yet"
			if all != nil && all.Version != target && match.AtLeast(scheme, all.Version, target) && all.Fixes > fixed {
				c.Rest = strconv.Itoa(all.Fixes-fixed) + " more are fixed by " + all.Version
				if all.NewLine {
					c.Rest += ", a new major version"
				}
			}
		}
		if wl.Container != nil && known {
			var tags []string
			if ref, err := imageref.Parse(wl.Container.ImageRef); err == nil {
				tags = s.tags[ref.Repository].Tags
			}
			if sg, ok := remedy.Suggest(app, wl.Container, target, tags); ok && !sg.Floating {
				c.Line, c.Verified, c.Compose = "image: "+sg.Image, sg.Verified, sg.Compose
				if sg.Compose != nil {
					c.Command = sg.Compose.Pull()
				}
			} else if ok && sg.Floating {
				c.Action = "Pull the image again and recreate the container"
				c.Compose = sg.Compose
				if sg.Compose != nil {
					c.Command = sg.Compose.Pull()
				}
			}
		}
	case image > 0 && wl.Container != nil:
		c.Action = "Pull a newer image and recreate the container"
		c.Fixes = plural(image, "flaw") + " in packages inside the image"
		c.Compose = remedy.ComposeOf(wl.Container)
		if c.Compose != nil {
			c.Command = c.Compose.Pull()
		}
	case open > 0:
		c.Action = "No fixed version is published yet"
		c.Fixes = "limit who can reach it until one is"
	default:
		c.Action = "Look at the " + plural(g.Count, "finding") + " Varde cannot confirm"
	}
}

// allOf words "all N flaws" for one and for several.
func allOf(n int) string {
	if n == 1 {
		return "the flaw"
	}
	return "all " + strconv.Itoa(n) + " flaws"
}

// why says in one line what makes a card pressing.
func why(c appCard, g todoGroup) string {
	var parts []string
	if g.KEV {
		parts = append(parts, "a flaw is known to be exploited")
	}
	switch {
	case c.Exposure == "public":
		parts = append(parts, "reachable from the internet")
	case c.Exposure == "lan":
		parts = append(parts, "reachable in your network")
	}
	if len(parts) == 0 {
		switch c.State {
		case appSoon:
			return "serious flaws, but not directly reachable"
		case appLater:
			return "minor flaws"
		case appCheck:
			return "Varde cannot tell whether these apply to the version running"
		}
	}
	return strings.Join(parts, ", ")
}

// appCounts are the numbers the front page leads with.
type appCounts struct {
	Now, Soon, Later, Check, Fine, Unknown, Total int
}

func countApps(cards []appCard) appCounts {
	var n appCounts
	for _, c := range cards {
		n.Total++
		switch c.State {
		case appNow:
			n.Now++
		case appSoon:
			n.Soon++
		case appLater:
			n.Later++
		case appCheck:
			n.Check++
		case appUnknown:
			n.Unknown++
		default:
			n.Fine++
		}
	}
	return n
}

// appSection is one group of cards on the front page.
type appSection struct {
	State, Title, Text string
	Cards              []appCard
	// Compact lists the cards as rows without an action.
	Compact bool
}

// appSections groups the cards for the front page: what needs doing, each
// under what it asks for, then the rest as a quiet list.
func appSections(cards []appCard) []appSection {
	by := map[string][]appCard{}
	for _, c := range cards {
		by[c.State] = append(by[c.State], c)
	}
	var out []appSection
	add := func(state, title, text string, compact bool, more ...string) {
		cs := by[state]
		for _, m := range more {
			cs = append(cs, by[m]...)
		}
		if len(cs) > 0 {
			out = append(out, appSection{State: state, Title: title, Text: text, Cards: cs, Compact: compact})
		}
	}
	add(appNow, "Update now", "Reachable or already being exploited. These are the ones Varde notifies about at once.", false)
	add(appSoon, "Update soon", "Serious, but not directly reachable. They are in the daily digest.", false)
	add(appLater, "With the next update", "Nothing pressing. They are in the weekly digest.", false)
	add(appCheck, "Check yourself", "Varde found advisories for these apps but cannot tell whether they apply to the version running.", false)
	add(appUnknown, "Not checked", "Varde cannot say anything about these. Each says why.", true)
	add(appOK, "Nothing to do", "", true, appKnown)
	return out
}

// appPage is the page of one app: what to do, why, and what is behind it.
func (a *app) appPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	s, err := a.load(r.Context(), false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	id := r.PathValue("id")
	wl, ok := s.byID[id]
	if !ok || identify.IsSystem(wl) {
		a.renderError(w, r, cur, http.StatusNotFound, "App not found", "It may have been removed.")
		return
	}
	var card *appCard
	cards := a.appCards(s)
	for i := range cards {
		if cards[i].Key == id {
			card = &cards[i]
			break
		}
	}
	if card == nil {
		a.renderError(w, r, cur, http.StatusNotFound, "App not found", "It may have been removed.")
		return
	}
	var fs []store.Finding
	for _, f := range s.findings {
		if f.WorkloadID == id && status.Active(f.State) {
			fs = append(fs, f)
		}
	}
	ident := s.ids[id]
	d := struct {
		Card    appCard
		Groups  []findingGroup
		Flaws   []appFlaw
		Hidden  int
		Version string
		Source  string
		Doubt   string
		Basis   string
		Machine string
	}{Card: *card, Groups: a.groupFindings(s, fs), Version: ident.Version, Source: ident.VersionSource, Doubt: ident.Doubt()}
	if app, ok := a.d.Catalog.Current().App(ident.AppID); ok && app.Origin != catalog.OriginBuiltin && app.Origin != catalog.OriginFeed {
		d.Basis = "recognised automatically"
	}
	if m := s.hostOf[wl.HostID]; m != nil {
		d.Machine = m.ID
	}
	d.Flaws, d.Hidden = appFlaws(fs, 25)
	a.page(w, r, cur, http.StatusOK, "app", view{Title: card.Name, Nav: "apps", Data: d})
}

// appFlaw is one finding on an app's page, in plain words.
type appFlaw struct {
	ID, Advisory, Summary, Fixed string
	State                        string
	Severity                     string
	Exploited                    bool
}

// appFlaws lists the findings of an app, most pressing first, at most max;
// hidden counts the rest.
func appFlaws(fs []store.Finding, max int) (flaws []appFlaw, hidden int) {
	sort.SliceStable(fs, func(i, j int) bool {
		if priorityRank[fs[i].Priority] != priorityRank[fs[j].Priority] {
			return priorityRank[fs[i].Priority] < priorityRank[fs[j].Priority]
		}
		return fs[i].AdvisoryID < fs[j].AdvisoryID
	})
	for _, f := range fs {
		if len(flaws) >= max {
			hidden++
			continue
		}
		var m match.Finding
		_ = json.Unmarshal(f.Detail, &m)
		state := stateOfPriority(f.Priority)
		if f.MatchState != string(match.Affected) {
			state = appCheck
		}
		flaws = append(flaws, appFlaw{ID: f.ID, Advisory: f.AdvisoryID, Summary: m.Summary, Fixed: f.FixedIn,
			State: state, Severity: m.SeverityLabel, Exploited: m.KEV})
	}
	return flaws, hidden
}
