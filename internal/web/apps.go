// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/upstream"
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
	appNow      = "now"      // a confirmed P1 finding an update fixes: update now
	appMitigate = "mitigate" // a confirmed P1 finding no known update fixes
	appSoon     = "soon"     // P2: update soon
	appLater    = "later"    // P3: with the next regular update
	appCheck    = "check"    // only findings Varde cannot confirm
	appSnoozed  = "snoozed"  // every open flaw snoozed by the user
	appOK       = "ok"       // compared with complete data, nothing found
	appKnown    = "known"    // compared, but the advisory data is incomplete
	appUnknown  = "unknown"  // nothing could be compared
)

// appStateRank orders the states for the list.
var appStateRank = map[string]int{appNow: 0, appMitigate: 1, appSoon: 2, appLater: 3, appCheck: 4, appSnoozed: 5, appUnknown: 6, appKnown: 7, appOK: 8}

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
	// Upstream is what Varde knows about a newer image, for cards of
	// containers with findings in their image's packages.
	Upstream *upstream.Status
	// Introduced says what the suggested image brings that the running
	// one does not have, when it brings something.
	Introduced string
	// Mitigation is what to do while no update fixes the findings.
	Mitigation *mitigation
	// Sev counts the card's confirmed flaws by severity, the three worst
	// severities present; Exploited those known to be exploited.
	Sev       []sevCount
	Exploited int
	// Others are further containers of the same image on the front page,
	// which the same update fixes; the card stands for all of them.
	Others []string
	// Platform is what deployed the container, which decides how an
	// update is applied: "compose", "portainer" (a Portainer stack),
	// "unraid" (Unraid's Docker manager) or "run" (docker run); empty for
	// anything else. RunHost and RunAddr name the machine a command runs
	// on.
	Platform, RunHost, RunAddr string
	// Release says which flaws in the image's packages the newest release
	// of the app fixes, Groups are the app and package versions behind
	// the card; both are set on the list of updates only.
	Release *releaseView
	Groups  []findingGroup
}

// appLabels are the states in the words of the pages.
var appLabels = map[string]string{
	appNow: "Update now", appMitigate: "Mitigate now", appSoon: "Update soon", appLater: "With the next update", appCheck: "Check yourself",
	appOK: "Nothing found", appKnown: "Nothing known", appUnknown: "Not checked", appSnoozed: "Snoozed",
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
	snoozed := map[string][]store.Finding{}
	for _, f := range s.findings {
		switch {
		case actionable(f.State):
			open = append(open, f)
		case f.State == store.StateSnoozed:
			snoozed[f.WorkloadID] = append(snoozed[f.WorkloadID], f)
		}
	}
	out := a.updateCards(s, a.todoGroups(s, open), open)
	seen := map[string]bool{}
	for i := range out {
		seen["w:"+out[i].Key] = true
		// The front page is a card and its action; what is behind it
		// is on the app's page and on the list of updates.
		out[i].Groups = nil
	}
	hostNames := hostNamesOf(s)
	for _, wl := range s.workloads {
		if seen["w:"+wl.ID] || identify.IsSystem(wl) {
			continue
		}
		id := s.ids[wl.ID]
		c := appCard{Key: wl.ID, Href: "/apps/" + wl.ID}
		a.describe(&c, s, wl, hostNames)
		if fs := snoozed[wl.ID]; len(fs) > 0 {
			// Put aside by the user: not an update to do until the snooze
			// ends.
			c.State, c.Label, c.Note = appSnoozed, appLabels[appSnoozed], snoozeNote(fs)
			out = append(out, c)
			continue
		}
		row := workloadRow{Derived: id.Derived}
		if kind, skip := coverage.NotAnApp(wl, id, s.marked); skip {
			row.NotApp = kind
		}
		switch kind, note := a.checked(id, row); kind {
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

// hostNamesOf maps host IDs to names.
func hostNamesOf(s *snapshot) map[string]string {
	names := map[string]string{}
	for _, h := range s.hosts {
		names[h.ID] = h.Name
	}
	return names
}

// updateCards are the cards of the updates to do: one per group of
// findings that one update fixes, in the groups' order. fs are the
// findings the groups were made of.
func (a *app) updateCards(s *snapshot, groups []todoGroup, fs []store.Finding) []appCard {
	hostNames := hostNamesOf(s)
	byWorkload := map[string][]store.Finding{}
	for _, f := range fs {
		byWorkload[f.WorkloadID] = append(byWorkload[f.WorkloadID], f)
	}
	var out []appCard
	for _, g := range groups {
		c := appCard{Key: g.Key, Name: g.Name, Count: g.Count, State: stateOfPriority(g.Priority), Release: g.Release, Groups: g.Groups}
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
			fix := a.plan(&c, s, wl, byWorkload[id], g)
			c.State = string(upstream.Decide(upstream.UrgencyOf(g.Priority), fix))
		} else {
			// The packages of a system: its page lists them.
			host := strings.TrimPrefix(g.Key, "h:")
			c.Href, c.Sub = "/findings?view=package", "packages of the system"
			if m := s.hostOf[host]; m != nil {
				c.Href = "/systems/" + m.ID + "#packages"
			}
			c.Action, c.Command = g.Action, g.Command
			c.Fixes = plural(g.Count, "flaw") + " in installed packages"
		}
		c.Label = appLabels[c.State]
		c.Why = why(c, g, workloadOf(s, c.Key), byWorkload[c.Key])
		c.Sev, c.Exploited = cardSeverities(byWorkload[c.Key])
		out = append(out, c)
	}
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
	c.RunHost, c.RunAddr = machineOf(s, wl.HostID)
	if wl.Container != nil {
		c.Platform = platformOf(wl.Container)
	}
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
// of all its findings that version fixes. For the packages inside an image
// it suggests an image only when Varde knows one that fixes them
// (upstream.Status); otherwise it says so and how to limit the risk. It
// returns what the update does to the card's most pressing findings, from
// which the card's state follows (upstream.Decide).
func (a *app) plan(c *appCard, s *snapshot, wl inventory.Workload, fs []store.Finding, g todoGroup) upstream.Fix {
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
		// fixedIn is what the advisory names, step the version the
		// analysis chose for the finding (a release that exists).
		fixedIn, step string
		top           bool
	}
	var fixes []fix
	open, noFix, image := 0, 0, 0
	var topImage []match.Finding // the image findings of the top priority
	var all *match.Target        // the update that fixes the most, on any line
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
			image++
			if top {
				topImage = append(topImage, m)
			}
		case f.FixedIn == "":
			noFix++
		default:
			// The step of the analysis; a finding stored before it
			// existed has its own fixed version.
			step := f.FixedIn
			if m.Step != nil {
				step = m.Step.Version
			}
			fixes = append(fixes, fix{f.FixedIn, step, top})
			if top && (target == "" || !match.AtLeast(scheme, target, step)) {
				target = step
			}
		}
	}
	if target == "" {
		// Nothing of the top priority has a fix: the update that fixes
		// the most of the rest.
		// Each finding's step, not its advisory's version: the card must
		// name what the image line carries.
		for _, f := range fixes {
			if target == "" || !match.AtLeast(scheme, target, f.step) {
				target = f.step
			}
		}
	}
	var st *upstream.Status
	if wl.Container != nil && image > 0 {
		st = s.upstreamOf(wl.ID)
		c.Upstream = st
	}
	// imageFix is what the upstream image does to the image findings.
	imageFix := upstream.NoFix
	if st != nil && st.Actionable() {
		imageFix = upstream.FixesOther
		for _, m := range topImage {
			if st.Fixes(m.AdvisoryID, m.Evidence.Package) {
				imageFix = upstream.FixesTop
				break
			}
		}
	}
	switch {
	case target != "":
		if p := wl.Package; p != nil && !p.System {
			// An app installed from its distribution: its package manager
			// installs the update.
			if cmd := remedy.PackageCommand(p.Distro, []string{p.Name}); cmd != "" {
				c.Command = remedy.AsRoot(cmd)
			}
		}
		fixed, fixedTop := 0, false
		for _, f := range fixes {
			if match.AtLeast(scheme, target, f.fixedIn) {
				fixed++
				fixedTop = fixedTop || f.top
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
		defer c.fitCommand()
		// sameImage is set when the image the card suggests is the one the
		// upstream status judged: only then do its fixes count for it.
		sameImage := false
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
				sameImage = st != nil && !st.Rebuilt && st.TargetTag != "" && tagOf(sg.Image) == st.TargetTag
			} else if ok && sg.Floating {
				c.Action = "Pull the image again and recreate the container"
				c.Compose = sg.Compose
				if sg.Compose != nil {
					c.Command = sg.Compose.Pull()
				}
				sameImage = st != nil && st.Rebuilt
			}
		}
		if !sameImage {
			// Another image than the one suggested fixes the flaws in
			// the image's packages; the suggestion is not credited with
			// them.
			imageFix = upstream.NoFix
		}
		// What the update fixes of the most pressing findings decides:
		// the app's own, or those in the image when the suggested image is
		// known to fix them.
		switch {
		case fixedTop || imageFix == upstream.FixesTop:
			return upstream.FixesTop
		case fixed > 0 || imageFix == upstream.FixesOther:
			return upstream.FixesOther
		}
		return upstream.NoFix
	case image > 0 && wl.Container != nil:
		a.imagePlan(c, wl, fs, st, image)
		return imageFix
	case open > 0:
		c.Action = "No fixed version is published yet"
		c.Fixes = "limit who can reach it until one is"
		c.Mitigation = mitigationOf(c, wl, fs, nil)
	default:
		c.Action = "Look at the " + plural(g.Count, "finding") + " Varde cannot confirm"
	}
	return upstream.NoFix
}

// tagOf is the tag of an image reference ("nginx:1.28" gives "1.28").
func tagOf(ref string) string {
	name, _, _ := strings.Cut(ref, "@")
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		return name[i+1:]
	}
	return ""
}

// allOf words "all N flaws" for one and for several.
func allOf(n int) string {
	if n == 1 {
		return "the flaw"
	}
	return "all " + strconv.Itoa(n) + " flaws"
}

// why says in one line what makes a card pressing. A flaw known to be
// exploited is named with its component: what the container serves, or a
// package that is only in the image (ADR 0045).
func why(c appCard, g todoGroup, wl *inventory.Workload, fs []store.Finding) string {
	var parts []string
	if g.KEV {
		text, whole := exploitedWhy(c, g, wl, fs)
		if whole {
			return text
		}
		parts = append(parts, text)
	}
	imageOnly := c.Upstream != nil && onlyImage(fs)
	switch c.Exposure {
	case "public":
		if imageOnly && !g.KEV {
			parts = append(parts, "flaws in packages of the image; the container is reachable from the internet")
		} else {
			parts = append(parts, "reachable from the internet")
		}
	case "lan":
		if imageOnly && !g.KEV {
			parts = append(parts, "flaws in packages of the image; the container is reachable in your network")
		} else {
			parts = append(parts, "reachable in your network")
		}
	}
	if len(parts) == 0 {
		switch c.State {
		case appSoon:
			return "serious flaws, but not directly reachable"
		case appLater:
			// The priority is low because nothing reaches the flaws, not
			// always because they are mild: the card must not call a
			// critical flaw minor.
			if r := buildReport(fs, ""); len(r.Counts) > 0 && severityRank(r.Counts[0].Severity) >= severityRank("high") {
				if imageOnly {
					return "serious flaws in packages of the image, but no known attack path uses them"
				}
				return "serious flaws, but no known attack path reaches them"
			}
			return "minor flaws"
		case appCheck:
			return "Varde cannot tell whether these apply to the version running"
		}
	}
	return strings.Join(parts, ", ")
}

// exploitedWhy words the flaw known to be exploited that makes a card
// pressing; whole is set when the text says all there is, reachability
// included.
func exploitedWhy(c appCard, g todoGroup, wl *inventory.Workload, fs []store.Finding) (text string, whole bool) {
	var pick *match.Finding
	pkg, pickTop := "", false
	for _, f := range fs {
		if f.MatchState != string(match.Affected) || !status.Active(f.State) {
			continue
		}
		var m match.Finding
		if json.Unmarshal(f.Detail, &m) != nil || !m.KEV {
			continue
		}
		// The most pressing one: one of the card's priority first.
		if top := f.Priority == g.Priority; pick == nil || (top && !pickTop) {
			mm := m
			pick, pickTop = &mm, top
			_, pkg, _ = distro.ParseSystemAppID(f.AppID)
		}
	}
	if pick == nil || !pick.Image || pkg == "" {
		return "a flaw is known to be exploited", false
	}
	exposed := c.Exposure == "public" || c.Exposure == "lan"
	var command []string
	if wl != nil && wl.Container != nil && wl.Container.Runtime != nil {
		command = wl.Container.Runtime.Command
	}
	if paths.ComponentOf(pkg, command, exposed).Reach != paths.Served {
		return "known-exploited flaw in " + pkg + ", in the image", true
	}
	return "known-exploited flaw in " + pkg + ", " + servedOn(c, wl), true
}

// servedOn says how what a container serves is reached: its published
// port, or the route that reaches it.
func servedOn(c appCard, wl *inventory.Workload) string {
	if wl != nil && wl.Container != nil {
		for _, p := range wl.Container.Ports {
			if p.PublicPort > 0 {
				return "served on port " + strconv.Itoa(int(p.PublicPort))
			}
		}
	}
	if c.Exposure == "public" {
		return "served to the internet"
	}
	return "served in your network"
}

// onlyImage reports whether every confirmed finding is in an image package.
func onlyImage(fs []store.Finding) bool {
	any := false
	for _, f := range fs {
		if f.MatchState != string(match.Affected) {
			continue
		}
		var m match.Finding
		if json.Unmarshal(f.Detail, &m) != nil || !m.Image {
			return false
		}
		any = true
	}
	return any
}

// appCounts are the numbers the front page leads with.
type appCounts struct {
	Snoozed                                                 int
	Now, Mitigate, Soon, Later, Check, Fine, Unknown, Total int
}

func countApps(cards []appCard) appCounts {
	var n appCounts
	for _, c := range cards {
		n.Total++
		switch c.State {
		case appNow:
			n.Now++
		case appMitigate:
			n.Mitigate++
		case appSoon:
			n.Soon++
		case appLater:
			n.Later++
		case appCheck:
			n.Check++
		case appUnknown:
			n.Unknown++
		case appSnoozed:
			n.Snoozed++
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

// Count is the number of apps the section's cards stand for: a card of
// several containers of one image counts each, as the chips above do.
func (s appSection) Count() int {
	n := 0
	for _, c := range s.Cards {
		n += 1 + len(c.Others)
	}
	return n
}

// mergeSameImage folds the cards of containers that run the same image and
// need the same update into one card: one image, one thing to do. Commands
// name a Compose service; a merged card keeps them only when all agree.
func mergeSameImage(cards []appCard, s *snapshot) []appCard {
	out := make([]appCard, 0, len(cards))
	first := map[string]int{}
	for _, c := range cards {
		wl, ok := s.byID[c.Key]
		if !ok || wl.Container == nil || wl.Container.ImageID == "" || c.Count == 0 {
			out = append(out, c)
			continue
		}
		key := wl.HostID + "\x00" + wl.Container.ImageID + "\x00" + c.State + "\x00" + c.Action + "\x00" + strconv.Itoa(c.Count)
		i, seen := first[key]
		if !seen {
			first[key] = len(out)
			out = append(out, c)
			continue
		}
		m := &out[i]
		m.Others = append(m.Others, wl.Name)
		if m.Command != c.Command {
			m.Command = ""
		}
		if m.Mitigation != nil && c.Mitigation != nil && m.Mitigation.Rebuild != c.Mitigation.Rebuild {
			mit := *m.Mitigation
			mit.Rebuild = ""
			m.Mitigation = &mit
		}
	}
	return out
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
	add(appNow, "Update now", "Reachable or already being exploited, and an update that fixes it exists. Varde notifies about these at once.", false)
	add(appMitigate, "Mitigate now", "Just as urgent, but no update that fixes it is known yet. Varde notifies about these at once; each says how to limit the risk, and it moves to \"Update now\" by itself once a fixed image appears.", false)
	add(appSoon, "Update soon", "Serious, but not directly reachable. They are in the daily digest.", false)
	add(appLater, "With the next update", "Nothing pressing. They are in the weekly digest.", false)
	add(appCheck, "Check yourself", "Varde found advisories for these apps but cannot tell whether they apply to the version running.", false)
	add(appSnoozed, "Snoozed", "You put their flaws aside. They come back by themselves when the snooze ends, and Varde does not notify about them until then.", true)
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
		Report  report
		Version string
		Source  string
		Doubt   string
		Basis   string
		Machine string
		WebSSH  string
	}{WebSSH: a.d.Settings.Get().WebSSHURL, Card: *card, Groups: a.groupFindings(s, fs), Report: buildReport(fs, card.Name), Version: ident.Version, Source: ident.VersionSource, Doubt: ident.Doubt()}
	if app, ok := a.d.Catalog.Current().App(ident.AppID); ok && app.Origin != catalog.OriginBuiltin && app.Origin != catalog.OriginFeed {
		d.Basis = "recognised automatically"
	}
	if m := s.hostOf[wl.HostID]; m != nil {
		d.Machine = m.ID
	}
	a.page(w, r, cur, http.StatusOK, "app", view{Title: card.Name, Nav: "apps", Data: d})
}

// appHref is the page of the app a workload is; "" for a system package,
// which belongs to its machine's page.
func appHref(wl inventory.Workload) string {
	if wl.ID == "" || identify.IsSystem(wl) {
		return ""
	}
	return "/apps/" + wl.ID
}

// cardSeverities counts the confirmed open flaws of a card by severity,
// the three worst severities present, and those known to be exploited.
func cardSeverities(fs []store.Finding) ([]sevCount, int) {
	r := buildReport(fs, "")
	out := r.Counts
	if len(out) > 3 {
		out = out[:3]
	}
	return out, r.Exploited
}

// snoozeNote says what was snoozed and what brings it back: the end of the
// latest snooze, or a fixed image for flaws snoozed until one appears.
func snoozeNote(fs []store.Finding) string {
	var until time.Time
	upstream := false
	for _, f := range fs {
		upstream = upstream || f.SnoozeUpstream
		if f.SnoozedUntil != nil && f.SnoozedUntil.After(until) {
			until = *f.SnoozedUntil
		}
	}
	note := plural(len(fs), "flaw") + " snoozed"
	switch {
	case upstream && !until.IsZero():
		note += " until a fixed image appears, at the latest " + until.Local().Format("2 Jan 2006")
	case upstream:
		note += " until a fixed image appears"
	case !until.IsZero():
		note += " until " + until.Local().Format("2 Jan 2006")
	}
	return note
}

// platformOf says what deployed a container (see appCard.Platform).
func platformOf(c *inventory.Container) string {
	switch cp := remedy.ComposeOf(c); {
	case remedy.Unraid(c):
		return "unraid"
	case cp != nil && cp.Portainer != "":
		return "portainer"
	case cp != nil:
		return "compose"
	}
	return "run"
}

// imageRefPattern accepts the image references a command may name.
var imageRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:@-]{0,255}$`)

// fitCommand makes the card's command fit what deployed the container: a
// Portainer stack and Unraid are updated in their own interface, with no
// command on the host; a container started with docker run pulls the new
// image, and is then recreated with the options it was started with.
func (c *appCard) fitCommand() {
	switch c.Platform {
	case "portainer", "unraid":
		c.Command = ""
	case "run":
		if c.Mitigation != nil {
			// No image to pull: none fixes the flaws, or it is built here.
			return
		}
		ref := strings.TrimPrefix(c.Line, "image: ")
		if ref == "" && strings.HasPrefix(c.Action, "Pull the ") {
			// A floating tag: the same reference brings the new image.
			ref = c.Image
		}
		c.Command = ""
		if ref != "" && imageRefPattern.MatchString(ref) {
			c.Command = "docker pull " + ref
		}
	}
}
