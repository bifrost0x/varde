// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/store"
)

// historyPeriods are the periods the history offers, in days.
var historyPeriods = []int{7, 30, 90, 365}

// historyEntry is one thing that happened: one analysis that fixed or
// opened findings of one workload for one reason, or one user action.
type historyEntry struct {
	At                    time.Time
	Kind                  string // fixed, opened, action
	Headline, Explain     string
	Workload, Host, Image string
	Actor                 string
	Items                 []historyItem
	Urgent                bool
}

type historyItem struct {
	FindingID, App, Advisory, Priority, From, To, FixedIn string
	// Link is set while the finding is still stored.
	Link bool
}

type historyDay struct {
	Date    string
	Entries []historyEntry
}

type historyCount struct {
	Label string
	Count int
}

type historyData struct {
	Days    int
	Periods []int
	HostID  string
	Hosts   []hostOption
	// Fixed counts findings fixed by an update or by removing the package;
	// Closed those that ended otherwise (workload gone, advisory changed).
	Fixed, Closed, Opened, Reopened int
	FixedUrgent                     int
	ByCause                         []historyCount
	// TimeToFix is the median time from opened to fixed per priority.
	TimeToFix  []timeToFix
	Open       int
	OpenUrgent int
	Oldest     []findingRow
	Timeline   []historyDay
	Truncated  bool
}

type hostOption struct{ ID, Name string }

type timeToFix struct {
	Priority, Median string
	Count            int
}

// historyFilter reads the period and host of a history request.
func historyFilter(r *http.Request, now time.Time) (int, store.HistoryFilter) {
	days := 30
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && slices.Contains(historyPeriods, d) {
		days = d
	}
	return days, store.HistoryFilter{From: now.Add(-time.Duration(days) * 24 * time.Hour), HostID: r.URL.Query().Get("host")}
}

func (a *app) history(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx, now := r.Context(), a.d.Now()
	days, filter := historyFilter(r, now)
	evs, err := a.d.Store.FindingEvents(ctx, filter)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	s, err := a.load(ctx, true)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	audit, err := a.d.Store.AuditLog(ctx, 2000)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	d := historyData{Days: days, Periods: historyPeriods, HostID: filter.HostID, Truncated: len(evs) >= 5000}
	hostNames := map[string]string{}
	for _, h := range s.hosts {
		hostNames[h.ID] = h.Name
		d.Hosts = append(d.Hosts, hostOption{ID: h.ID, Name: h.Name})
	}
	sort.Slice(d.Hosts, func(i, j int) bool { return d.Hosts[i].Name < d.Hosts[j].Name })
	stored := map[string]store.Finding{}
	for _, f := range s.findings {
		stored[f.ID] = f
		if active(f.State) && (filter.HostID == "" || s.byID[f.WorkloadID].HostID == filter.HostID) {
			d.Open++
			if f.Priority == "P1" {
				d.OpenUrgent++
			}
			d.Oldest = append(d.Oldest, a.row(s, f))
		}
	}
	// The longest open first: what has waited longest.
	first := map[string]time.Time{}
	for _, f := range s.findings {
		first[f.ID] = f.FirstSeen
	}
	sort.SliceStable(d.Oldest, func(i, j int) bool { return first[d.Oldest[i].ID].Before(first[d.Oldest[j].ID]) })
	if len(d.Oldest) > 5 {
		d.Oldest = d.Oldest[:5]
	}

	causes := map[string]int{}
	fixTimes := map[string][]time.Duration{}
	groups := map[string]*historyEntry{}
	var entries []*historyEntry
	for _, e := range evs {
		switch e.Kind {
		case "opened":
			d.Opened++
		case "reopened":
			d.Reopened++
		case "resolved":
			causes[e.Cause]++
			if fixed(e.Cause) {
				d.Fixed++
				if e.Priority == "P1" {
					d.FixedUrgent++
				}
				if e.OpenedAt != nil {
					fixTimes[e.Priority] = append(fixTimes[e.Priority], e.At.Sub(*e.OpenedAt))
				}
			} else {
				d.Closed++
			}
		}
		// One analysis stamps all its changes with the same time.
		key := e.WorkloadID + "\x00" + e.Kind + "\x00" + e.Cause + "\x00" + strconv.FormatInt(e.At.UnixMilli(), 10)
		g, ok := groups[key]
		if !ok {
			g = &historyEntry{At: e.At, Kind: entryKind(e.Kind), Workload: e.WorkloadName, Host: e.HostName, Image: e.ImageRef}
			g.Headline, g.Explain = eventHeadline(e)
			groups[key] = g
			entries = append(entries, g)
		}
		f, link := stored[e.FindingID]
		prio := e.Priority
		if prio == "" && link {
			// A new finding is rated after it is recorded.
			prio = f.Priority
		}
		g.Items = append(g.Items, historyItem{FindingID: e.FindingID, App: a.appName(e.AppID), Advisory: e.AdvisoryID, Priority: prio,
			From: e.FromVersion, To: e.ToVersion, FixedIn: e.FixedIn, Link: link})
		if prio == "P1" {
			g.Urgent = true
		}
	}
	for _, en := range audit {
		if !strings.HasPrefix(en.Action, "finding.") || en.At.Before(filter.From) {
			continue
		}
		f, ok := stored[en.Target]
		if filter.HostID != "" && (!ok || s.byID[f.WorkloadID].HostID != filter.HostID) {
			continue
		}
		g := &historyEntry{At: en.At, Kind: "action", Actor: en.Actor, Headline: actionHeadline(en.Action), Explain: en.Detail}
		if ok {
			wl := s.byID[f.WorkloadID]
			g.Workload, g.Host = wl.Name, hostNames[wl.HostID]
			g.Items = []historyItem{{FindingID: f.ID, App: a.appName(f.AppID), Advisory: f.AdvisoryID, Priority: f.Priority, FixedIn: f.FixedIn, Link: true}}
		}
		entries = append(entries, g)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].At.After(entries[j].At) })
	for _, en := range entries {
		sort.SliceStable(en.Items, func(i, j int) bool {
			if en.Items[i].Priority != en.Items[j].Priority {
				return prioRank(en.Items[i].Priority) < prioRank(en.Items[j].Priority)
			}
			return en.Items[i].App < en.Items[j].App
		})
		day := en.At.Local().Format("Monday, 2 January 2006")
		if n := len(d.Timeline); n == 0 || d.Timeline[n-1].Date != day {
			d.Timeline = append(d.Timeline, historyDay{Date: day})
		}
		d.Timeline[len(d.Timeline)-1].Entries = append(d.Timeline[len(d.Timeline)-1].Entries, *en)
	}
	for _, c := range []string{store.CauseUpdated, store.CauseUninstalled, store.CauseRemoved, store.CauseAdvisory, ""} {
		if n := causes[c]; n > 0 {
			d.ByCause = append(d.ByCause, historyCount{Label: causeLabel(c), Count: n})
		}
	}
	for _, p := range []string{"P1", "P2", "P3"} {
		if ts := fixTimes[p]; len(ts) > 0 {
			d.TimeToFix = append(d.TimeToFix, timeToFix{Priority: p, Median: span(median(ts)), Count: len(ts)})
		}
	}
	a.page(w, r, cur, http.StatusOK, "history", view{Title: "History", Nav: "findings", Tabs: tabs("findings", "/findings/history"), Data: d})
}

// historyCSV exports the history of the period, one row per event.
func (a *app) historyCSV(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx, now := r.Context(), a.d.Now()
	days, filter := historyFilter(r, now)
	// Every event of the period, written in full before anything is sent:
	// a failure halfway must not arrive as a complete-looking report.
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"time", "event", "cause", "host", "workload", "image", "app", "advisory", "priority", "version", "new_version", "fixed_in", "open_days"})
	err := a.d.Store.EachFindingEvent(ctx, filter, func(e store.FindingEvent) error {
		open := ""
		if e.OpenedAt != nil {
			open = strconv.FormatFloat(e.At.Sub(*e.OpenedAt).Hours()/24, 'f', 1, 64)
		}
		return cw.Write([]string{e.At.UTC().Format(time.RFC3339), e.Kind, e.Cause, csvSafe(e.HostName), csvSafe(e.WorkloadName), csvSafe(e.ImageRef),
			csvSafe(a.appName(e.AppID)), csvSafe(e.AdvisoryID), e.Priority, csvSafe(e.FromVersion), csvSafe(e.ToVersion), csvSafe(e.FixedIn), open})
	})
	if cw.Flush(); err == nil {
		err = cw.Error()
	}
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="varde-history-`+now.Format("2006-01-02")+"-"+strconv.Itoa(days)+`d.csv"`)
	_, _ = w.Write(buf.Bytes())
}

// csvSafe keeps a spreadsheet from reading a cell as a formula: names come
// from containers and images, which anyone on a host can choose.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// fixed reports whether a resolution was a fix: an update or the package
// taken out, not a workload going away or an advisory changing.
func fixed(cause string) bool { return cause == store.CauseUpdated || cause == store.CauseUninstalled }

func entryKind(kind string) string {
	if kind == "resolved" {
		return "fixed"
	}
	return "opened"
}

func causeLabel(cause string) string {
	switch cause {
	case store.CauseUpdated:
		return "Fixed by an update"
	case store.CauseUninstalled:
		return "Fixed by removing the package or app"
	case store.CauseRemoved:
		return "Closed: the container or system is gone"
	case store.CauseAdvisory:
		return "Closed: the advisory no longer applies"
	}
	return "Resolved before Varde recorded why"
}

// eventHeadline says in a few words what happened, and why it matters.
func eventHeadline(e store.FindingEvent) (string, string) {
	switch e.Kind {
	case "opened":
		return "New findings", "An advisory now applies to a version running here."
	case "reopened":
		return "Findings back", "A finding that was resolved applies again, for example after a downgrade or a changed advisory."
	}
	if e.ImageRef != "" && strings.HasPrefix(e.AppID, distro.SystemPrefix) && fixed(e.Cause) {
		return "New image", "The container runs a newer image: these packages in it were updated or are no longer part of it."
	}
	switch e.Cause {
	case store.CauseUpdated:
		return "Updated", "A newer version is running; these advisories no longer apply to it."
	case store.CauseUninstalled:
		return "Package removed", "The package or app is no longer installed, so its advisories are gone."
	case store.CauseRemoved:
		return "Removed", "The container or system is gone; its findings are closed, not fixed."
	case store.CauseAdvisory:
		return "Advisory changed", "The same version is running; the advisory was withdrawn or no longer names it."
	}
	return "Resolved", "Resolved before Varde recorded the reason."
}

func actionHeadline(action string) string {
	switch strings.TrimPrefix(action, "finding.") {
	case "acknowledge":
		return "Acknowledged"
	case "unacknowledge":
		return "Acknowledgement taken back"
	case "snooze":
		return "Snoozed"
	case "unsnooze":
		return "Snooze ended"
	case "unsuppress":
		return "Suppression lifted"
	}
	return strings.TrimPrefix(action, "finding.")
}

func prioRank(p string) int {
	switch p {
	case "P1":
		return 0
	case "P2":
		return 1
	case "P3":
		return 2
	}
	return 3
}

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// span is a duration for people: minutes, hours or days.
func span(d time.Duration) string {
	switch {
	case d < time.Hour:
		return plural(max(1, int(d/time.Minute)), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	}
	return plural(int(d/(24*time.Hour)), "day")
}

// findingHistory is the history of one finding with what users did about
// it, newest first. It is empty when the history cannot be read: the page
// is still useful without it.
func (a *app) findingHistory(r *http.Request, id string) []historyEntry {
	evs, err := a.d.Store.FindingEvents(r.Context(), store.HistoryFilter{FindingID: id, Limit: 200})
	if err != nil {
		a.d.Log.Warn("finding history not read", "finding", id, "err", err)
		return nil
	}
	var out []historyEntry
	for _, e := range evs {
		h, ex := eventHeadline(e)
		out = append(out, historyEntry{At: e.At, Kind: entryKind(e.Kind), Headline: h, Explain: ex,
			Items: []historyItem{{From: e.FromVersion, To: e.ToVersion}}})
	}
	audit, err := a.d.Store.AuditFor(r.Context(), id, 200)
	if err != nil {
		a.d.Log.Warn("finding audit not read", "finding", id, "err", err)
	}
	for _, en := range audit {
		if strings.HasPrefix(en.Action, "finding.") {
			out = append(out, historyEntry{At: en.At, Kind: "action", Headline: actionHeadline(en.Action), Explain: en.Detail, Actor: en.Actor})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}
