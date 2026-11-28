// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
)

// The security report of an app: its flaws grouped by the package that has
// them, each package with the version installed and the one that fixes all
// of its flaws, so that a page says in one table what an image or a system
// needs, and each flaw keeps its evidence one click away.

// Severities in the order the report counts them.
var severities = []string{"critical", "high", "medium", "low", "negligible", "unrated"}

// severityOf is the severity a flaw is counted under: its publisher's
// rating where one is given, else the CVSS score's.
func severityOf(label string, cvss float64) string {
	switch strings.ToLower(label) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "negligible", "unimportant":
		return "negligible"
	}
	switch {
	case cvss >= 9:
		return "critical"
	case cvss >= 7:
		return "high"
	case cvss >= 4:
		return "medium"
	case cvss > 0:
		return "low"
	}
	return "unrated"
}

func severityRank(s string) int {
	for i, x := range severities {
		if x == s {
			return len(severities) - i
		}
	}
	return 0
}

// recordPrefixes name the datasets of distribution records by the prefix of
// their IDs (ADR 0047), and osv.dev's databases by theirs.
var recordPrefixes = []struct{ prefix, name string }{
	{"DEBIAN-", "Debian security tracker"},
	{"UBUNTU-", "Ubuntu security data (Canonical)"},
	{"ALPINE-", "Alpine secdb"},
	{"WOLFI-", "Wolfi security data"},
	{"CHAINGUARD-", "Chainguard security data"},
	{"GHSA-", "GitHub advisory database"},
	{"GO-", "Go vulnerability database"},
	{"PYSEC-", "PyPA advisory database"},
	{"RUSTSEC-", "RustSec advisory database"},
	{"ALSA-", "AlmaLinux errata"},
	{"RLSA-", "Rocky Linux errata"},
	{"RHSA-", "Red Hat errata"},
	{"SUSE-", "SUSE security data"},
	{"openSUSE-", "openSUSE security data"},
}

// datasetOf names the dataset a record comes from, "" when the ID does not
// tell.
func datasetOf(recordID string) string {
	for _, p := range recordPrefixes {
		if strings.HasPrefix(recordID, p.prefix) {
			return p.name
		}
	}
	return ""
}

// flawID is the identifier a person looks a flaw up by: the CVE (or GitHub
// advisory) a distribution's record is about, else the advisory's own ID.
func flawID(id string, aliases []string) string {
	for _, p := range []string{"DEBIAN-", "UBUNTU-", "ALPINE-", "WOLFI-", "CHAINGUARD-"} {
		if rest, ok := strings.CutPrefix(id, p); ok {
			return rest
		}
	}
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return id
}

// reportFlaw is one flaw of the report.
type reportFlaw struct {
	FindingID, ID, Record, Summary, Severity, Fixed, State, Status string
	CVSS, EPSS                                                     float64
	KEV                                                            bool
	FirstSeen                                                      time.Time
	URL                                                            string
	Aliases                                                        []string
}

// reportPackage is a package and its flaws.
type reportPackage struct {
	// Key is the package as the evidence names it ("Debian:13/vim").
	Key, Name, Kind string
	ecosystem       string
	Installed       string
	// FixedIn is the version that fixes every flaw with a fix; Unfixed
	// counts the flaws without one.
	FixedIn string
	Unfixed int
	// Snoozed counts the package's flaws the user snoozed.
	Snoozed int
	Worst   string
	KEV     bool
	Flaws   []reportFlaw
}

// report is an app's flaws by package, with counts by severity.
type report struct {
	Packages []reportPackage
	// Counts are the confirmed flaws by severity, in severities' order.
	Counts                         []sevCount
	Total, Fixable, Exploited, Max int
	// Unconfirmed counts the flaws Varde cannot confirm, Snoozed those the
	// user put aside; both are listed but not counted by severity.
	Unconfirmed, Snoozed int
}

type sevCount struct {
	Severity string
	N        int
	// Offset and Width place the severity on a bar of 100 units.
	Offset, Width float64
}

// buildReport groups the open findings of a workload by package. Findings
// of the app itself (not of a package inside it) form a package of their
// own named after the app.
func buildReport(fs []store.Finding, appName string) report {
	byKey := map[string]*reportPackage{}
	var order []string
	counts := map[string]int{}
	var r report
	for _, f := range fs {
		if !status.Active(f.State) {
			continue
		}
		var m match.Finding
		if err := json.Unmarshal(f.Detail, &m); err != nil {
			continue
		}
		key, name, kind, eco := packageOf(f, m, appName)
		p := byKey[key]
		if p == nil {
			p = &reportPackage{Key: key, Name: name, Kind: kind, ecosystem: eco, Installed: m.Evidence.Version}
			byKey[key] = p
			order = append(order, key)
		}
		sev := severityOf(m.SeverityLabel, m.CVSS)
		fl := reportFlaw{
			FindingID: f.ID, ID: flawID(f.AdvisoryID, m.Aliases), Record: f.AdvisoryID, Summary: m.Summary, Severity: sev,
			Fixed: f.FixedIn, State: f.MatchState, Status: f.State, CVSS: m.CVSS, EPSS: m.EPSS, KEV: m.KEV, FirstSeen: f.FirstSeen,
			URL: m.URL, Aliases: m.Aliases,
		}
		p.Flaws = append(p.Flaws, fl)
		if f.State == store.StateSnoozed {
			// Put aside, not counted; the package still says what fixes
			// every flaw it lists.
			r.Snoozed++
			p.Snoozed++
			if f.MatchState == string(match.Affected) {
				p.addFix(eco, f.FixedIn)
			}
			continue
		}
		if f.MatchState != string(match.Affected) {
			r.Unconfirmed++
			continue
		}
		r.Total++
		counts[sev]++
		if m.KEV {
			r.Exploited++
			p.KEV = true
		}
		if severityRank(sev) > severityRank(p.Worst) {
			p.Worst = sev
		}
		if f.FixedIn != "" {
			r.Fixable++
		}
		p.addFix(eco, f.FixedIn)
	}
	for _, k := range order {
		p := byKey[k]
		sort.SliceStable(p.Flaws, func(i, j int) bool {
			a, b := p.Flaws[i], p.Flaws[j]
			if (a.Status == store.StateSnoozed) != (b.Status == store.StateSnoozed) {
				return b.Status == store.StateSnoozed
			}
			if (a.State == string(match.Affected)) != (b.State == string(match.Affected)) {
				return a.State == string(match.Affected)
			}
			if a.KEV != b.KEV {
				return a.KEV
			}
			if severityRank(a.Severity) != severityRank(b.Severity) {
				return severityRank(a.Severity) > severityRank(b.Severity)
			}
			if a.CVSS != b.CVSS {
				return a.CVSS > b.CVSS
			}
			return a.ID < b.ID
		})
		if p.Worst == "" {
			p.Worst = "unrated"
		}
		r.Packages = append(r.Packages, *p)
	}
	// Exploited first, then the worst severity, then the most flaws.
	sort.SliceStable(r.Packages, func(i, j int) bool {
		a, b := r.Packages[i], r.Packages[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if severityRank(a.Worst) != severityRank(b.Worst) {
			return severityRank(a.Worst) > severityRank(b.Worst)
		}
		if len(a.Flaws) != len(b.Flaws) {
			return len(a.Flaws) > len(b.Flaws)
		}
		return a.Name < b.Name
	})
	offset := 0.0
	for _, s := range severities {
		n := counts[s]
		if n == 0 {
			continue
		}
		w := 100 * float64(n) / float64(r.Total)
		r.Counts = append(r.Counts, sevCount{Severity: s, N: n, Offset: offset, Width: w})
		offset += w
		if n > r.Max {
			r.Max = n
		}
	}
	return r
}

// packageOf names the package a finding is in.
func packageOf(f store.Finding, m match.Finding, appName string) (key, name, kind, ecosystem string) {
	if eco, pkg, ok := distro.ParseSystemAppID(f.AppID); ok {
		label, _ := distro.SystemName(f.AppID)
		kind = strings.TrimSuffix(strings.TrimPrefix(label, pkg+" ("), ")")
		return f.AppID, pkg, kind, eco
	}
	if eco, pkg, ok := strings.Cut(m.Evidence.Package, "/"); ok && (m.Image || distro.Supported(eco) && !distro.Language(eco)) {
		// A package inside an image, or a catalog app installed from its
		// distribution: its versions compare in the package manager's
		// order.
		return m.Evidence.Package, pkg, strings.ReplaceAll(eco, ":", " ") + " package", eco
	}
	return "app:" + f.AppID, appName, "the app itself", ""
}

// newer reports whether version a is above b in the package's ecosystem;
// versions that do not compare keep the first one seen.
func newer(ecosystem, a, b string) bool {
	if ecosystem == "" {
		return false
	}
	c, ok := distro.Compare(ecosystem, a, b)
	return ok && c > 0
}

// reportCSV serves the security report of an app as a CSV file: one row per
// open flaw, for a spreadsheet or a ticket system.
func (a *app) reportCSV(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
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
	var fs []store.Finding
	for _, f := range s.findings {
		if f.WorkloadID == id {
			fs = append(fs, f)
		}
	}
	name := a.appName(s.ids[id].AppID)
	if name == "" {
		name = wl.Name
	}
	rep := buildReport(fs, name)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(wl.Name)+`-security-report.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"package", "kind", "installed", "fixed_in", "id", "record", "aliases", "severity", "cvss", "known_exploited", "epss",
		"match", "state", "first_seen", "summary", "url"})
	for _, p := range rep.Packages {
		for _, f := range p.Flaws {
			cvss := ""
			if f.CVSS > 0 {
				cvss = strconv.FormatFloat(f.CVSS, 'f', 1, 64)
			}
			epss := ""
			if f.EPSS > 0 {
				epss = strconv.FormatFloat(f.EPSS, 'f', 4, 64)
			}
			_ = cw.Write(csvRow(p.Name, p.Kind, p.Installed, f.Fixed, f.ID, f.Record, strings.Join(f.Aliases, " "), f.Severity, cvss,
				strconv.FormatBool(f.KEV), epss, f.State, f.Status, f.FirstSeen.UTC().Format(time.RFC3339), f.Summary, f.URL))
		}
	}
	cw.Flush()
}

// csvRow neutralises cells a spreadsheet would run as a formula: advisory
// text and package names come from upstream and must not execute.
func csvRow(cells ...string) []string {
	for i, c := range cells {
		if formulaLike(c) {
			cells[i] = "'" + c
		}
	}
	return cells
}

// formulaLike reports whether a spreadsheet could read s as a formula:
// it starts with a control character, or with a formula character (also
// in full width) after any spaces, which some importers drop.
func formulaLike(s string) bool {
	if s == "" {
		return false
	}
	if strings.ContainsRune("\t\r\n", rune(s[0])) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(strings.TrimLeft(s, " "))
	return strings.ContainsRune("=+-@\uff1d\uff0b\uff0d\uff20", r)
}

// safeFilename keeps the characters a download name may hold.
func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "app"
	}
	return b.String()
}

// runOn is where a fix command runs: the machine, an address to reach it,
// and the user's WebSSH, which the page opens with the command (the
// element ID) copied. Varde sends WebSSH nothing and runs nothing itself.
type runOn struct {
	ID, Host, Address, WebSSH string
}

// machineOf names the machine a host record belongs to and an address of
// it, for "run it on".
func machineOf(s *snapshot, hostID string) (name, address string) {
	m := s.hostOf[hostID]
	if m == nil {
		return "", ""
	}
	if len(m.Addresses) > 0 {
		address = m.Addresses[0]
	}
	return m.Name, address
}

// addFix takes a flaw's fixed version into the package's: the highest
// fixed version, or one more flaw without a fix.
func (p *reportPackage) addFix(ecosystem, fixed string) {
	if fixed == "" {
		p.Unfixed++
		return
	}
	if p.FixedIn == "" || newer(ecosystem, fixed, p.FixedIn) {
		p.FixedIn = fixed
	}
}
