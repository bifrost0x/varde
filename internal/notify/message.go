// SPDX-License-Identifier: Apache-2.0

// Package notify decides when to notify and delivers plain, short messages
// to ntfy, Gotify, a webhook or SMTP. Urgent (P1) findings are sent at
// once, P2 in a daily and P3 in a weekly digest; repeated scans never
// re-notify, escalations do.
package notify

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/policy"
)

// Message kinds.
const (
	KindImmediate    = "immediate"
	KindDigestDaily  = "digest-daily"
	KindDigestWeekly = "digest-weekly"
	KindTest         = "test"
)

// Item is one finding prepared for rendering.
type Item struct {
	FindingID        string          `json:"finding_id"`
	AppID            string          `json:"app_id"`
	AppName          string          `json:"app"`
	WorkloadName     string          `json:"workload"`
	HostName         string          `json:"host,omitempty"`
	Version          string          `json:"version,omitempty"`
	AdvisoryID       string          `json:"advisory_id"`
	Aliases          []string        `json:"aliases,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Severity         string          `json:"severity,omitempty"`
	CVSS             float64         `json:"cvss,omitempty"`
	KEV              bool            `json:"kev"`
	EPSS             float64         `json:"epss,omitempty"`
	Exposure         string          `json:"exposure"`
	ExposureEvidence []string        `json:"exposure_evidence,omitempty"`
	FixedIn          string          `json:"fixed_in,omitempty"`
	AdvisoryURL      string          `json:"advisory_url,omitempty"`
	FindingURL       string          `json:"finding_url,omitempty"`
	Priority         policy.Priority `json:"priority"`
	PriorityReason   string          `json:"priority_reason,omitempty"`
	MatchState       string          `json:"match_state"`
	// Image marks a package of a container's image: a newer image fixes
	// it (ADR 0033).
	Image bool `json:"image,omitempty"`
	// PathClass and PathReason relate the finding to the attack paths
	// (ADR 0034).
	PathClass  string `json:"path_class,omitempty"`
	PathReason string `json:"path_reason,omitempty"`
}

// Notice is a system notice in a digest: a blind spot such as a host that
// stopped reporting, not a vulnerability.
type Notice struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// Message is what channels deliver.
type Message struct {
	Kind     string          `json:"kind"`
	Priority policy.Priority `json:"priority,omitempty"`
	Title    string          `json:"title"`
	Body     string          `json:"text"`
	Items    []Item          `json:"items,omitempty"`
	Notices  []Notice        `json:"notices,omitempty"`
}

// FindingIDs returns the IDs of the message's items.
func (m Message) FindingIDs() []string {
	ids := make([]string, 0, len(m.Items))
	for _, it := range m.Items {
		ids = append(ids, it.FindingID)
	}
	return ids
}

const prefix = "[" + buildinfo.ID + "]"

// Immediate renders an urgent message for P1 items.
func Immediate(items []Item) Message {
	sortItems(items)
	var title string
	if len(items) == 1 {
		it := items[0]
		title = fmt.Sprintf("%s P1 %s: %s", prefix, it.AppName, headline(it))
	} else {
		title = fmt.Sprintf("%s P1: %s", prefix, updatesAndFindings(items, "urgent update"))
	}
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteString("\n")
		}
		writeItem(&b, it, true)
	}
	return Message{Kind: KindImmediate, Priority: policy.P1, Title: oneLine(title), Body: b.String(), Items: items}
}

// Digest renders a digest; attention lists unverified findings of public
// apps, notices the blind spots found since the last digest (shown first).
// It returns false when there is nothing to send.
func Digest(kind string, items, attention []Item, notices []Notice, resolved []Item) (Message, bool) {
	if len(items) == 0 && len(attention) == 0 && len(notices) == 0 && len(resolved) == 0 {
		return Message{}, false
	}
	sortItems(items)
	sortItems(attention)
	sortItems(resolved)
	period := "Daily"
	if kind == KindDigestWeekly {
		period = "Weekly"
	}
	title := fmt.Sprintf("%s %s digest: %s", prefix, period, updatesAndFindings(items, "update"))
	if len(attention) > 0 {
		title += fmt.Sprintf(", %d need attention", len(attention))
	}
	if len(notices) > 0 {
		title += ", " + plural(len(notices), "blind spot")
	}
	if len(resolved) > 0 {
		title += fmt.Sprintf(", %d resolved", len(resolved))
	}
	var b strings.Builder
	if len(notices) > 0 {
		b.WriteString("Blind spots: Varde cannot check these\n\n")
		for _, n := range notices {
			fmt.Fprintf(&b, "- %s\n", clean(n.Title, 200))
			if n.Detail != "" {
				fmt.Fprintf(&b, "  %s\n", clean(n.Detail, 400))
			}
		}
		b.WriteString("\n")
	}
	var current policy.Priority = "-"
	for _, g := range groupItems(items) {
		if g[0].Priority != current {
			current = g[0].Priority
			fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(string(current)+" "+priorityLabel(current)))
		}
		if len(g) == 1 {
			writeItem(&b, g[0], false)
		} else {
			writeGroup(&b, g)
		}
		b.WriteString("\n")
	}
	if len(resolved) > 0 {
		b.WriteString("Resolved since the last weekly digest\n\n")
		for _, it := range resolved {
			fmt.Fprintf(&b, "- %s (%s): %s\n", it.AppName, it.WorkloadName, it.AdvisoryID)
		}
		b.WriteString("\n")
	}
	if len(attention) > 0 {
		b.WriteString("Needs attention: version unknown or not comparable on publicly exposed apps\n\n")
		for _, it := range attention {
			fmt.Fprintf(&b, "- %s (%s): %s %s\n", it.AppName, it.WorkloadName, it.AdvisoryID, clean(it.Summary, 120))
			b.WriteString("  Set the label varde.version on the container so Varde can check it.\n")
		}
	}
	all := append(append([]Item(nil), items...), attention...)
	p := policy.P3
	if kind == KindDigestDaily {
		p = policy.P2
	}
	return Message{Kind: kind, Priority: p, Title: oneLine(title), Body: strings.TrimRight(b.String(), "\n") + "\n", Items: all, Notices: notices}, true
}

// Test renders a test message.
func Test() Message {
	return Message{
		Kind:  KindTest,
		Title: prefix + " Test notification",
		Body:  "This is a test notification. If you can read it, this channel is configured correctly.\n",
	}
}

func writeItem(b *strings.Builder, it Item, verbose bool) {
	b.WriteString(subject(it))
	ids := append([]string{it.AdvisoryID}, it.Aliases...)
	fmt.Fprintf(b, "%s: %s\n", strings.Join(ids, " / "), clean(it.Summary, 200))
	fmt.Fprintf(b, "Severity: %s\n", severityLine(it))
	if verbose || it.Exposure == "public" {
		exp := it.Exposure
		if len(it.ExposureEvidence) > 0 {
			exp += " (" + clean(strings.Join(it.ExposureEvidence, "; "), 200) + ")"
		}
		fmt.Fprintf(b, "Exposure: %s\n", exp)
	}
	if it.PathReason != "" && (verbose || it.PathClass == "path-internet" || it.PathClass == "path-lan" || it.PathClass == "amplifier") {
		fmt.Fprintf(b, "Attack path: %s\n", clean(it.PathReason, 200))
	}
	switch {
	case it.FixedIn != "" && it.Image:
		fmt.Fprintf(b, "Action: pull a newer image whose %s is %s or later and recreate the container\n", clean(packageName(it), 128), clean(it.FixedIn, 64))
	case it.FixedIn != "":
		fmt.Fprintf(b, "Action: update to %s or later\n", clean(it.FixedIn, 64))
	default:
		b.WriteString("Action: no fixed version published yet; restrict access until one is available\n")
	}
	if it.AdvisoryURL != "" {
		fmt.Fprintf(b, "Advisory: %s\n", clean(it.AdvisoryURL, 300))
	}
	if it.FindingURL != "" {
		fmt.Fprintf(b, "Details: %s\n", it.FindingURL)
	}
}

func headline(it Item) string {
	s := it.AdvisoryID
	for _, a := range it.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			s = a
			break
		}
	}
	if it.FixedIn != "" {
		return s + ", update to " + it.FixedIn
	}
	return s
}

func severityLine(it Item) string {
	var parts []string
	switch {
	case it.Severity != "" && it.CVSS > 0:
		parts = append(parts, fmt.Sprintf("%s (CVSS %.1f)", it.Severity, it.CVSS))
	case it.CVSS > 0:
		parts = append(parts, fmt.Sprintf("CVSS %.1f", it.CVSS))
	case it.Severity != "":
		parts = append(parts, it.Severity)
	default:
		parts = append(parts, "not rated")
	}
	if it.KEV {
		parts = append(parts, "known exploited (CISA KEV)")
	}
	if it.EPSS >= 0.01 {
		parts = append(parts, fmt.Sprintf("EPSS %.2f", it.EPSS))
	}
	return strings.Join(parts, ", ")
}

func priorityLabel(p policy.Priority) string {
	switch p {
	case policy.P1:
		return "urgent"
	case policy.P2:
		return "important"
	case policy.P3:
		return "low"
	}
	return ""
}

func sortItems(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Priority.Rank() != b.Priority.Rank() {
			return a.Priority.Rank() > b.Priority.Rank()
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.AppName != b.AppName {
			return a.AppName < b.AppName
		}
		return a.AdvisoryID < b.AdvisoryID
	})
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// clean makes upstream-controlled text safe for plain-text channels and
// mail headers: control characters become spaces, whitespace collapses,
// length is bounded.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}

func oneLine(s string) string { return clean(s, 200) }

// groupItems groups the findings of one app or package in one version on
// one workload within a priority, as the UI does: one update closes them
// together. Order follows the first finding of each group.
func groupItems(items []Item) [][]Item {
	index := map[string]int{}
	var out [][]Item
	for _, it := range items {
		key := string(it.Priority) + "\x00" + it.AppID + "\x00" + it.Version + "\x00" + it.WorkloadName + "\x00" + it.HostName
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], it)
	}
	return out
}

// updates counts the things to do behind items: one container or app on a
// machine, or the system packages of a machine. It is how many updates the
// reader has to install, not how many advisories there are.
func updates(items []Item) int {
	seen := map[string]bool{}
	for _, it := range items {
		key := it.WorkloadName + "\x00" + it.HostName
		if strings.HasPrefix(it.AppID, "os:") {
			key = "os\x00" + it.HostName
		}
		seen[key] = true
	}
	return len(seen)
}

// updatesAndFindings says "3 updates (41 findings)", or only the updates
// when each fixes one finding.
func updatesAndFindings(items []Item, noun string) string {
	n := updates(items)
	if n == len(items) {
		return plural(n, noun)
	}
	return plural(n, noun) + " (" + plural(len(items), "finding") + ")"
}

// groupShown is how many advisories a group names before "and N more".
const groupShown = 5

// writeGroup renders several findings of one app or package in one block:
// what runs where, the advisories, the worst severity, and the update.
func writeGroup(b *strings.Builder, g []Item) {
	first := g[0]
	b.WriteString(subject(first))
	var ids []string
	kev, cvss, epss := 0, 0.0, 0.0
	for _, it := range g {
		id := it.AdvisoryID
		for _, a := range it.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				id = a
				break
			}
		}
		if it.KEV {
			kev++
			id += " (known exploited)"
		}
		ids = append(ids, clean(id, 64))
		cvss, epss = max(cvss, it.CVSS), max(epss, it.EPSS)
	}
	// Known exploited ones first, then the order of the findings.
	sort.SliceStable(ids, func(i, j int) bool {
		return strings.HasSuffix(ids[i], "(known exploited)") && !strings.HasSuffix(ids[j], "(known exploited)")
	})
	shown := ids
	if len(shown) > groupShown {
		shown = append(append([]string(nil), ids[:groupShown]...), fmt.Sprintf("and %d more", len(ids)-groupShown))
	}
	fmt.Fprintf(b, "%d advisories: %s\n", len(g), strings.Join(shown, ", "))
	var sev []string
	if cvss > 0 {
		sev = append(sev, fmt.Sprintf("highest CVSS %.1f", cvss))
	} else {
		sev = append(sev, "not rated")
	}
	if kev > 0 {
		sev = append(sev, plural(kev, "known exploited (CISA KEV)"))
	}
	if epss >= 0.01 {
		sev = append(sev, fmt.Sprintf("EPSS up to %.2f", epss))
	}
	fmt.Fprintf(b, "Severity: %s\n", strings.Join(sev, ", "))
	if first.Exposure == "public" {
		fmt.Fprintf(b, "Exposure: public\n")
	}
	switch fixes, target := groupTarget(g); {
	case target != "" && first.Image:
		fmt.Fprintf(b, "Action: pull a newer image whose %s is %s or later and recreate the container; it fixes %d of %d\n", clean(packageName(first), 128), clean(target, 64), fixes, len(g))
	case target != "" && fixes == len(g):
		fmt.Fprintf(b, "Action: update to %s or later; it fixes all %d\n", clean(target, 64), len(g))
	case target != "":
		fmt.Fprintf(b, "Action: update to %s or later; it fixes %d of %d, the rest have no fix yet\n", clean(target, 64), fixes, len(g))
	default:
		b.WriteString("Action: no fixed version published yet; restrict access until one is available\n")
	}
	if u := groupURL(first); u != "" {
		fmt.Fprintf(b, "Details: %s\n", u)
	}
}

// groupTarget is the update that fixes the most findings of a group: for a
// distribution package the newest fixed version in the package manager's
// order, otherwise the fixed version all findings share, if any.
func groupTarget(g []Item) (fixes int, target string) {
	eco, _, system := distro.ParseSystemAppID(g[0].AppID)
	for _, it := range g {
		if it.FixedIn == "" {
			continue
		}
		fixes++
		switch {
		case target == "":
			target = it.FixedIn
		case system:
			if c, ok := distro.Compare(eco, it.FixedIn, target); ok && c > 0 {
				target = it.FixedIn
			}
		case it.FixedIn != target:
			// Versions of different schemes cannot be ordered here; the
			// UI names the update.
			return fixes, ""
		}
	}
	return fixes, target
}

// groupURL links a group's findings: the findings page filtered to its app.
func groupURL(it Item) string {
	i := strings.Index(it.FindingURL, "/findings/")
	if i < 0 {
		return ""
	}
	return it.FindingURL[:i] + "/findings?app=" + url.QueryEscape(it.AppID)
}

// subject is the first line of a finding: what runs where, in which
// version. A system package is its own workload, so it is named once.
func subject(it Item) string {
	version := it.Version
	if version == "" {
		version = "unknown version"
	}
	if strings.HasPrefix(it.AppID, distro.SystemPrefix) && it.Image {
		on := ""
		if it.HostName != "" {
			on = " on " + clean(it.HostName, 64)
		}
		return fmt.Sprintf("%s in the image of %s%s, version %s\n", clean(it.AppName, 64), clean(it.WorkloadName, 64), on, clean(version, 64))
	}
	if strings.HasPrefix(it.AppID, distro.SystemPrefix) {
		on := ""
		if it.HostName != "" {
			on = " on " + clean(it.HostName, 64)
		}
		return fmt.Sprintf("%s%s, installed %s\n", clean(it.AppName, 64), on, clean(version, 64))
	}
	where := it.WorkloadName
	if it.HostName != "" {
		where += " on " + clean(it.HostName, 64)
	}
	return fmt.Sprintf("%s (%s), running %s\n", clean(it.AppName, 64), clean(where, 128), clean(version, 64))
}

// packageName is the bare name of the package or module an item's fixed
// version belongs to: the version of a package of an image is the
// package's, not the image's.
func packageName(it Item) string {
	if _, name, ok := distro.ParseSystemAppID(it.AppID); ok {
		if name == "stdlib" {
			return "Go standard library"
		}
		return name
	}
	return it.AppName
}
