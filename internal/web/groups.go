// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"sort"

	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// findingGroup is every finding of one app in one running version: one
// update closes them together, so the UI shows one row per group instead of
// one per advisory.
type findingGroup struct {
	AppID, AppName, Version string
	Workloads               []string
	// Priority is the highest confirmed priority, empty when every finding
	// of the group still needs a check.
	Priority string
	KEV      bool
	Exposure string
	CVSS     float64
	// New counts findings nobody has acknowledged or snoozed yet.
	New, Acknowledged, Unverified int
	Target                        *match.Target
	Rows                          []findingRow
	// Image marks a package of container images: a newer image fixes it,
	// not a package update on the host (ADR 0033).
	Image bool
	// Package is the package or module the fixed version belongs to, for
	// the action of an image: the version is the package's, not the
	// image's.
	Package string
	// PathClass is the most urgent relation of its findings to the attack
	// paths (ADR 0034).
	PathClass string
}

// Key identifies the group in URLs and form fields.
func (g findingGroup) Key() string { return g.AppID + "@" + g.Version }

var exposureRank = map[string]int{"public": 0, "lan": 1, "unknown": 2, "": 2, "internal": 3}

var priorityRank = map[string]int{"P1": 0, "P2": 1, "P3": 2, "": 3}

// groupFindings groups findings by app and running version. Advisories that
// apply to several workloads of the same group are listed once.
func (a *app) groupFindings(s *snapshot, fs []store.Finding) []findingGroup {
	index := map[string]int{}
	var groups []findingGroup
	seenAdv := map[string]map[string]bool{}
	seenWl := map[string]map[string]bool{}
	for _, f := range fs {
		var m match.Finding
		_ = json.Unmarshal(f.Detail, &m)
		key := f.AppID + "@" + m.Evidence.Version
		i, ok := index[key]
		if !ok {
			i = len(groups)
			index[key] = i
			groups = append(groups, findingGroup{AppID: f.AppID, AppName: a.appName(f.AppID), Package: imagePackageName(f.AppID), Version: m.Evidence.Version, Exposure: f.Exposure})
			seenAdv[key], seenWl[key] = map[string]bool{}, map[string]bool{}
		}
		g := &groups[i]
		if name := s.byID[f.WorkloadID].Name; !seenWl[key][f.WorkloadID] {
			seenWl[key][f.WorkloadID] = true
			g.Workloads = append(g.Workloads, name)
		}
		if exposureRank[f.Exposure] < exposureRank[g.Exposure] {
			g.Exposure = f.Exposure
		}
		if m.Target != nil && g.Target == nil {
			g.Target = m.Target
		}
		g.Image = g.Image || m.Image
		if seenAdv[key][f.AdvisoryID] {
			continue
		}
		seenAdv[key][f.AdvisoryID] = true
		row := a.row(s, f)
		g.Rows = append(g.Rows, row)
		switch {
		case f.MatchState == string(match.Unverified):
			g.Unverified++
		case g.Priority == "" || priorityRank[f.Priority] < priorityRank[g.Priority]:
			g.Priority = f.Priority
		}
		if f.State == store.StateOpen {
			g.New++
		} else if active(f.State) {
			g.Acknowledged++
		}
		g.KEV = g.KEV || row.KEV
		if f.MatchState != string(match.Unverified) && (g.PathClass == "" || pathRank[f.PathClass] < pathRank[g.PathClass]) {
			g.PathClass = f.PathClass
		}
		if f.MatchState != string(match.Unverified) && row.CVSS > g.CVSS {
			g.CVSS = row.CVSS
		}
	}
	for i := range groups {
		sortRows(groups[i].Rows)
		sort.Strings(groups[i].Workloads)
		if groups[i].Target == nil {
			groups[i].Target = distroTarget(groups[i], ecosystemOf(s, fs, groups[i].AppID))
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if priorityRank[a.Priority] != priorityRank[b.Priority] {
			return priorityRank[a.Priority] < priorityRank[b.Priority]
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.AppName != b.AppName {
			return a.AppName < b.AppName
		}
		return a.Version < b.Version
	})
	return groups
}

// ecosystemOf is the distribution ecosystem of a group's package: from a
// system package's app ID, else from the package of one of its workloads.
func ecosystemOf(s *snapshot, fs []store.Finding, appID string) string {
	if eco, _, ok := distro.ParseSystemAppID(appID); ok {
		return eco
	}
	for _, f := range fs {
		if f.AppID != appID {
			continue
		}
		if p := s.byID[f.WorkloadID].Package; p != nil {
			if eco, _, ok := distro.Ecosystem(p.Distro); ok {
				return eco
			}
		}
	}
	return ""
}

// distroTarget is the update for a distribution package: the newest fixed
// version among its confirmed findings, which fixes every one with a
// fixed version. Distribution versions are compared in the package
// manager's order; nil when the group is no distribution package.
func distroTarget(g findingGroup, ecosystem string) *match.Target {
	if ecosystem == "" {
		return nil
	}
	t := &match.Target{}
	for _, r := range g.Rows {
		if r.MatchState != string(match.Affected) {
			continue
		}
		t.Total++
		if r.FixedIn == "" {
			continue
		}
		t.Fixes++
		if c, ok := distro.Compare(ecosystem, r.FixedIn, t.Version); t.Version == "" || (ok && c > 0) {
			t.Version = r.FixedIn
		}
	}
	if t.Total == 0 {
		return nil
	}
	return t
}

// imagePackageName is the bare name of a package or module of an image
// ("github.com/andybalholm/brotli", "openssl"), empty for an app.
func imagePackageName(appID string) string {
	_, name, ok := distro.ParseSystemAppID(appID)
	if !ok {
		return ""
	}
	if name == "stdlib" {
		return "Go standard library"
	}
	return name
}
