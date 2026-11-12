// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/store"
)

// pathRank orders the path classes, most urgent first.
var pathRank = map[string]int{"path-internet": 0, "path-lan": 1, "amplifier": 2, "unclear": 3, "": 3, "noise": 4}

// onPath reports whether a class puts a finding on an attack path.
func onPath(class string) bool {
	return class == string(paths.OnPathInternet) || class == string(paths.OnPathLAN) || class == string(paths.Amplifier)
}

// pathFilter reports whether a finding's class matches the filter value:
// "path" for every class on a path, else the class itself.
func pathFilter(filter, class string) bool {
	switch filter {
	case "":
		return true
	case "path":
		return onPath(class)
	case "unclear":
		return class == "unclear" || class == ""
	}
	return class == filter
}

type pathStep struct {
	paths.Step
	// Finding is the advisory behind the step, for the link.
	Advisory, Priority string
}

type pathCard struct {
	paths.Path
	Steps []pathStep
	// Open counts the findings on the path still open.
	Open int
	// Same are further paths that start with the same way in and are cut
	// by the same fix: they are listed with this one instead of repeating
	// it line by line.
	Same []pathCard
}

// Targets names what the card's paths end on.
func (c pathCard) Targets() []string {
	out := []string{c.Name()}
	for _, o := range c.Same {
		out = append(out, o.Name())
	}
	return out
}

// Name is what the path ends on; a path stored before paths had a subject
// is named by its impact.
func (c pathCard) Name() string {
	if c.Subject != "" {
		return c.Subject
	}
	return c.Impact
}

// MaxSteps is the longest of the card's paths.
func (c pathCard) MaxSteps() int {
	n := len(c.Steps)
	for _, o := range c.Same {
		n = max(n, len(o.Steps))
	}
	return n
}

// groupPaths puts paths with one way in and one fix on one card, in the
// order of the first of each group (the most dangerous first).
func groupPaths(cards []pathCard) []pathCard {
	var out []pathCard
	at := map[string]int{}
	for _, c := range cards {
		key := c.Breaker + "\x00" + c.Cut + "\x00" + c.Gain
		if i, ok := at[key]; ok && c.Breaker != "" {
			out[i].Same = append(out[i].Same, c)
			continue
		}
		at[key] = len(out)
		out = append(out, c)
	}
	return out
}

type pathsData struct {
	Internet, LAN []pathCard
	// InternetCount and LANCount are all paths per entry.
	InternetCount, LANCount int
	// Count is all paths, Shown the paths listed.
	Count, Shown int
	// Machines counts the machines an attacker can reach root on.
	Root int
	// Noise and Unclear count the findings in those classes.
	Noise, Unclear, OnPath int
}

// pathsShown bounds the paths listed per entry: the top ones matter.
const pathsShown = 25

func (a *app) attackPaths(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	ps, err := a.d.Store.Paths(ctx)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	fs, err := a.d.Store.Findings(ctx, store.FindingFilter{})
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	byID := make(map[string]store.Finding, len(fs))
	d := pathsData{Count: len(ps)}
	for _, f := range fs {
		byID[f.ID] = f
		if !active(f.State) {
			continue
		}
		switch {
		case onPath(f.PathClass):
			d.OnPath++
		case f.PathClass == string(paths.Noise):
			d.Noise++
		default:
			d.Unclear++
		}
	}
	root := map[string]bool{}
	for _, p := range ps {
		card := pathCard{Path: p}
		for _, s := range p.Steps {
			st := pathStep{Step: s}
			if f, ok := byID[s.FindingID]; ok {
				st.Advisory, st.Priority = f.AdvisoryID, f.Priority
				if active(f.State) {
					card.Open++
				}
			}
			card.Steps = append(card.Steps, st)
		}
		if strings.HasPrefix(p.Impact, "root ") {
			root[p.Target] = true
		}
		switch p.Entry {
		case paths.Internet:
			d.InternetCount++
			if len(d.Internet) < pathsShown {
				d.Internet = append(d.Internet, card)
			}
		case paths.LAN:
			d.LANCount++
			if len(d.LAN) < pathsShown {
				d.LAN = append(d.LAN, card)
			}
		}
	}
	d.Shown = len(d.Internet) + len(d.LAN)
	d.Internet, d.LAN = groupPaths(d.Internet), groupPaths(d.LAN)
	d.Root = len(root)
	a.page(w, r, cur, http.StatusOK, "paths", view{Title: "Attack paths", Nav: "findings", Tabs: tabs("findings", "/findings/paths"), Data: d})
}

type noiseGroup struct {
	Reason string
	Rows   []findingRow
}

func (a *app) noise(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	s, err := a.load(r.Context(), false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	byReason := map[string]*noiseGroup{}
	var groups []*noiseGroup
	total := 0
	for _, f := range s.findings {
		if !active(f.State) || f.PathClass != string(paths.Noise) {
			continue
		}
		g, ok := byReason[f.PathReason]
		if !ok {
			g = &noiseGroup{Reason: f.PathReason}
			byReason[f.PathReason] = g
			groups = append(groups, g)
		}
		g.Rows = append(g.Rows, a.row(s, f))
		total++
	}
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i].Rows) > len(groups[j].Rows) })
	for _, g := range groups {
		sortRows(g.Rows)
	}
	a.page(w, r, cur, http.StatusOK, "noise", view{Title: "Background noise", Nav: "findings", Tabs: tabs("findings", "/findings/noise"), Data: struct {
		Groups []*noiseGroup
		Count  int
	}{groups, total}})
}

// findingPaths are the stored paths that use a finding, at most a few.
func (a *app) findingPaths(r *http.Request, id string) []paths.Path {
	ps, err := a.d.Store.Paths(r.Context())
	if err != nil {
		return nil
	}
	var out []paths.Path
	for _, p := range ps {
		if slices.Contains(p.Findings, id) {
			out = append(out, p)
			if len(out) == 5 {
				break
			}
		}
	}
	return out
}
