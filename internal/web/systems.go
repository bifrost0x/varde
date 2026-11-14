// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
)

// systemView is one machine with everything Varde knows about it: where it
// knows it from, what is installed (apps, containers, every package), what
// is affected and what Varde cannot see yet.
type systemView struct {
	Machine  coverage.Machine
	Children []coverage.Machine
	Apps     []workloadRow
	// Containers are all containers, identified or not.
	Containers []workloadRow
	// Packages is the full package list of the machine's host records.
	Packages    []inventory.Package
	PackageOS   string
	PackageRead time.Time
	Query       string
	Shown       int
	Findings    []store.Finding
	// AppNames names the apps and system packages of the findings.
	AppNames map[string]string
	// Updates counts the open findings an update fixes, per source
	// package, for the package list.
	Updates map[string]int
	// Checked reports whether the system packages are checked (ADR 0032).
	Checked bool
	// Kernel is the running kernel; Reboot why the system needs a restart.
	Kernel, Reboot string
	// Unfixed counts the distribution's open issues no update fixes yet,
	// per source package, and in all; they are not findings.
	Unfixed      map[string]int
	UnfixedTotal int
	// Blind says what Varde cannot read on this machine, with the step.
	Blind []blindSpot
}

type blindSpot struct{ Text, Link, Action string }

// packageLimit bounds the rows rendered at once; the filter narrows them.
const packageLimit = 500

func (a *app) system(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	s, err := a.load(ctx, false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	id := r.PathValue("id")
	var m *coverage.Machine
	for i := range s.machines {
		if s.machines[i].ID == id {
			m = &s.machines[i]
		}
	}
	if m == nil {
		if hm := s.hostOf[id]; hm != nil {
			http.Redirect(w, r, "/systems/"+hm.ID, http.StatusSeeOther)
			return
		}
		a.renderError(w, r, cur, http.StatusNotFound, "System not found", "It may have been removed, or merged with another one.")
		return
	}
	v := systemView{Machine: *m, Query: strings.TrimSpace(r.URL.Query().Get("q")), AppNames: map[string]string{}, Updates: map[string]int{}, Unfixed: map[string]int{},
		Checked: a.d.Settings.Get().DirectOSV}
	for _, c := range s.machines {
		if c.ParentID == m.ID {
			v.Children = append(v.Children, c)
		}
	}
	hosts := map[string]bool{}
	for _, h := range m.HostIDs {
		hosts[h] = true
	}
	eol, err := a.d.Store.EOL(ctx)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	open := map[string]int{}
	for _, f := range s.findings {
		if !hosts[s.byID[f.WorkloadID].HostID] || f.State == store.StateResolved {
			continue
		}
		v.Findings = append(v.Findings, f)
		v.AppNames[f.AppID] = a.appName(f.AppID)
		if status.Active(f.State) && f.MatchState == string(match.Affected) {
			open[f.WorkloadID]++
			if w := s.byID[f.WorkloadID]; identify.IsSystem(w) {
				v.Updates[w.Name]++
			}
		}
	}
	sort.SliceStable(v.Findings, func(i, j int) bool { return v.Findings[i].Priority < v.Findings[j].Priority })
	for _, wl := range s.system {
		if n := s.ids[wl.ID].Unfixed; hosts[wl.HostID] && n > 0 && v.Checked {
			v.Unfixed[wl.Name] += n
			v.UnfixedTotal += n
		}
	}
	for _, wl := range s.workloads {
		if !hosts[wl.HostID] {
			continue
		}
		row := a.workloadRow(s, wl, open, eol)
		if wl.Container != nil {
			v.Containers = append(v.Containers, row)
		}
		if row.AppID != "" {
			v.Apps = append(v.Apps, row)
		}
	}
	for _, h := range m.HostIDs {
		pk, ok, err := a.d.Store.HostPackageList(ctx, h)
		if err != nil {
			a.fail(w, r, cur, err)
			return
		}
		if ok {
			v.Packages, v.PackageOS, v.PackageRead = append(v.Packages, pk.Packages...), pk.OS, pk.Read
			if pk.Kernel != "" {
				v.Kernel = pk.Kernel
			}
			if pk.Reboot != "" {
				v.Reboot = pk.Reboot
			}
		}
	}
	sort.Slice(v.Packages, func(i, j int) bool { return v.Packages[i].Name < v.Packages[j].Name })
	total := len(v.Packages)
	if v.Query != "" {
		q := strings.ToLower(v.Query)
		kept := v.Packages[:0]
		for _, p := range v.Packages {
			if strings.Contains(strings.ToLower(p.Name), q) || strings.Contains(strings.ToLower(p.Source), q) {
				kept = append(kept, p)
			}
		}
		v.Packages = kept
	}
	if len(v.Packages) > packageLimit {
		v.Packages = v.Packages[:packageLimit]
	}
	v.Shown = len(v.Packages)
	nodeKey := false
	for _, in := range s.integrations {
		for _, ad := range m.Addresses {
			nodeKey = nodeKey || (in.Kind == "proxmox-lxc" && in.Address == ad)
		}
	}
	v.Blind = blindSpots(m, total, len(v.Containers), nodeKey, a.agentInstallReady())
	// What needs doing on this machine, as on the front page: one row
	// per app with its update, not one per advisory.
	var updates []appCard
	for _, c := range a.appCards(s) {
		host := s.byID[c.Key].HostID
		if h, ok := strings.CutPrefix(c.Key, "h:"); ok {
			host = h
		}
		if on := s.hostOf[host]; on == nil || on.ID != m.ID {
			continue
		}
		switch c.State {
		case appNow, appSoon, appLater, appCheck:
			updates = append(updates, c)
		}
	}
	a.page(w, r, cur, http.StatusOK, "system", view{Title: m.Name, Nav: "systems", Tabs: tabs("systems", "/systems"), Data: struct {
		systemView
		Total int
		ToDo  []appCard
	}{v, total, updates}})
}

// blindSpots says what Varde does not read on a machine and how to change
// that.
func blindSpots(m *coverage.Machine, packages, containers int, nodeKey, agentInstall bool) []blindSpot {
	var out []blindSpot
	addr := ""
	if len(m.Addresses) > 0 {
		addr = m.Addresses[0]
	}
	for _, e := range m.Evidence {
		if strings.Contains(e.Detail, "guest agent does not answer") {
			out = append(out, blindSpot{Text: "The QEMU guest agent of this VM does not answer, so Varde reads nothing inside it. Install qemu-guest-agent in the VM and enable \"QEMU Guest Agent\" in its Proxmox options."})
		}
	}
	switch {
	case m.Kind == "bare-metal" && m.Has(coverage.EvidenceProxmox) && !nodeKey:
		out = append(out, blindSpot{Text: "The guests of this node are seen from the outside only. One key on the node reads the packages and Docker containers of every LXC container and every VM with guest agent.", Link: "/connections/connect/proxmox-lxc?address=" + addr, Action: "Read all guests of this node"})
	case packages == 0 && containers == 0 && m.IsHost() && agentInstall:
		out = append(out, blindSpot{Text: "Varde knows this machine exists but not what is installed on it. The agent reports every package and Docker container; Varde installs it with one SSH sign-in.", Link: "/connections/agents/install?address=" + addr, Action: "Install the agent"})
	case packages == 0 && containers == 0 && m.IsHost():
		out = append(out, blindSpot{Text: "Varde knows this machine exists but not what is installed on it.", Link: "/connections/connect/packages?address=" + addr, Action: "Read its packages over SSH"})
	}
	return out
}
