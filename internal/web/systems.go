// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/remedy"
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
	// Device is the scanned device behind the machine, when there is one.
	Device *deviceView
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
	v := systemView{Machine: *m, Query: strings.TrimSpace(r.URL.Query().Get("q")), AppNames: map[string]string{}, Updates: map[string]int{}, Unfixed: map[string]int{}}
	for _, c := range s.machines {
		if c.ParentID == m.ID {
			v.Children = append(v.Children, c)
		}
	}
	hosts := map[string]bool{}
	for _, h := range m.HostIDs {
		hosts[h] = true
	}
	// Checked only when security data covers the release of this
	// system's packages.
	var own []inventory.Workload
	for _, wl := range s.system {
		if hosts[wl.HostID] {
			own = append(own, wl)
		}
	}
	v.Checked = a.systemPackagesCovered(own) > 0
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
		if actionable(f.State) && f.MatchState == string(match.Affected) {
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
	if d, shared, ok := a.scannedDevice(s, m); ok {
		v.Device = newDeviceView(d, shared, m.Level)
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
	fix, err := a.hostFix(ctx, s, *m)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.page(w, r, cur, http.StatusOK, "system", view{Title: m.Name, Nav: "systems", Tabs: tabs("systems", "/systems"), Data: struct {
		systemView
		Total int
		ToDo  []appCard
		Fix   *hostFix
	}{v, total, updates, fix}})
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

// hostFix is how to install the security updates a system's packages wait
// for: the command for a shell on the system, and for an LXC container the
// same from its Proxmox node.
type hostFix struct {
	// Command runs on the system through sudo; Guest runs it from Node.
	Command, Guest, Node string
	// Packages are the installed packages the command upgrades, Flaws the
	// flaws their updates fix.
	Packages []string
	Flaws    int
	// Kernel is set when the kernel is among them: it takes effect after
	// a restart.
	Kernel bool
	// Host and Address are the machine, WebSSH the user's WebSSH.
	Host, Address, WebSSH string
}

// lxcGuestID reads the VMID of a Proxmox guest record ("pve-3-105").
var lxcGuestID = regexp.MustCompile(`^pve-[^-]+-(\d{1,9})$`)

// hostFix builds the command that installs exactly the updates the flaws
// of the system packages on hosts need: the installed packages built from
// each affected source package, and for a kernel the metapackage that
// brings the new one. Nil when no flaw has a fix or Varde does not know the
// package manager.
func (a *app) hostFix(ctx context.Context, s *snapshot, m coverage.Machine) (*hostFix, error) {
	hosts := map[string]bool{}
	for _, h := range m.HostIDs {
		hosts[h] = true
	}
	affected := map[string]bool{}
	f := &hostFix{Host: m.Name, WebSSH: a.d.Settings.Get().WebSSHURL}
	if len(m.Addresses) > 0 {
		f.Address = m.Addresses[0]
	}
	for _, fd := range s.findings {
		w := s.byID[fd.WorkloadID]
		if !actionable(fd.State) || fd.MatchState != string(match.Affected) || fd.FixedIn == "" || !identify.IsSystem(w) || !hosts[w.HostID] {
			continue
		}
		eco, name, ok := distro.ParseSystemAppID(fd.AppID)
		if !ok {
			continue
		}
		affected[name] = true
		f.Flaws++
		f.Kernel = f.Kernel || distro.Kernel(eco, name)
	}
	if len(affected) == 0 {
		return nil, nil
	}
	release, guest := "", 0
	for _, h := range m.HostIDs {
		pk, ok, err := a.d.Store.HostPackageList(ctx, h)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		release = pk.Distro
		for _, p := range pk.Packages {
			src := p.Source
			if src == "" {
				src = p.Name
			}
			if affected[src] || affected[p.Name] || f.Kernel && kernelImage(p.Name) {
				f.Packages = append(f.Packages, p.Name)
			}
		}
		if host, err := a.d.Store.Host(ctx, h); err == nil && host.Kind == inventory.HostProxmoxGuest && strings.Contains(strings.ToLower(host.OS), "lxc") {
			if mm := lxcGuestID.FindStringSubmatch(host.ID); mm != nil {
				guest, _ = strconv.Atoi(mm[1])
				if node, err := a.d.Store.Host(ctx, host.ParentID); err == nil {
					f.Node = node.Name
				}
			}
		}
	}
	cmd := remedy.PackageCommand(release, f.Packages)
	if cmd == "" {
		return nil, nil
	}
	f.Command = remedy.AsRoot(cmd)
	if guest > 0 && f.Node != "" {
		f.Guest = remedy.InLXC(guest, cmd)
	}
	sort.Strings(f.Packages)
	return f, nil
}

// kernelImage reports whether a package is a kernel image of a Debian or
// Ubuntu system: the kernel of one version ("linux-image-6.1.0-18-amd64",
// built from linux-signed-amd64, not from "linux") and the metapackage that
// brings the newest one ("linux-image-amd64"). Upgrading them installs the
// fixed kernel; a package without an update is left as it is.
func kernelImage(name string) bool {
	rest, ok := strings.CutPrefix(name, "linux-image-")
	return ok && rest != ""
}
