// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
)

// enrollmentLifetime is how long an enrollment token can be used.
const enrollmentLifetime = time.Hour

// systemRow is one machine in the systems list: what is installed on it,
// what is affected, and where Varde knows it from.
type systemRow struct {
	Machine coverage.Machine
	// Guest is set for a machine that runs on another one in the list.
	Guest                  bool
	Packages, Containers   int
	Apps                   int
	P1, P2, P3, Unverified int
	// Reboot says why the system needs a restart for its updates to take
	// effect; empty when it does not.
	Reboot string
}

// Read reports whether Varde knows what is installed on the machine.
func (r systemRow) Read() bool { return r.Packages > 0 || r.Containers > 0 || r.Apps > 0 }

// Open is the number of open findings.
func (r systemRow) Open() int { return r.P1 + r.P2 + r.P3 + r.Unverified }

type systemsView struct {
	Systems []systemRow
	Counts  coverage.MachineCounts
	// Read is the number of systems Varde knows the installed software of.
	Read    int
	Notices []store.Notice
}

// systems lists every machine: what is installed, what is critical, where
// the information comes from. Guests follow their node.
func (a *app) systems(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	s, err := a.load(ctx, false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	v := systemsView{Counts: coverage.CountMachines(s.machines)}
	if v.Systems, err = a.systemRows(ctx, s); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	v.Read = readSystems(v.Systems)
	notices, err := a.d.Store.ActiveNotices(ctx)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	for _, n := range notices {
		if n.Kind == store.NoticeHostStale {
			v.Notices = append(v.Notices, n)
		}
	}
	a.page(w, r, cur, http.StatusOK, "hosts", view{Title: "Machines", Nav: "systems", Tabs: tabs("systems", "/systems"), Data: v})
}

// readSystems counts the systems whose installed software Varde knows. Every
// page that says how many systems are read uses it.
func readSystems(rows []systemRow) int {
	n := 0
	for _, r := range rows {
		if r.Read() {
			n++
		}
	}
	return n
}

// systemRows builds the systems list: every host machine with what is
// installed and what is affected, nodes first, each followed by its guests.
func (a *app) systemRows(ctx context.Context, s *snapshot) ([]systemRow, error) {
	pkgCounts, err := a.d.Store.HostPackageCounts(ctx)
	if err != nil {
		return nil, err
	}
	reboots, err := a.d.Store.HostReboots(ctx)
	if err != nil {
		return nil, err
	}
	rows := map[string]*systemRow{}
	for _, m := range s.machines {
		if !m.IsHost() {
			continue
		}
		row := &systemRow{Machine: m}
		for _, h := range m.HostIDs {
			row.Packages = max(row.Packages, pkgCounts[h])
			if why := reboots[h]; why != "" {
				row.Reboot = why
			}
		}
		rows[m.ID] = row
	}
	for _, wl := range s.workloads {
		m := s.hostOf[wl.HostID]
		if m == nil || rows[m.ID] == nil {
			continue
		}
		if wl.Container != nil {
			rows[m.ID].Containers++
		}
		if id, ok := s.ids[wl.ID]; ok && id.AppID != "" {
			rows[m.ID].Apps++
		}
	}
	for _, f := range s.findings {
		if !status.Active(f.State) {
			continue
		}
		m := s.hostOf[s.byID[f.WorkloadID].HostID]
		if m == nil || rows[m.ID] == nil {
			continue
		}
		row := rows[m.ID]
		switch {
		case f.MatchState != string(match.Affected):
			row.Unverified++
		case f.Priority == "P1":
			row.P1++
		case f.Priority == "P2":
			row.P2++
		default:
			row.P3++
		}
	}
	var out []systemRow
	added := map[string]bool{}
	var add func(m coverage.Machine, guest bool)
	add = func(m coverage.Machine, guest bool) {
		row := rows[m.ID]
		if row == nil || added[m.ID] {
			return
		}
		added[m.ID] = true
		row.Guest = guest
		out = append(out, *row)
		for _, c := range s.machines {
			if c.ParentID == m.ID {
				add(c, true)
			}
		}
	}
	for _, m := range s.machines {
		if m.ParentID == "" || rows[m.ParentID] == nil {
			add(m, false)
		}
	}
	for _, m := range s.machines {
		add(m, false)
	}
	return out, nil
}

type agentsView struct {
	// Agents are the stored agent hosts, revoked ones included.
	Agents      []inventory.Host
	Pending     []store.EnrollmentToken
	AgentsOff   bool
	ListenAddr  string
	NewToken    string
	NewName     string
	Error       string
	RenewWithin time.Duration
	// CanInstall is set when Varde can install agents over SSH.
	CanInstall bool
}

func (a *app) agents(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	a.renderAgents(w, r, cur, http.StatusOK, agentsView{})
}

func (a *app) renderAgents(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, v agentsView) {
	ctx := r.Context()
	snap, err := a.load(ctx, false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	for _, h := range snap.hosts {
		if h.Source == inventory.SourceAgent {
			v.Agents = append(v.Agents, h)
		}
	}
	if v.Pending, err = a.d.Store.PendingEnrollmentTokens(ctx, a.d.Now()); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	v.AgentsOff, v.ListenAddr, v.CanInstall = a.d.AgentCAPin == "", a.d.AgentListenAddr, a.agentInstallReady()
	if status == http.StatusOK && v.NewToken != "" {
		// The secret is in the body only; keep it out of caches.
		w.Header().Set("Cache-Control", "no-store")
	}
	a.page(w, r, cur, status, "agents", view{Title: "Agents", Nav: "connections", Tabs: tabs("connections", "/connections/agents"), Data: v})
}

func (a *app) createEnrollment(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if a.d.AgentCAPin == "" {
		a.renderAgents(w, r, cur, http.StatusConflict, agentsView{Error: "The agent listener is switched off (VARDE_AGENT_LISTEN_ADDR=off)."})
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n\x00") {
		a.renderAgents(w, r, cur, http.StatusBadRequest, agentsView{Error: "Give the token a name (up to 64 characters), for example the host it is for."})
		return
	}
	secret, err := auth.RandomToken(32)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	id, err := auth.RandomToken(12)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	now := a.d.Now()
	if err := a.d.Store.CreateEnrollmentToken(r.Context(), store.EnrollmentToken{
		ID: id, Name: name, TokenHash: auth.HashToken(secret), CreatedBy: cur.User.Username,
		CreatedAt: now, ExpiresAt: now.Add(enrollmentLifetime),
	}); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "enrollment.create", id, name)
	// Rendered directly so the token never appears in a URL or history entry.
	a.renderAgents(w, r, cur, http.StatusOK, agentsView{NewToken: wire.FormatToken(secret, a.d.AgentCAPin), NewName: name})
}

func (a *app) deleteEnrollment(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	id := r.PathValue("id")
	if err := a.d.Store.DeleteEnrollmentToken(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "enrollment.delete", id, "")
	http.Redirect(w, r, "/connections/agents", http.StatusSeeOther)
}

func (a *app) revokeHost(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	id := r.PathValue("id")
	h, err := a.d.Store.Host(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && h.Source != inventory.SourceAgent) {
		a.renderError(w, r, cur, http.StatusNotFound, "Not found", "No agent with this ID.")
		return
	}
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	if err := a.d.Store.RevokeAgent(ctx, id, a.d.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "agent.revoke", id, h.Name)
	a.d.Analyze(ctx)
	http.Redirect(w, r, "/connections/agents", http.StatusSeeOther)
}

// systemCounts are the machine counts with the number of systems whose
// installed software Varde knows, the same number the systems list shows.
type systemCounts struct {
	coverage.MachineCounts
	Read int
}

func (a *app) countSystems(ctx context.Context, s *snapshot) (systemCounts, error) {
	rows, err := a.systemRows(ctx, s)
	if err != nil {
		return systemCounts{}, err
	}
	return systemCounts{MachineCounts: coverage.CountMachines(s.machines), Read: readSystems(rows)}, nil
}
