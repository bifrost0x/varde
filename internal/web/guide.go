// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
)

// guideStep is one step of getting started. Exactly one undone step is the
// next one; the overview shows it as the main action.
type guideStep struct {
	Title, Text, Link, Action string
	Done                      bool
}

// guide leads a new user from an empty Varde to systems it reads, then to
// notifications and HTTPS.
type guide struct {
	Steps []guideStep
	// Next is the index of the first undone step, -1 when all are done.
	Next int
	// Started is set when the first three steps (networks, scan, read a
	// system) are done; the guide then shrinks to what is left.
	Started bool
}

// maxBulkInstall bounds the hosts one installation run covers.
const maxBulkInstall = 20

// agentCandidates are the addresses of found machines the agent suits:
// they answer SSH, are not a Proxmox node (read through its API), run no
// agent yet and Varde knows nothing installed on them.
func (a *app) agentCandidates(s *snapshot, rows []systemRow) []string {
	if !a.agentInstallReady() {
		return nil
	}
	read := map[string]bool{}
	for _, r := range rows {
		read[r.Machine.ID] = r.Read()
	}
	machineOf := map[string]coverage.Machine{}
	for _, m := range s.machines {
		for _, e := range m.Evidence {
			if e.Source == coverage.EvidenceScan && len(e.Addresses) > 0 {
				machineOf[e.Addresses[0]] = m
			}
		}
	}
	scope := a.d.Settings.Get().Networks
	var out []string
	for _, d := range s.devices {
		addr, err := netip.ParseAddr(d.Address)
		if err != nil || !scope.Contains(addr) || d.Kind == discovery.KindProxmox || d.Kind == discovery.KindProxmoxBackup {
			continue
		}
		ssh := false
		for _, svc := range d.Services {
			ssh = ssh || svc.Proto == discovery.ProtoSSH
		}
		m := machineOf[d.Address]
		if !ssh || m.Self || m.Has(coverage.EvidenceAgent) || read[m.ID] {
			continue
		}
		out = append(out, d.Address)
	}
	return out
}

// installLink opens the agent installation for the given hosts.
func installLink(addrs []string) string {
	q := url.Values{}
	for _, a := range addrs {
		q.Add("address", a)
	}
	return "/connections/agents/install?" + q.Encode()
}

func (a *app) buildGuide(ctx context.Context, r *http.Request, s *snapshot) (guide, error) {
	rows, err := a.systemRows(ctx, s)
	if err != nil {
		return guide{}, err
	}
	read := readSystems(rows)
	g := guide{Next: -1}
	scope := a.d.Settings.Get().Networks
	scanned := len(s.devices) > 0 || len(s.integrations) > 0
	if a.d.Network != nil {
		sc := a.d.Network.Scan()
		scanned = scanned || !sc.Ended.IsZero()
	}
	g.Steps = append(g.Steps, guideStep{
		Title: "Allow your networks", Done: !scope.Empty(),
		Text: "Varde connects only to the address ranges you allow, for scans and for every connection.",
		Link: "/connections#scope", Action: "Allow a network",
	}, guideStep{
		Title: "Scan them", Done: scanned,
		Text: "Finds Linux hosts, Proxmox nodes, Docker hosts and web apps; about half a minute per /24.",
		Link: "/connections#scan", Action: "Scan the network",
	})
	// The step is done once Varde reads systems and no found Linux host is
	// left without: one agent connected must not hide the hosts whose
	// installation did not get through.
	cands := a.agentCandidates(s, rows)
	readStep := guideStep{Title: "Read your systems", Done: read > 0 && len(cands) == 0}
	switch {
	case len(cands) > 0:
		n := min(len(cands), maxBulkInstall)
		readStep.Text = "Varde found " + plural(len(cands), "Linux host") + " it knows nothing inside of yet. The agent reports every installed package and every Docker container; Varde installs it with one SSH sign-in it does not keep."
		if read > 0 {
			verb := "still report"
			if len(cands) == 1 {
				verb = "still reports"
			}
			readStep.Text = fmt.Sprintf("Varde knows what is installed on %d of %d systems; %s %s nothing. An agent that was installed but cannot reach Varde shows why when you install it again.",
				read, len(rows), plural(len(cands), "Linux host"), verb)
		}
		readStep.Link, readStep.Action = installLink(cands[:n]), "Install the agent on "+plural(n, "host")
	case read > 0:
		readStep.Text = fmt.Sprintf("Varde knows what is installed on %d of %d systems.", read, len(rows))
		readStep.Link, readStep.Action = "/systems", "Show systems"
	case a.agentInstallReady():
		readStep.Text = "The agent reports every installed package and every Docker container of a host; Varde installs it with one SSH sign-in it does not keep."
		readStep.Link, readStep.Action = "/connections/agents/install", "Install the agent on a host"
	default:
		readStep.Text = "Connect a platform Varde found, or read a host over SSH."
		readStep.Link, readStep.Action = "/connections#devices", "Show what Varde found"
	}
	checkStep := guideStep{
		Title: "Check the installed packages", Done: a.packagesChecked(),
		Text: "Varde asks osv.dev, the open vulnerability database, which security fixes the installed packages of your systems lack, and reports every update that fixes one. This tells osv.dev the names and versions of those packages; without it, only apps are checked.",
		Link: "/settings#sources", Action: "Turn on package checks",
	}
	if len(s.system) > 0 && !checkStep.Done {
		checkStep.Text = "Varde knows " + plural(len(s.system), "system package") + " on your systems. " + checkStep.Text
	}
	g.Steps = append(g.Steps, readStep, checkStep, guideStep{
		Title: "Get notified", Done: len(a.d.Channels) > 0,
		Text: "Without a channel, urgent findings are only visible here. Channels (ntfy, Gotify, email, Discord, Telegram, webhook) are set in Varde's environment, so their secrets never pass the UI.",
		Link: "/settings#notifications", Action: "Set up notifications",
	})
	https := guideStep{Title: "Serve Varde over HTTPS", Done: a.d.Sessions.Secure(r), Text: insecureText(a.d.Sessions.UntrustedTLSProxy(r))}
	g.Steps = append(g.Steps, https)
	for i, st := range g.Steps {
		if !st.Done {
			g.Next = i
			break
		}
	}
	g.Started = g.Steps[0].Done && g.Steps[1].Done && g.Steps[2].Done
	return g, nil
}

// packagesChecked reports that the installed packages of the systems are
// checked: their switch is on, or a full feed brings the data. The data
// package does not carry distribution data.
func (a *app) packagesChecked() bool {
	m := a.mode()
	return a.d.Settings.Get().DirectOSV || (m != "direct" && m != "package")
}
