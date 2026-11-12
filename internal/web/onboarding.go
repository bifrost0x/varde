// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"sort"

	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/integrations"
)

// step is one suggestion of the setup checklist: what to do, what it
// unlocks, and what Varde may do afterwards.
type step struct {
	Title string
	// Gain says what becomes visible; Impact ranks the steps (machines or
	// apps it unlocks).
	Gain   string
	Impact int
	// Grant is the access Varde gets, in plain words.
	Grant string
	Link  string
}

// setupSteps derives the next steps from what Varde knows. They are ranked
// by impact so one connection that reveals many machines comes first; the
// user never has to connect services one by one.
func (a *app) setupSteps(s *snapshot, rows []systemRow) []step {
	if a.d.Network == nil {
		return nil
	}
	scope := a.d.Settings.Get().Networks
	if scope.Empty() {
		return []step{{
			Title: "Allow your networks", Gain: "Varde can find what runs in your LAN.", Impact: 1000,
			Grant: "Varde may connect to addresses in these ranges, nowhere else.", Link: "/connections#scope",
		}}
	}
	scan := a.d.Network.Scan()
	if scan.Ended.IsZero() && !scan.Running && len(s.devices) == 0 {
		return []step{{
			Title: "Scan your network", Gain: "Finds Proxmox, Docker hosts and web apps; takes about half a minute per /24.", Impact: 900,
			Grant: "Connects to a few common ports and reads what the services announce.", Link: "/connections#scan",
		}}
	}
	kinds := map[string]bool{}
	for _, in := range s.integrations {
		kinds[in.Kind+"@"+in.Address] = true
	}
	var steps []step
	// Linux hosts nothing reads: the agent gives their full inventory.
	if cands := a.agentCandidates(s, rows); len(cands) > 0 {
		n := min(len(cands), maxBulkInstall)
		steps = append(steps, step{
			Title: "Read the full inventory of " + plural(len(cands), "Linux host"),
			Gain:  "Every installed package and every Docker container, kept current by the agent.", Impact: 400 * len(cands),
			Grant: "One SSH sign-in that Varde does not keep. The agent runs as an unprivileged service user; Docker access only if you allow it.",
			Link:  installLink(cands[:n]),
		})
	}
	// Proxmox nodes not connected yet: one token shows every guest. A node
	// of a cluster that is already connected is known through the API.
	viaAPI := map[string]bool{}
	for _, m := range s.machines {
		if m.Has(coverage.EvidenceProxmox) {
			for _, a := range m.Addresses {
				viaAPI[a] = true
			}
		}
	}
	for _, d := range s.devices {
		if d.Kind != discovery.KindProxmox || kinds[integrations.KindProxmox+"@"+d.Address] || viaAPI[d.Address] {
			continue
		}
		steps = append(steps, step{
			Title: "Connect Proxmox VE at " + d.Address, Gain: "Every node, VM and container of the cluster, with addresses.", Impact: 500,
			Grant: "A read-only API token (role PVEAuditor) that you create on the node.",
			Link:  "/connections/connect/proxmox?address=" + d.Address,
		})
	}
	// Guests of a connected node that nothing reads yet: one key line on
	// the node reads all of them, LXC containers and VMs with guest agent.
	seenLXC := map[string]int{}
	for _, m := range s.machines {
		if (m.Kind == "lxc" || m.Kind == "vm") && m.State == coverage.MachineSeen && m.Has(coverage.EvidenceProxmox) {
			for _, e := range m.Evidence {
				if e.Source == coverage.EvidenceProxmox {
					seenLXC[e.IntegrationID]++
				}
			}
		}
	}
	for _, in := range s.integrations {
		if in.Kind != integrations.KindProxmox || seenLXC[in.ID] == 0 || kinds[integrations.KindProxmoxLXC+"@"+in.Address] {
			continue
		}
		n := seenLXC[in.ID]
		steps = append(steps, step{
			Title: fmt.Sprintf("Read the full inventory of %d guests on %s", n, in.Address),
			Gain:  "Every package and every Docker container of each running LXC container and of each VM with guest agent, with one key line instead of one per guest.", Impact: 100 * n,
			Grant: "A key for root on the node that can only run one fixed, read-only command.",
			Link:  "/connections/connect/proxmox-lxc?address=" + in.Address,
		})
	}
	// Docker hosts the scan found that nothing reads.
	for _, d := range s.devices {
		if d.Kind != discovery.KindDocker || kinds[integrations.KindDockerSSH+"@"+d.Address] {
			continue
		}
		steps = append(steps, step{
			Title: "Read the containers on " + d.Address, Gain: "Every container with image, version and exposure.", Impact: 300,
			Grant: "A key that only opens the Docker API stream (docker system dial-stdio). Docker access equals root on that host.",
			Link:  "/connections/connect/docker?address=" + d.Address,
		})
	}
	// Guests and hosts Varde only knows from the outside, reachable over SSH.
	ssh := map[string]bool{}
	for _, d := range s.devices {
		for _, svc := range d.Services {
			if svc.Proto == discovery.ProtoSSH {
				ssh[d.Address] = true
			}
		}
	}
	for _, m := range s.machines {
		// With agents available, the step above covers these hosts.
		if a.agentInstallReady() || !m.IsHost() || m.State != coverage.MachineSeen || m.Kind == "lxc" || m.Kind == "bare-metal" {
			continue
		}
		for _, addr := range m.Addresses {
			if ssh[addr] && !kinds[integrations.KindSSHInventory+"@"+addr] {
				steps = append(steps, step{
					Title: "Read the packages on " + m.Name, Gain: "Apps installed natively on this machine.", Impact: 50,
					Grant: "A key that can only run one fixed, read-only command listing packages and services.",
					Link:  "/connections/connect/packages?address=" + addr,
				})
				break
			}
		}
	}
	if !a.d.Settings.Get().RegistryTags {
		n := 0
		for _, g := range a.workloadCoverage(s).VersionUnknown {
			if g.Workload.Container != nil {
				n++
			}
		}
		if n > 0 {
			steps = append(steps, step{
				Title: fmt.Sprintf("Read the versions of %d containers on floating tags", n),
				Gain:  "The registry tells which release tag points to the running image; no labels needed.", Impact: 60 * n,
				Grant: "Anonymous, read-only requests to the image registries (tag lists and manifest digests).",
				Link:  "/settings#registry",
			})
		}
	}
	if !a.d.Settings.Get().EOLData {
		cat := a.d.Catalog.Current()
		n := 0
		for _, id := range s.ids {
			if app, ok := cat.App(id.AppID); ok && app.EOL != "" && id.Version != "" {
				n++
			}
		}
		if n > 0 {
			steps = append(steps, step{
				Title: fmt.Sprintf("Check the release lines of %d apps for their end of life", n),
				Gain:  "Shows which versions no longer get security fixes, before an advisory says so.", Impact: 20 * n,
				Grant: "One request a day per product to endoflife.date, revealing the product names.",
				Link:  "/settings#eol",
			})
		}
	}
	if !a.d.Settings.Get().DirectOSV {
		pkgs := identify.DistroPackages(a.d.Catalog.Current(), s.workloads)
		n := 0
		for _, ps := range pkgs {
			n += len(ps)
		}
		if n > 0 {
			steps = append(steps, step{
				Title: fmt.Sprintf("Check %d distribution packages against their distribution's security data", n),
				Gain:  "Debian, Ubuntu and Alpine state which package versions carry the fix; backported fixes count, upstream version ranges do not.", Impact: 40 * n,
				Grant: "Queries to osv.dev with the package names and releases.",
				Link:  "/settings#sources",
			})
		}
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].Impact > steps[j].Impact })
	return steps
}
