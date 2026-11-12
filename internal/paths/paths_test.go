// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"fmt"
	"strings"
	"testing"
)

const (
	vecNet   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	vecAdj   = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	vecLocal = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
	vecPhys  = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
)

// homelab is a Proxmox node with an LXC guest running Docker, and a second
// LAN machine with SSH.
func homelab() Input {
	return Input{
		Machines: []Machine{
			{ID: "node", Name: "pve", Kind: "bare-metal", HostIDs: []string{"h-node"}},
			{ID: "ct", Name: "docker-ct", Kind: "lxc", ParentID: "node", HostIDs: []string{"h-ct"}},
			{ID: "nas", Name: "nas", Kind: "linux", HostIDs: []string{"h-nas"}},
		},
		Hosts: map[string]Host{
			"h-node": {Known: true, Sources: map[string]bool{"proxmox-kernel-6.8": true, "openssh": true}},
			"h-ct":   {Known: true, Sources: map[string]bool{"openssh": true, "cups": true}},
			"h-nas":  {Known: true, Sources: map[string]bool{"openssh": true, "gnutls28": true, "openssl": true, "samba": true}},
		},
		HostMachine: map[string]string{"h-node": "node", "h-ct": "ct", "h-nas": "nas"},
		Workloads: []Workload{
			{ID: "w-app", HostID: "h-ct", Name: "immich", Container: true, Exposure: "public", Escape: "the container runs privileged", Networks: []string{"immich_default"}},
			{ID: "w-db", HostID: "h-ct", Name: "postgres", Container: true, Exposure: "internal", Networks: []string{"immich_default"}},
			{ID: "w-kernel", HostID: "h-node", Name: "proxmox-kernel-6.8", Package: "proxmox-kernel-6.8"},
			{ID: "w-cups", HostID: "h-ct", Name: "cups", Package: "cups"},
			{ID: "w-ssl", HostID: "h-nas", Name: "gnutls28", Package: "gnutls28"},
			{ID: "w-openssl", HostID: "h-nas", Name: "openssl", Package: "openssl"},
			{ID: "w-smb", HostID: "h-nas", Name: "samba", Package: "samba"},
		},
		Services: []Service{
			{MachineID: "ct", Port: 443, Proto: "tcp", Entry: Internet, Via: "photos.example.com", WorkloadID: "w-app"},
			{MachineID: "nas", Port: 445, Proto: "tcp", Entry: LAN, Via: "listener"},
		},
		Findings: []Finding{
			{ID: "f-app", WorkloadID: "w-app", AdvisoryID: "GHSA-app", Name: "Immich", Vector: vecNet, CVSS: 9.8, Affected: true, FixedIn: "1.121.0"},
			{ID: "f-db", WorkloadID: "w-db", AdvisoryID: "CVE-db", Name: "PostgreSQL", Vector: vecNet, CVSS: 8.8, Affected: true},
			{ID: "f-kernel", WorkloadID: "w-kernel", AdvisoryID: "CVE-kernel", Name: "proxmox-kernel-6.8", Vector: vecLocal, CVSS: 7.8, Affected: true},
			{ID: "f-cups", WorkloadID: "w-cups", AdvisoryID: "CVE-cups", Name: "cups", Vector: vecNet, CVSS: 9.0, Affected: true},
			{ID: "f-ssl", WorkloadID: "w-ssl", AdvisoryID: "CVE-ssl", Name: "gnutls28", Vector: vecNet, CVSS: 7.5, Affected: true},
			{ID: "f-smb", WorkloadID: "w-smb", AdvisoryID: "CVE-smb", Name: "samba", Vector: vecAdj, CVSS: 8.1, Affected: true},
			{ID: "f-phys", WorkloadID: "w-ssl", AdvisoryID: "CVE-phys", Name: "gnutls28", Vector: vecPhys, CVSS: 6.0, Affected: true},
			{ID: "f-openssl", WorkloadID: "w-openssl", AdvisoryID: "CVE-openssl", Name: "openssl", Vector: vecNet, CVSS: 7.5, Affected: true},
		},
	}
}

func TestInternetToHypervisor(t *testing.T) {
	r := Analyze(homelab())
	var top *Path
	for i := range r.Paths {
		if r.Paths[i].Target == "node" {
			top = &r.Paths[i]
			break
		}
	}
	if top == nil {
		t.Fatalf("no path to the node: %+v", r.Paths)
	}
	kinds := []string{}
	for _, s := range top.Steps {
		kinds = append(kinds, s.Kind)
	}
	if got := strings.Join(kinds, ","); got != "enter,exploit,escape,escalate" {
		t.Fatalf("steps: %s", got)
	}
	if top.Entry != Internet || top.Breaker != "f-app" || !strings.Contains(top.Cut, "update to 1.121.0") || !strings.Contains(top.Impact, "root on pve") {
		t.Fatalf("path: %+v", top)
	}
	// The path to the hypervisor ranks above every LAN path.
	if r.Paths[0].Entry != Internet {
		t.Fatalf("first path is not from the internet: %+v", r.Paths[0])
	}
	if c := r.Placements["f-app"].Class; c != OnPathInternet {
		t.Fatalf("app finding: %s", c)
	}
	if c := r.Placements["f-kernel"].Class; c != Amplifier {
		t.Fatalf("node kernel: %s", c)
	}
}

func TestNeighbourContainer(t *testing.T) {
	r := Analyze(homelab())
	pl := r.Placements["f-db"]
	if pl.Class != OnPathInternet || len(pl.Paths) == 0 {
		t.Fatalf("database behind the app: %+v", pl)
	}
	found := false
	for _, p := range r.Paths {
		for _, s := range p.Steps {
			found = found || (s.Kind == "pivot" && strings.Contains(s.Label, "immich_default"))
		}
	}
	if !found {
		t.Fatal("no pivot over the Docker network")
	}
}

func TestLateralFromInternetFoothold(t *testing.T) {
	r := Analyze(homelab())
	// Samba's flaw is adjacent-network: usable from the LAN, so also from a
	// machine taken over from the internet.
	pl := r.Placements["f-smb"]
	if pl.Class != OnPathInternet {
		t.Fatalf("samba: %+v", pl)
	}
	// gnutls on the NAS is a library of samba. Without a sign that its flaw
	// is being exploited it is not a way in: whether samba uses the flawed
	// part is unknown. It is neither on a path nor noise.
	stepOf := func(r Result) *Step {
		var step *Step
		for i := range r.Paths {
			for j := range r.Paths[i].Steps {
				if r.Paths[i].Steps[j].FindingID == "f-smb" {
					step = &r.Paths[i].Steps[j]
				}
			}
		}
		return step
	}
	if step := stepOf(r); step == nil || step.More != 0 || r.Placements["f-ssl"].Class != Unclear || !strings.Contains(r.Placements["f-ssl"].Reason, "library of a reachable service") {
		t.Fatalf("gnutls through samba, no sign of exploitation: %+v %+v", step, r.Placements["f-ssl"])
	}
	// Likely to be exploited, it is another flaw usable at the same step,
	// after samba's own.
	in := homelab()
	for i := range in.Findings {
		if in.Findings[i].ID == "f-ssl" {
			in.Findings[i].EPSS = 0.4
		}
	}
	likely := Analyze(in)
	if step := stepOf(likely); step == nil || step.More != 1 || step.also[0] != "f-ssl" || likely.Placements["f-ssl"].Class != OnPathInternet {
		t.Fatalf("gnutls through samba, likely exploited: %+v %+v", step, likely.Placements["f-ssl"])
	}
	// openssl is installed, but nothing reachable on the NAS uses it.
	if pl := r.Placements["f-openssl"]; pl.Class != Noise {
		t.Fatalf("openssl: %+v", pl)
	}
}

func TestNoise(t *testing.T) {
	r := Analyze(homelab())
	for id, want := range map[string]string{
		"f-cups": "no reachable service of the host uses cups",
		"f-phys": "physical access",
	} {
		pl := r.Placements[id]
		if pl.Class != Noise || !strings.Contains(pl.Reason, want) {
			t.Errorf("%s: %+v", id, pl)
		}
	}
}

func TestUnknownSurfaceIsUnclear(t *testing.T) {
	in := homelab()
	in.Hosts["h-ct"] = Host{Sources: in.Hosts["h-ct"].Sources}
	r := Analyze(in)
	if pl := r.Placements["f-cups"]; pl.Class != Unclear {
		t.Fatalf("without listeners Varde cannot call it noise: %+v", pl)
	}
}

func TestLocalFlawWithoutPath(t *testing.T) {
	in := homelab()
	// Without the public app, nothing reaches the node.
	in.Findings = in.Findings[2:]
	r := Analyze(in)
	if pl := r.Placements["f-kernel"]; pl.Class != Noise || !strings.Contains(pl.Reason, "no attack path reaches") {
		t.Fatalf("kernel: %+v", pl)
	}
}

func TestAdjacentNotFromInternet(t *testing.T) {
	in := Input{
		Machines:    []Machine{{ID: "m", Name: "m", HostIDs: []string{"h"}}},
		Hosts:       map[string]Host{"h": {Known: true, Sources: map[string]bool{"samba": true}}},
		HostMachine: map[string]string{"h": "m"},
		Workloads:   []Workload{{ID: "w", HostID: "h", Package: "samba"}},
		Services:    []Service{{MachineID: "m", Port: 445, Proto: "tcp", Entry: Internet}},
		Findings:    []Finding{{ID: "f", WorkloadID: "w", Vector: vecAdj, CVSS: 8, Affected: true}},
	}
	if r := Analyze(in); len(r.Paths) != 0 {
		t.Fatalf("an adjacent flaw is not reachable from the internet: %+v", r.Paths)
	}
}

func TestUnknownVectorIsAssumedAndMarked(t *testing.T) {
	in := Input{
		Machines:    []Machine{{ID: "m", Name: "m", HostIDs: []string{"h"}}},
		Hosts:       map[string]Host{"h": {Known: true, Sources: map[string]bool{"openssh": true}}},
		HostMachine: map[string]string{"h": "m"},
		Workloads:   []Workload{{ID: "w", HostID: "h", Package: "openssh"}},
		Services:    []Service{{MachineID: "m", Port: 22, Proto: "tcp", Entry: LAN}},
		Findings:    []Finding{{ID: "f", WorkloadID: "w", AdvisoryID: "CVE-x", Name: "openssh", Affected: true}},
	}
	r := Analyze(in)
	if len(r.Paths) != 1 || !r.Paths[0].Steps[1].Indirect || !strings.Contains(r.Paths[0].Steps[1].Label, "assumed remote") {
		t.Fatalf("paths: %+v", r.Paths)
	}
	if r.Placements["f"].Class != OnPathLAN {
		t.Fatalf("placement: %+v", r.Placements["f"])
	}
}

func TestOpenServiceIsAFoothold(t *testing.T) {
	in := Input{
		Machines: []Machine{{ID: "m", Name: "docker1", HostIDs: []string{"h"}}},
		Services: []Service{{MachineID: "m", Port: 2375, Proto: "tcp", Entry: LAN, Via: "scan", Open: "Docker API without authentication"}},
	}
	r := Analyze(in)
	if len(r.Paths) != 1 || r.Paths[0].Impact != "root on docker1" || !strings.HasPrefix(r.Paths[0].Cut, "Require authentication") {
		t.Fatalf("paths: %+v", r.Paths)
	}
}

func TestUnverifiedFindingsAreIgnored(t *testing.T) {
	in := homelab()
	for i := range in.Findings {
		in.Findings[i].Affected = false
	}
	r := Analyze(in)
	if len(r.Paths) != 0 || len(r.Placements) != 0 {
		t.Fatalf("unverified findings must not build paths: %+v", r)
	}
}

func TestBounded(t *testing.T) {
	in := Input{Hosts: map[string]Host{}, HostMachine: map[string]string{}}
	for i := 0; i < 60; i++ {
		id := string(rune('a'+i%26)) + string(rune('a'+i/26))
		in.Machines = append(in.Machines, Machine{ID: id, Name: id, HostIDs: []string{"h" + id}})
		in.Hosts["h"+id] = Host{Known: true, Sources: map[string]bool{"openssh": true}}
		in.HostMachine["h"+id] = id
		in.Workloads = append(in.Workloads, Workload{ID: "w" + id, HostID: "h" + id, Package: "openssh"})
		in.Findings = append(in.Findings, Finding{ID: "f" + id, WorkloadID: "w" + id, Vector: vecNet, CVSS: 9, Affected: true})
		entry := LAN
		if i%10 == 0 {
			entry = Internet
		}
		in.Services = append(in.Services, Service{MachineID: id, Port: 22, Proto: "tcp", Entry: entry})
	}
	r := Analyze(in)
	if len(r.Paths) > maxPaths {
		t.Fatalf("%d paths", len(r.Paths))
	}
}

func TestServicePackages(t *testing.T) {
	installed := map[string]bool{"postgresql-16": true, "openssh": true, "nginx": true, "apache2": true}
	if got := servicePackages(5432, "tcp", "", installed); len(got) != 1 || got[0] != "postgresql-16" {
		t.Fatalf("postgres: %v", got)
	}
	// The banner beats the port's guess.
	if got := servicePackages(8443, "tcp", "nginx/1.24.0", installed); len(got) != 1 || got[0] != "nginx" {
		t.Fatalf("banner: %v", got)
	}
	if got := servicePackages(443, "tcp", "", map[string]bool{"cups": true}); len(got) != 0 {
		t.Fatalf("uninstalled: %v", got)
	}
	if !kernelPackage("linux") || !kernelPackage("proxmox-kernel-6.8") || kernelPackage("linux-firmware") {
		t.Fatal("kernel packages")
	}
	if !NetworkPackage("openssl") || NetworkPackage("bash") {
		t.Fatal("network packages")
	}
}

func TestTruncatedIsNeverNoise(t *testing.T) {
	a := newAnalysis(homelab())
	a.truncated = true
	if pl := a.place(a.findings["f-cups"]); pl.Class != Unclear {
		t.Fatalf("after the bound nothing is noise: %+v", pl)
	}
}

// One way in through a service is one path, however many flaws it has.
func TestOnePathPerWayIn(t *testing.T) {
	in := Input{
		Machines:    []Machine{{ID: "m", Name: "m", HostIDs: []string{"h"}}},
		Hosts:       map[string]Host{"h": {Known: true}},
		HostMachine: map[string]string{"h": "m"},
		Workloads:   []Workload{{ID: "w", HostID: "h", Name: "app", Container: true, Exposure: "public"}},
		Services:    []Service{{MachineID: "m", Port: 443, Proto: "tcp", Entry: Internet, WorkloadID: "w"}},
	}
	for i := range 30 {
		in.Findings = append(in.Findings, Finding{ID: fmt.Sprintf("f%02d", i), WorkloadID: "w", Vector: vecNet, CVSS: float64(i%10) + 0.5, Affected: true})
	}
	r := Analyze(in)
	if len(r.Paths) != 1 || r.Paths[0].Steps[1].More != 29 || !strings.Contains(r.Paths[0].Cut, "29 other flaws") {
		t.Fatalf("paths: %d %+v", len(r.Paths), r.Paths)
	}
	for _, f := range in.Findings {
		if r.Placements[f.ID].Class != OnPathInternet {
			t.Fatalf("%s: %+v", f.ID, r.Placements[f.ID])
		}
	}
}

// Root on a machine ranks above control of a container, whatever the number
// of flaws on the way.
func TestRootRanksFirst(t *testing.T) {
	in := Input{
		Machines:    []Machine{{ID: "m", Name: "docker1", HostIDs: []string{"h"}}},
		Hosts:       map[string]Host{"h": {Known: true}},
		HostMachine: map[string]string{"h": "m"},
		Workloads: []Workload{
			{ID: "a", HostID: "h", Name: "router", Container: true, Exposure: "public", Networks: []string{"n"}},
			{ID: "b", HostID: "h", Name: "vault", Container: true, Exposure: "internal", Networks: []string{"n"}},
			{ID: "c", HostID: "h", Name: "oldweb", Container: true, Exposure: "public", Escape: "the container runs privileged"},
		},
		Services: []Service{{MachineID: "m", Entry: Internet, WorkloadID: "a"}, {MachineID: "m", Entry: Internet, WorkloadID: "c"}},
		Findings: []Finding{
			{ID: "fa", WorkloadID: "a", Vector: vecNet, CVSS: 9.8, KEV: true, Affected: true},
			{ID: "fb", WorkloadID: "b", Vector: vecNet, CVSS: 9.8, KEV: true, Affected: true},
			{ID: "fc", WorkloadID: "c", Vector: vecNet, CVSS: 7.0, Affected: true},
		},
	}
	r := Analyze(in)
	if len(r.Paths) < 2 || r.Paths[0].Impact != "root on docker1" {
		t.Fatalf("first: %+v", r.Paths)
	}
}

// A host listening on a port Varde cannot tie to a package: its packages
// are not noise, they are unclear.
func TestUnknownPortIsNotNoise(t *testing.T) {
	in := homelab()
	in.Hosts["h-ct"] = Host{Known: true, Sources: in.Hosts["h-ct"].Sources, UnknownPorts: []uint16{3000}}
	r := Analyze(in)
	if pl := r.Placements["f-cups"]; pl.Class != Unclear || !strings.Contains(pl.Reason, "port 3000") {
		t.Fatalf("cups: %+v", pl)
	}
}

// A container behind a reverse proxy on its network is not noise while the
// proxy's routes are unknown; nor is a container next to a tunnel.
func TestProxyNeighbourIsNotNoise(t *testing.T) {
	for _, proxy := range []Workload{
		{ID: "w-npm", HostID: "h", Name: "npm", Container: true, Exposure: "public", Proxy: "proxy", Networks: []string{"web"}},
		{ID: "w-cf", HostID: "h", Name: "cloudflared", Container: true, Exposure: "internal", Proxy: "tunnel", Networks: []string{"web"}},
	} {
		in := Input{
			Machines:    []Machine{{ID: "m", Name: "m", HostIDs: []string{"h"}}},
			Hosts:       map[string]Host{"h": {Known: true}},
			HostMachine: map[string]string{"h": "m"},
			Workloads:   []Workload{proxy, {ID: "w-vw", HostID: "h", Name: "vaultwarden", Container: true, Exposure: "internal", Networks: []string{"web"}}},
			Findings:    []Finding{{ID: "f", WorkloadID: "w-vw", Vector: vecNet, CVSS: 9.8, KEV: true, Affected: true}},
		}
		if pl := Analyze(in).Placements["f"]; pl.Class != Unclear || !strings.Contains(pl.Reason, proxy.Name) {
			t.Fatalf("%s: %+v", proxy.Name, pl)
		}
	}
}

// The kept paths are the most dangerous, whatever order they were found in.
func TestTopPathsByScore(t *testing.T) {
	in := Input{Hosts: map[string]Host{}, HostMachine: map[string]string{}}
	for i := range 300 {
		id := fmt.Sprintf("a%03d", i)
		in.Machines = append(in.Machines, Machine{ID: id, Name: id, HostIDs: []string{"h" + id}})
		in.Hosts["h"+id] = Host{Known: true, Sources: map[string]bool{"openssh": true}}
		in.HostMachine["h"+id] = id
		in.Workloads = append(in.Workloads, Workload{ID: "w" + id, HostID: "h" + id, Package: "openssh"})
		in.Findings = append(in.Findings, Finding{ID: "f" + id, WorkloadID: "w" + id, Vector: vecAdj, CVSS: 5, Affected: true})
		in.Services = append(in.Services, Service{MachineID: id, Port: 22, Proto: "tcp", Entry: LAN})
	}
	in.Machines = append(in.Machines, Machine{ID: "z", Name: "z", HostIDs: []string{"hz"}})
	in.HostMachine["hz"] = "z"
	in.Workloads = append(in.Workloads, Workload{ID: "wz", HostID: "hz", Name: "app", Container: true, Exposure: "public", Escape: "the container runs privileged"})
	in.Findings = append(in.Findings, Finding{ID: "fz", WorkloadID: "wz", Vector: vecNet, CVSS: 9.8, KEV: true, Affected: true})
	in.Services = append(in.Services, Service{MachineID: "z", Entry: Internet, WorkloadID: "wz"})
	r := Analyze(in)
	if len(r.Paths) != maxPaths || r.Paths[0].Target != "z" {
		t.Fatalf("first of %d: %+v", len(r.Paths), r.Paths[0])
	}
}

// Two ways to the same impact from the same entry: the more dangerous is
// listed, the findings of both stay on a path.
func TestOnePathPerImpact(t *testing.T) {
	in := Input{
		Machines:    []Machine{{ID: "m", Name: "m", HostIDs: []string{"h"}}},
		Hosts:       map[string]Host{"h": {Known: true}},
		HostMachine: map[string]string{"h": "m"},
		Workloads: []Workload{
			{ID: "a", HostID: "h", Name: "a", Container: true, Exposure: "public", Networks: []string{"n"}},
			{ID: "b", HostID: "h", Name: "b", Container: true, Exposure: "public", Networks: []string{"n"}},
			{ID: "db", HostID: "h", Name: "db", Container: true, Exposure: "internal", Networks: []string{"n"}},
		},
		Services: []Service{{MachineID: "m", Entry: Internet, WorkloadID: "a"}, {MachineID: "m", Entry: Internet, WorkloadID: "b"}},
		Findings: []Finding{
			{ID: "fa", WorkloadID: "a", Vector: vecNet, CVSS: 9.8, Affected: true},
			{ID: "fb", WorkloadID: "b", Vector: vecNet, CVSS: 5.0, Affected: true},
			{ID: "fdb", WorkloadID: "db", Vector: vecNet, CVSS: 8.0, Affected: true},
		},
	}
	r := Analyze(in)
	n := 0
	for _, p := range r.Paths {
		if p.Impact == "container db on m" && p.Subject == "db" && p.Where == "container on m" {
			n++
			if p.Breaker != "fa" {
				t.Errorf("listed path is not the most dangerous: %+v", p)
			}
		}
	}
	if n != 1 || r.Placements["fb"].Class != OnPathInternet {
		t.Fatalf("paths to db: %d, fb: %+v", n, r.Placements["fb"])
	}
}

// A flaw in a library of a container's image opens a path only with a sign
// that it is being exploited and a vector known to be remote. Nearly every
// image has some library flaw: without this rule every container gets a
// path and the paths say nothing.
func TestLibraryFlawNeedsASignOfExploitation(t *testing.T) {
	build := func(f Finding) Result {
		f.ID, f.WorkloadID, f.Affected, f.ImagePackage, f.Name = "lib", "c", true, "zlib", "zlib"
		return Analyze(Input{
			Machines:    []Machine{{ID: "m", Name: "docker", HostIDs: []string{"h"}}},
			Hosts:       map[string]Host{"h": {Known: true}},
			HostMachine: map[string]string{"h": "m"},
			Workloads:   []Workload{{ID: "c", HostID: "h", Name: "paperless", Container: true, Exposure: "lan"}},
			Services:    []Service{{MachineID: "m", Entry: LAN, WorkloadID: "c", Port: 8000, Proto: "tcp"}},
			Findings:    []Finding{f},
		})
	}
	for _, tc := range []struct {
		name string
		f    Finding
		path bool
	}{
		{"severe but no sign", Finding{Vector: vecNet, CVSS: 9.8, FixedIn: "1.3.1"}, false},
		{"known exploited", Finding{Vector: vecNet, CVSS: 7.5, KEV: true, FixedIn: "1.3.1"}, true},
		{"likely exploited", Finding{Vector: vecNet, CVSS: 7.5, EPSS: 0.10, FixedIn: "1.3.1"}, true},
		{"just below the threshold", Finding{Vector: vecNet, CVSS: 7.5, EPSS: 0.09}, false},
		{"exploited but vector unknown", Finding{CVSS: 9.8, KEV: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := build(tc.f)
			if got := len(r.Paths) == 1; got != tc.path {
				t.Fatalf("path = %v, want %v: %+v", got, tc.path, r.Paths)
			}
			pl := r.Placements["lib"]
			if tc.path {
				p := r.Paths[0]
				if pl.Class != OnPathLAN || p.Subject != "paperless" || p.Where != "container on docker" || !strings.HasPrefix(p.Cut, "Update the image of paperless: it contains ") {
					t.Errorf("placement %+v, path %+v", pl, p)
				}
				return
			}
			if pl.Class != Unclear || !strings.Contains(pl.Reason, "nothing says it is being exploited") {
				t.Errorf("placement %+v", pl)
			}
		})
	}
}

// The server an image is built around is not a library: its flaw opens a
// path by its vector, whatever its exploitation score.
func TestServerPackageOfTheImageIsNotALibrary(t *testing.T) {
	r := Analyze(Input{
		Machines:    []Machine{{ID: "m", Name: "docker", HostIDs: []string{"h"}}},
		Hosts:       map[string]Host{"h": {Known: true}},
		HostMachine: map[string]string{"h": "m"},
		Workloads:   []Workload{{ID: "c", HostID: "h", Name: "web", Container: true, Exposure: "lan"}},
		Services:    []Service{{MachineID: "m", Entry: LAN, WorkloadID: "c", Port: 80, Proto: "tcp"}},
		Findings:    []Finding{{ID: "srv", WorkloadID: "c", Affected: true, ImagePackage: "nginx", Name: "nginx", Vector: vecNet, CVSS: 7.5}},
	})
	if len(r.Paths) != 1 || r.Placements["srv"].Class != OnPathLAN || r.Paths[0].Steps[1].Indirect {
		t.Fatalf("paths %+v, placement %+v", r.Paths, r.Placements["srv"])
	}
}
