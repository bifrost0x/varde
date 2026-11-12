// SPDX-License-Identifier: Apache-2.0

// Package paths finds attack paths through the infrastructure Varde knows:
// from the internet or the LAN to a reachable service, through a flaw in
// it to a foothold, and on to root on the host, the hypervisor and further
// machines. Findings no path uses are background noise, each with the
// reason; findings Varde lacks the data to place stay unclear (ADR 0034).
package paths

import (
	"fmt"
	"sort"
	"strings"
)

// Entry is where an attacker starts.
type Entry string

// Entries.
const (
	Internet Entry = "internet"
	LAN      Entry = "lan"
)

// Class says how a finding relates to the attack paths.
type Class string

// Classes.
const (
	// OnPathInternet and OnPathLAN: the finding opens a path from there.
	OnPathInternet Class = "path-internet"
	OnPathLAN      Class = "path-lan"
	// Amplifier: a local flaw that turns a foothold into root on a path.
	Amplifier Class = "amplifier"
	// Noise: no path uses the finding, and Varde knows why.
	Noise Class = "noise"
	// Unclear: Varde lacks the data to tell.
	Unclear Class = "unclear"
)

// Machine is a host or device.
type Machine struct {
	ID, Name, Kind string
	// ParentID is the node a guest runs on.
	ParentID string
	HostIDs  []string
}

// Service is a reachable port of a machine.
type Service struct {
	MachineID string
	Port      uint16
	Proto     string
	// Product is what the service announced to the scan, if anything.
	Product string
	// Entry is where it can be reached from.
	Entry Entry
	// Via says how Varde knows: "scan", "listener", or the public host
	// name of a proxy route.
	Via string
	// WorkloadID is set when a container serves the port.
	WorkloadID string
	// Open names a service that grants control without authentication,
	// such as a Docker API without TLS: a foothold without any flaw.
	Open string
}

// Workload is a container or a system package.
type Workload struct {
	ID, HostID, Name string
	// Container: the runtime facts that decide an escape.
	Container bool
	// Escape names how a foothold in the container gives the host; empty
	// when nothing known does.
	Escape string
	// Exposure is the container's exposure (public, lan, internal,
	// unknown); empty for packages.
	Exposure string
	// Package is the source package of a system package.
	Package string
	// Networks are the Docker networks a container is attached to:
	// containers on one network reach each other.
	Networks []string
	// Proxy is "proxy" for a reverse proxy and "tunnel" for a tunnel to
	// the internet (cloudflared): they forward traffic to their neighbours.
	Proxy string
}

// Finding is an open finding.
type Finding struct {
	ID, WorkloadID, AppID, AdvisoryID string
	// Vector is the CVSS v3 vector, empty when unknown.
	Vector   string
	CVSS     float64
	EPSS     float64
	KEV      bool
	FixedIn  string
	Affected bool
	// Name is what the finding is in (app or package name).
	Name string
	// ImagePackage is the source package when the finding is in a package
	// of a container's image rather than in the app.
	ImagePackage string
}

// Host is what Varde knows of a host's surface.
type Host struct {
	// Known is set when the listening sockets of the host are known.
	Known bool
	// UnknownPorts are listening ports Varde cannot attribute to a
	// package or a container: while there are any, no package of the host
	// can be called unreachable.
	UnknownPorts []uint16
	// Sources are the installed source packages.
	Sources map[string]bool
}

// Input is everything the analysis looks at.
type Input struct {
	Machines  []Machine
	Services  []Service
	Workloads []Workload
	Findings  []Finding
	// Hosts by stored host ID.
	Hosts map[string]Host
	// HostMachine maps a stored host ID to its machine.
	HostMachine map[string]string
}

// Step is one move of an attacker.
type Step struct {
	// Kind: enter, exploit, escalate, escape, pivot.
	Kind string `json:"kind"`
	// Label says it in words.
	Label     string `json:"label"`
	MachineID string `json:"machine_id,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
	// Indirect marks a flaw in a library the service uses, or a vector
	// Varde had to assume: weaker evidence than a flaw in the service.
	Indirect bool `json:"indirect,omitempty"`
	// More counts the other flaws usable at the same step; also are they.
	More int `json:"more,omitempty"`
	also []string
}

// Path is one way in, ranked by Score.
type Path struct {
	ID    string `json:"id"`
	Entry Entry  `json:"entry"`
	Steps []Step `json:"steps"`
	// Impact says what the attacker holds at the end.
	Impact string `json:"impact"`
	// Subject is what the path ends on (a container or a machine), Where
	// says where that is, and Gain what the attacker can do there. The
	// three name a path by its target.
	Subject string `json:"subject,omitempty"`
	Where   string `json:"where,omitempty"`
	Gain    string `json:"gain,omitempty"`
	// Target is the machine the path ends on.
	Target     string `json:"target"`
	TargetName string `json:"target_name"`
	Score      int    `json:"score"`
	// Breaker is the finding whose fix cuts the path at its start; Cut
	// says what to do.
	Breaker string `json:"breaker,omitempty"`
	Cut     string `json:"cut"`
	// Findings are all findings the path uses.
	Findings []string `json:"findings"`
}

// Placement is a finding's relation to the paths.
type Placement struct {
	Class  Class    `json:"class"`
	Reason string   `json:"reason"`
	Paths  []string `json:"paths,omitempty"`
}

// Result is the analysis.
type Result struct {
	Paths      []Path               `json:"paths"`
	Placements map[string]Placement `json:"placements"`
}

// libraryEPSS is the probability of exploitation from which a flaw in a
// library counts as a way in (the threshold the priorities use as well).
const libraryEPSS = 0.10

const (
	maxPaths = 200
	// maxExplore bounds the paths followed; the maxPaths most dangerous of
	// them are kept, whatever order they were found in.
	maxExplore = 5000
	maxDepth   = 2 // lateral hops after the first foothold
)

// level is what a foothold gives.
type level int

const (
	levelService level = iota // code execution as the service or in a container
	levelRoot                 // root on the machine
)

type foothold struct {
	machine   string
	container string // workload ID when inside a container
	level     level
}

// Analyze finds the paths and places every finding.
func Analyze(in Input) Result {
	a := newAnalysis(in)
	a.run()
	return a.result()
}

type analysis struct {
	in        Input
	machines  map[string]Machine
	workloads map[string]Workload
	byWork    map[string][]Finding
	// system packages per host: source → workload IDs
	systemPkg map[string]map[string][]string
	services  map[string][]Service // by machine
	paths     []Path
	findings  map[string]Finding
	used      map[string]map[string]Class // finding → path ID → class
	reach     map[string]bool             // machines with a foothold on some path
	recorded  map[string]bool
	truncated bool
	entered   map[string]bool // containers with a foothold on some path
	// weak are flaws in a library of a reachable service that were not
	// taken for a way in: nothing says they are being exploited.
	weak   map[string]bool
	beyond map[string]bool // containers past the depth bound
}

func newAnalysis(in Input) *analysis {
	a := &analysis{in: in, machines: map[string]Machine{}, workloads: map[string]Workload{}, byWork: map[string][]Finding{},
		systemPkg: map[string]map[string][]string{}, services: map[string][]Service{}, used: map[string]map[string]Class{}, reach: map[string]bool{}, recorded: map[string]bool{}, entered: map[string]bool{}, beyond: map[string]bool{}, weak: map[string]bool{}}
	for _, m := range in.Machines {
		a.machines[m.ID] = m
	}
	for _, w := range in.Workloads {
		a.workloads[w.ID] = w
		if w.Package != "" {
			if a.systemPkg[w.HostID] == nil {
				a.systemPkg[w.HostID] = map[string][]string{}
			}
			a.systemPkg[w.HostID][w.Package] = append(a.systemPkg[w.HostID][w.Package], w.ID)
		}
	}
	a.findings = make(map[string]Finding, len(in.Findings))
	for _, f := range in.Findings {
		a.findings[f.ID] = f
		if f.Affected {
			a.byWork[f.WorkloadID] = append(a.byWork[f.WorkloadID], f)
		}
	}
	for _, s := range in.Services {
		a.services[s.MachineID] = append(a.services[s.MachineID], s)
	}
	return a
}

// hostsOf returns the stored host IDs of a machine.
func (a *analysis) hostsOf(machine string) []string { return a.machines[machine].HostIDs }

func (a *analysis) run() {
	ids := make([]string, 0, len(a.services))
	for id := range a.services {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, mid := range ids {
		for _, svc := range a.services[mid] {
			enter := Step{Kind: "enter", MachineID: mid, Label: enterLabel(svc, a.machines[mid].Name)}
			if svc.Open != "" {
				take := Step{Kind: "exploit", MachineID: mid, Label: fmt.Sprintf("Take control through %s on port %d", svc.Open, svc.Port)}
				a.extend(svc.Entry, []Step{enter, take}, foothold{machine: mid, level: levelRoot}, 0, map[string]bool{mid: true})
			}
			for _, ex := range a.exploits(svc) {
				steps := []Step{enter, ex.step}
				a.extend(svc.Entry, steps, ex.hold, 0, map[string]bool{mid: true, "w:" + svc.WorkloadID: true})
			}
		}
	}
}

type exploit struct {
	step Step
	hold foothold
}

// candidate is a flaw usable at one step.
type candidate struct {
	f        Finding
	indirect bool
	what     string
}

// better orders candidates: a flaw in the service itself before one in a
// library, then the stronger flaw.
func better(x, y candidate) bool {
	if x.indirect != y.indirect {
		return !x.indirect
	}
	return stronger(x.f, y.f)
}

// exploits is the way in through a service: one step with the strongest
// usable flaw, the others kept as alternatives of the same step. A path is
// a way in, not a flaw; every alternative must be fixed to cut it.
func (a *analysis) exploits(svc Service) []exploit {
	var cands []candidate
	add := func(f Finding, indirect bool, what string) {
		v := vectorOf(f.Vector)
		if !network(v, svc.Entry) {
			return
		}
		// A flaw in a library is not a flaw in the service: whether the
		// service uses the flawed part is unknown. Nearly every image has
		// such a flaw, so taking each for a way in would put a path on every
		// container and say nothing. It counts only with a sign that it is
		// being exploited and a vector that is known to be remote.
		if indirect && (v == "" || !exploited(f)) {
			a.weak[f.ID] = true
			return
		}
		cands = append(cands, candidate{f, indirect, what})
	}
	hold := foothold{machine: svc.MachineID}
	if svc.WorkloadID != "" {
		hold.container = svc.WorkloadID
		for _, f := range a.byWork[svc.WorkloadID] {
			switch {
			case f.ImagePackage == "":
				add(f, false, "")
			case ServerPackage(f.ImagePackage):
				// The image's own server (nginx in an nginx image): a flaw
				// in the service, reported through its package.
				add(f, false, ", the server in the image")
			case NetworkPackage(f.ImagePackage):
				// A library of the image the app may use to talk to the
				// network: weaker evidence than a flaw in the app.
				add(f, true, ", a library in the image")
			}
		}
	} else {
		for _, h := range a.hostsOf(svc.MachineID) {
			host := a.in.Hosts[h]
			for _, src := range servicePackages(svc.Port, svc.Proto, svc.Product, host.Sources) {
				for _, wid := range a.systemPkg[h][src] {
					for _, f := range a.byWork[wid] {
						add(f, false, "")
					}
				}
				for _, lib := range librariesOf(src) {
					for _, wid := range a.systemPkg[h][lib] {
						for _, f := range a.byWork[wid] {
							add(f, true, ", a library of "+src)
						}
					}
				}
			}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if better(c, best) {
			best = c
		}
	}
	step := Step{Kind: "exploit", MachineID: svc.MachineID, FindingID: best.f.ID, Indirect: best.indirect}
	step.Label = fmt.Sprintf("Exploit %s in %s%s", ident(best.f), best.f.Name, best.what)
	if vectorOf(best.f.Vector) == "" {
		step.Label += " (attack vector unknown, assumed remote)"
		step.Indirect = true
	}
	seen := map[string]bool{best.f.ID: true}
	for _, c := range cands {
		if !seen[c.f.ID] {
			seen[c.f.ID] = true
			step.also = append(step.also, c.f.ID)
		}
	}
	sort.Strings(step.also)
	if step.More = len(step.also); step.More > 0 {
		step.Label += fmt.Sprintf(", or one of %d more flaws", step.More)
	}
	return []exploit{{step: step, hold: hold}}
}

// exploited reports a sign that a flaw is being used: listed as exploited,
// or likely to be within a month.
func exploited(f Finding) bool { return f.KEV || f.EPSS >= libraryEPSS }

// extend follows a foothold: escape a container, escalate to root, reach the
// node, pivot to other machines. Only the longest paths are recorded; the
// steps before them are part of them.
func (a *analysis) extend(entry Entry, steps []Step, hold foothold, depth int, seen map[string]bool) {
	if hold.container == "" {
		// A foothold on the machine itself: its local flaws matter now.
		a.reach[hold.machine] = true
	} else {
		a.entered[hold.container] = true
	}
	grown := false
	next := func(st []Step, h foothold, d int, s map[string]bool) {
		grown = true
		a.extend(entry, st, h, d, s)
	}
	switch {
	case hold.container != "":
		// Inside a container: out to the host, if anything allows it.
		if w := a.workloads[hold.container]; w.Escape != "" {
			esc := Step{Kind: "escape", MachineID: hold.machine, Label: "Escape to the host: " + w.Escape}
			next(append(clone(steps), esc), foothold{machine: hold.machine, level: levelRoot}, depth, seen)
		} else if k := a.localFlaw(hold.machine, true); k.FindingID != "" {
			k.Label = "Escape to the host through the shared kernel: " + k.Label
			next(append(clone(steps), k), foothold{machine: hold.machine, level: levelRoot}, depth, seen)
		}
		grown = a.neighbours(entry, steps, hold, depth, seen) || grown
	case hold.level == levelService:
		if lp := a.localFlaw(hold.machine, false); lp.FindingID != "" {
			next(append(clone(steps), lp), foothold{machine: hold.machine, level: levelRoot}, depth, seen)
		}
	case hold.level == levelRoot:
		// Root in an LXC guest: the node, through the node's kernel.
		if m := a.machines[hold.machine]; m.ParentID != "" && m.Kind == "lxc" {
			if k := a.localFlaw(m.ParentID, true); k.FindingID != "" {
				k.Label = "Escape the container to the Proxmox node: " + k.Label
				next(append(clone(steps), k), foothold{machine: m.ParentID, level: levelRoot}, depth, seen)
			}
		}
	}
	// Root on a machine is an impact of its own, whatever follows: it is
	// recorded before the pivots below can use up the exploration bound.
	milestone := hold.container == "" && hold.level == levelRoot
	if milestone {
		a.record(entry, steps, hold)
	}
	// Pivot: the LAN services of other machines, from a machine taken from
	// the internet.
	if hold.container == "" && entry == Internet && depth < maxDepth && len(a.paths) < maxExplore {
		ids := make([]string, 0, len(a.services))
		for id := range a.services {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, mid := range ids {
			if seen[mid] {
				continue
			}
			for _, svc := range a.services[mid] {
				if svc.Entry != LAN {
					continue
				}
				for _, ex := range a.exploits(svc) {
					ns := map[string]bool{mid: true}
					for k := range seen {
						ns[k] = true
					}
					pivot := Step{Kind: "pivot", MachineID: mid, Label: "Reach " + serviceLabel(svc, a.machines[mid].Name) + " from " + a.machines[hold.machine].Name}
					next(append(append(clone(steps), pivot), ex.step), ex.hold, depth+1, ns)
				}
			}
		}
	}
	if !grown && !milestone {
		a.record(entry, steps, hold)
	}
}

// neighbours follows a foothold in a container to the containers on its
// networks: they need not publish a port to be reached from there. It
// reports whether it found any.
func (a *analysis) neighbours(entry Entry, steps []Step, hold foothold, depth int, seen map[string]bool) bool {
	if depth >= maxDepth || len(a.paths) >= maxExplore {
		// Neighbours left unfollowed are not unreachable: they stay
		// unclear, never noise.
		from := a.workloads[hold.container]
		for _, w := range a.in.Workloads {
			if w.Container && w.ID != from.ID && w.HostID == from.HostID && shared(from.Networks, w.Networks) != "" {
				a.beyond[w.ID] = true
			}
		}
		return false
	}
	from := a.workloads[hold.container]
	found := false
	for _, w := range a.in.Workloads {
		if !w.Container || w.ID == from.ID || w.HostID != from.HostID || seen["w:"+w.ID] || reachable(w, entry) {
			continue
		}
		net := shared(from.Networks, w.Networks)
		if net == "" {
			continue
		}
		for _, ex := range a.exploits(Service{MachineID: hold.machine, Entry: LAN, WorkloadID: w.ID}) {
			ns := map[string]bool{"w:" + w.ID: true}
			for k := range seen {
				ns[k] = true
			}
			found = true
			pivot := Step{Kind: "pivot", MachineID: hold.machine, Label: "Reach container " + w.Name + " from " + from.Name + " over the Docker network " + net}
			a.extend(entry, append(append(clone(steps), pivot), ex.step), ex.hold, depth+1, ns)
		}
	}
	return found
}

// reachable reports whether a container is reached from the entry
// directly: a detour through its neighbours shows nothing new.
func reachable(w Workload, e Entry) bool {
	return w.Exposure == "public" || (e == LAN && w.Exposure == "lan")
}

func shared(a, b []string) string {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return x
			}
		}
	}
	return ""
}

// localFlaw is the strongest local flaw on a machine that gives root: in the
// kernel when kernelOnly is set (an escape), otherwise in any system package.
// The other local flaws are kept as alternatives of the step.
func (a *analysis) localFlaw(machine string, kernelOnly bool) Step {
	var all []Finding
	for _, h := range a.hostsOf(machine) {
		for src, wids := range a.systemPkg[h] {
			if kernelOnly && !kernelPackage(src) {
				continue
			}
			for _, wid := range wids {
				for _, f := range a.byWork[wid] {
					if vectorOf(f.Vector) == "L" {
						all = append(all, f)
					}
				}
			}
		}
	}
	if len(all) == 0 {
		return Step{}
	}
	sort.Slice(all, func(i, j int) bool { return stronger(all[i], all[j]) })
	best := all[0]
	st := Step{Kind: "escalate", MachineID: machine, FindingID: best.ID, Label: fmt.Sprintf("Become root through %s in %s", ident(best), best.Name)}
	for _, f := range all[1:] {
		st.also = append(st.also, f.ID)
	}
	if st.More = len(st.also); st.More > 0 {
		st.Label += fmt.Sprintf(", or one of %d more local flaws", st.More)
	}
	return st
}

// record stores a path ending at hold.
func (a *analysis) record(entry Entry, steps []Step, hold foothold) {
	if len(a.paths) >= maxExplore {
		// Paths beyond the bound are not explored: nothing may count as
		// unreachable any more.
		a.truncated = true
		return
	}
	m := a.machines[hold.machine]
	impact, subject, where, gain := "code execution on "+m.Name, m.Name, "machine", "an attacker runs code on it"
	switch {
	case hold.container != "":
		subject, where, gain = a.workloads[hold.container].Name, "container on "+m.Name, "an attacker runs code in it"
		impact = "container " + subject + " on " + m.Name
	case hold.level == levelRoot && m.Kind == "bare-metal":
		impact, gain = "root on "+m.Name+", and every guest on it", "an attacker becomes root, on it and on every guest"
	case hold.level == levelRoot:
		impact, gain = "root on "+m.Name, "an attacker becomes root"
	}
	key := string(entry) + "|" + impact
	for _, s := range steps {
		key += "|" + s.FindingID + s.Kind + s.MachineID
	}
	if a.recorded[pathID(key)] {
		return
	}
	a.recorded[pathID(key)] = true
	p := Path{ID: pathID(key), Entry: entry, Steps: clone(steps), Impact: impact, Subject: subject, Where: where, Gain: gain, Target: hold.machine, TargetName: m.Name}
	p.Score = a.score(p, hold)
	for _, s := range steps {
		if s.FindingID != "" {
			p.Findings = append(p.Findings, s.FindingID)
			p.Findings = append(p.Findings, s.also...)
		}
		if s.Kind != "exploit" || p.Cut != "" {
			continue
		}
		if s.FindingID == "" {
			p.Cut = "Require authentication or close the port: " + strings.TrimPrefix(s.Label, "Take control through ")
			continue
		}
		f := a.finding(s.FindingID)
		p.Breaker = f.ID
		if w := a.workloads[f.WorkloadID]; f.ImagePackage != "" && w.Container {
			// The fix is a newer image of the container; the version is
			// the package's, never the app's.
			p.Cut = "Update the image of " + w.Name + ": it contains " + ident(f) + " in " + f.Name
			if f.FixedIn != "" {
				p.Cut += " (the package is fixed from " + f.FixedIn + " on)"
			}
		} else {
			p.Cut = "Fix " + ident(f) + " in " + f.Name
			if f.FixedIn != "" {
				p.Cut += " (update to " + f.FixedIn + ")"
			}
		}
		if s.More > 0 {
			p.Cut += fmt.Sprintf(", and the %d other flaws usable there", s.More)
		}
	}
	a.paths = append(a.paths, p)
	for _, s := range steps {
		if s.FindingID == "" {
			continue
		}
		c := Amplifier
		if s.Kind == "exploit" {
			c = OnPathLAN
			if entry == Internet {
				c = OnPathInternet
			}
		}
		for _, id := range append([]string{s.FindingID}, s.also...) {
			if a.used[id] == nil {
				a.used[id] = map[string]Class{}
			}
			a.used[id][p.ID] = c
		}
	}
}

// score ranks a path: where it starts, how good its flaws are for an
// attacker, how far it gets, how short it is.
//
// A path is as feasible as its hardest step: the weakest flaw it needs
// counts, not the sum of all. What it reaches counts as much: root on a
// hypervisor above root on a machine above control of one container.
func (a *analysis) score(p Path, hold foothold) int {
	s := 20
	if p.Entry == Internet {
		s = 50
	}
	weakest := -1
	for _, st := range p.Steps {
		q := -1
		switch {
		case st.Kind == "exploit" && st.FindingID == "":
			// A service open without authentication: as good as a known
			// exploited flaw.
			q = 60
		case st.FindingID != "":
			f := a.finding(st.FindingID)
			q = int(f.CVSS*3) + int(f.EPSS*20)
			if f.KEV {
				q += 30
			}
			if st.Indirect {
				q -= 10
			}
		}
		if q >= 0 && (weakest < 0 || q < weakest) {
			weakest = q
		}
	}
	s += max(weakest, 0)
	switch m := a.machines[hold.machine]; {
	case hold.container != "":
		s += 10
	case hold.level == levelRoot && m.Kind == "bare-metal":
		s += 60
	case hold.level == levelRoot:
		s += 45
	default:
		s += 25
	}
	return s - 3*len(p.Steps)
}

func (a *analysis) finding(id string) Finding { return a.findings[id] }

func (a *analysis) result() Result {
	sort.SliceStable(a.paths, func(i, j int) bool {
		if a.paths[i].Score != a.paths[j].Score {
			return a.paths[i].Score > a.paths[j].Score
		}
		return a.paths[i].ID < a.paths[j].ID
	})
	// One path per entry and impact: the most dangerous way there. The
	// other ways stay counted, every finding on them keeps its place.
	seen := map[string]bool{}
	kept := a.paths[:0]
	for _, p := range a.paths {
		k := string(p.Entry) + "|" + p.Impact
		if seen[k] {
			continue
		}
		seen[k] = true
		kept = append(kept, p)
	}
	a.paths = kept
	if len(a.paths) > maxPaths {
		a.paths = a.paths[:maxPaths]
	}
	r := Result{Paths: a.paths, Placements: map[string]Placement{}}
	for _, f := range a.in.Findings {
		if !f.Affected {
			continue
		}
		r.Placements[f.ID] = a.place(f)
	}
	return r
}

// place says how a finding relates to the paths, with the reason.
func (a *analysis) place(f Finding) Placement {
	if used := a.used[f.ID]; len(used) > 0 {
		best := Amplifier
		var ids []string
		for id, c := range used {
			ids = append(ids, id)
			if c == OnPathInternet || (c == OnPathLAN && best == Amplifier) {
				best = c
			}
		}
		sort.Strings(ids)
		reason := "opens an attack path from the LAN"
		switch best {
		case OnPathInternet:
			reason = "opens an attack path from the internet"
		case Amplifier:
			reason = "turns a foothold on an attack path into root"
		}
		return Placement{Class: best, Reason: reason, Paths: ids}
	}
	w := a.workloads[f.WorkloadID]
	v := vectorOf(f.Vector)
	machine := a.in.HostMachine[w.HostID]
	host := a.in.Hosts[w.HostID]
	switch {
	case v == "P":
		return Placement{Class: Noise, Reason: "needs physical access to the machine"}
	case a.weak[f.ID]:
		return Placement{Class: Unclear, Reason: "a library of a reachable service; nothing says it is being exploited, and Varde cannot tell whether the service uses the flawed part"}
	case a.truncated:
		return Placement{Class: Unclear, Reason: "too many attack paths to follow them all"}
	case w.Container && a.beyond[w.ID] && !a.entered[w.ID]:
		return Placement{Class: Unclear, Reason: "reachable only over more hops than Varde follows"}
	case w.Container && v == "L" && a.entered[w.ID]:
		return Placement{Class: Unclear, Reason: "a local flaw in the container; it matters once an attacker is inside it"}
	case w.Container && v == "L" && a.known(w):
		return Placement{Class: Noise, Reason: "a local flaw, and no attack path reaches this container"}
	case !w.Container && v == "L" && machine != "" && !a.reach[machine] && a.known(w):
		return Placement{Class: Noise, Reason: "a local flaw, and no attack path reaches this machine"}
	case v == "L":
		return Placement{Class: Unclear, Reason: "a local flaw; it matters once an attacker is on the machine"}
	case w.Container && w.Exposure == "internal" && a.forwarder(w) != "":
		return Placement{Class: Unclear, Reason: a.forwarder(w) + " on its Docker network may forward traffic to it; connect it so Varde reads its routes"}
	case w.Container && w.Exposure == "internal" && a.exposedNeighbour(w) != "":
		return Placement{Class: Noise, Reason: "only containers on its Docker network reach it (such as " + a.exposedNeighbour(w) + "), and no attack path through them uses this flaw"}
	case w.Container && w.Exposure == "internal":
		return Placement{Class: Noise, Reason: "the container publishes no port and no route leads to it"}
	case w.Container && f.ImagePackage != "" && !NetworkPackage(f.ImagePackage) && a.known(w):
		return Placement{Class: Unclear, Reason: "a package of the image; Varde cannot tell whether the app uses it"}
	case w.Package != "" && host.Known && len(host.UnknownPorts) > 0:
		return Placement{Class: Unclear, Reason: fmt.Sprintf("the host listens on port %d, which Varde cannot tie to a package", host.UnknownPorts[0])}
	case w.Package != "" && host.Known:
		return Placement{Class: Noise, Reason: "no reachable service of the host uses " + w.Package}
	}
	return Placement{Class: Unclear, Reason: "Varde does not know which services can reach it"}
}

// forwarder names a reverse proxy or tunnel on a network of w that may
// forward traffic to it: a tunnel always, a proxy when it is reachable.
func (a *analysis) forwarder(w Workload) string {
	for _, o := range a.in.Workloads {
		if !o.Container || o.ID == w.ID || o.HostID != w.HostID || shared(o.Networks, w.Networks) == "" {
			continue
		}
		switch {
		case o.Proxy == "tunnel":
			return "the tunnel " + o.Name
		case o.Proxy == "proxy" && (o.Exposure == "public" || o.Exposure == "lan"):
			return "the reverse proxy " + o.Name
		}
	}
	return ""
}

// exposedNeighbour names a reachable container sharing a network with w.
func (a *analysis) exposedNeighbour(w Workload) string {
	for _, o := range a.in.Workloads {
		if o.Container && o.ID != w.ID && o.HostID == w.HostID && (o.Exposure == "lan" || o.Exposure == "public") && shared(o.Networks, w.Networks) != "" {
			return o.Name
		}
	}
	return ""
}

// known reports whether Varde knows the surface of a workload's host.
func (a *analysis) known(w Workload) bool {
	if w.Container {
		return w.Exposure != "" && w.Exposure != "unknown"
	}
	h := a.in.Hosts[w.HostID]
	return h.Known && len(h.UnknownPorts) == 0
}

// vectorOf returns the attack vector letter of a CVSS v3 vector: N, A, L or
// P; empty when unknown.
func vectorOf(vector string) string {
	for _, part := range strings.Split(vector, "/") {
		if v, ok := strings.CutPrefix(part, "AV:"); ok && len(v) == 1 {
			return v
		}
	}
	return ""
}

// network reports whether an attack vector can be used from an entry:
// network flaws from anywhere, adjacent ones from the LAN. An unknown
// vector is assumed to be remote, marked as such.
func network(v string, e Entry) bool {
	switch v {
	case "N", "":
		return true
	case "A":
		return e == LAN
	}
	return false
}

func stronger(f, g Finding) bool {
	if f.KEV != g.KEV {
		return f.KEV
	}
	if f.CVSS != g.CVSS {
		return f.CVSS > g.CVSS
	}
	return f.ID < g.ID
}

func ident(f Finding) string { return f.AdvisoryID }

func serviceLabel(s Service, machine string) string {
	what := fmt.Sprintf("port %d/%s on %s", s.Port, s.Proto, machine)
	if s.Port == 0 {
		// A container reached through a route or a network, no port known.
		what = machine
	}
	if s.Product != "" {
		what = s.Product + " (" + what + ")"
	}
	return what
}

func enterLabel(s Service, machine string) string {
	what := serviceLabel(s, machine)
	switch {
	case s.Entry == Internet && s.Via != "" && s.Via != "scan" && s.Via != "listener":
		return "From the internet through " + s.Via + " to " + what
	case s.Entry == Internet:
		return "From the internet to " + what
	}
	return "From the LAN to " + what
}

func clone(s []Step) []Step { return append([]Step(nil), s...) }

func pathID(key string) string {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("p%016x", h)
}
