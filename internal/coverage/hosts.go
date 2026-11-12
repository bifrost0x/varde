// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// Evidence sources. Each is one way Varde learned that a machine exists.
const (
	EvidenceScan    = "scan"
	EvidenceProxmox = "proxmox"
	EvidenceSSH     = "ssh"
	// EvidenceSSHInventory reads native packages and services over SSH.
	EvidenceSSHInventory = "ssh-inventory"
	// EvidenceEndpoint is an app that reported its version over the
	// network.
	EvidenceEndpoint = "endpoint"
	// EvidenceNodeInventory reads an LXC container's packages through its
	// Proxmox node.
	EvidenceNodeInventory = "node-inventory"
	// EvidenceLease is a router or DHCP server that knows the device.
	EvidenceLease = "lease"
	// EvidenceAppliance is an appliance's own API reporting its firmware.
	EvidenceAppliance = "appliance"
	EvidenceAgent     = "agent"
	EvidenceLocal     = "local"
	EvidenceManual    = "manual"
)

// Evidence states.
const (
	// EvidenceActive is a source that reported recently.
	EvidenceActive = "active"
	// EvidenceStale is a source that stopped reporting.
	EvidenceStale = "stale"
	// EvidencePaused is a source whose integration the user switched off.
	EvidencePaused = "paused"
)

// Machine states.
const (
	// MachineInventoried: a source that reads workloads reports for it.
	MachineInventoried = "inventoried"
	// MachineStale: every source that read its workloads stopped reporting.
	MachineStale = "stale"
	// MachinePaused: its workloads come from a switched-off integration.
	MachinePaused = "paused"
	// MachineSeen: Varde knows it exists (scan, Proxmox) but reads nothing
	// on it.
	MachineSeen = "seen"
)

// Evidence is one source's view of a machine.
type Evidence struct {
	Source string `json:"source"`
	// HostID is the stored host the evidence comes from; empty for a scan.
	HostID        string    `json:"host_id,omitempty"`
	IntegrationID string    `json:"integration_id,omitempty"`
	Name          string    `json:"name,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	Addresses     []string  `json:"addresses,omitempty"`
	LastSeen      time.Time `json:"last_seen"`
	State         string    `json:"state"`
	// ReadsWorkloads is set for sources that report what runs on the
	// machine (local Docker, Docker over SSH, agents, manual entries).
	ReadsWorkloads bool `json:"reads_workloads"`
}

// Machine is one physical host, VM, container guest or device, with the
// evidence of every source that knows it. It is the single host record all
// pages, counters and the API use.
type Machine struct {
	// ID is the ID of the primary stored host, or "device:<address>" for a
	// machine only the scan found.
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	OS        string     `json:"os,omitempty"`
	Addresses []string   `json:"addresses,omitempty"`
	Evidence  []Evidence `json:"evidence"`
	// HostIDs are the stored hosts merged into this machine; workloads
	// belong to one of them.
	HostIDs   []string  `json:"host_ids,omitempty"`
	Workloads int       `json:"workloads"`
	State     string    `json:"state"`
	LastSeen  time.Time `json:"last_seen"`
	// Self marks the machine Varde runs on.
	Self bool `json:"self,omitempty"`
	// MACs and MachineID are identity keys reported by the sources.
	MACs      []string `json:"macs,omitempty"`
	MachineID string   `json:"machine_id,omitempty"`
	// ParentID and ParentName name the machine this one runs on (a Proxmox
	// guest's node).
	ParentID   string `json:"parent_id,omitempty"`
	ParentName string `json:"parent_name,omitempty"`
	// parentRecords are the parent host records named by the sources.
	parentRecords []string
	// Keys are the strong identity keys ("host:<id>", "mac:<mac>",
	// "mid:<machine-id>") that tie the machine to its stable asset ID.
	Keys []string `json:"-"`
}

// AssetKeys returns the identity keys of every host (devices only seen by
// the scan get no asset), by machine index.
func AssetKeys(ms []Machine) map[int][]string {
	out := map[int][]string{}
	for i, m := range ms {
		if m.IsHost() && len(m.Keys) > 0 {
			out[i] = m.Keys
		}
	}
	return out
}

// ApplyAssetIDs replaces the IDs of hosts by their stable asset ID, found
// through any of their keys. Hosts without a known key keep the ID of
// their best source until the next asset refresh.
func ApplyAssetIDs(ms []Machine, owner map[string]string) {
	for i := range ms {
		for _, k := range ms[i].Keys {
			if id, ok := owner[k]; ok {
				ms[i].ID = id
				break
			}
		}
	}
	resolveParents(ms)
}

// resolveParents points every machine at the machine of its parent record.
func resolveParents(ms []Machine) {
	byRecord := map[string]int{}
	for i, m := range ms {
		for _, id := range m.HostIDs {
			byRecord[id] = i
		}
	}
	for i := range ms {
		ms[i].ParentID, ms[i].ParentName = "", ""
		for _, rec := range ms[i].parentRecords {
			if j, ok := byRecord[rec]; ok && j != i {
				ms[i].ParentID, ms[i].ParentName = ms[j].ID, ms[j].Name
				break
			}
		}
	}
}

// Inventoried reports whether Varde currently reads the workloads.
func (m Machine) Inventoried() bool { return m.State == MachineInventoried }

// IsHost reports whether a platform knows the machine; a machine only the
// scan or a router knows is a device.
func (m Machine) IsHost() bool {
	for _, e := range m.Evidence {
		if e.Source != EvidenceScan && e.Source != EvidenceLease {
			return true
		}
	}
	return false
}

// Has reports whether a source of the given kind knows the machine.
func (m Machine) Has(source string) bool {
	for _, e := range m.Evidence {
		if e.Source == source {
			return true
		}
	}
	return false
}

// MachineInput is what building the machines needs.
type MachineInput struct {
	Hosts        []inventory.Host
	Devices      []store.StoredDevice
	Integrations []store.Integration
	// Scope limits the devices shown and the addresses used for merging.
	Scope discovery.Scope
	// Workloads counts the present workloads per stored host.
	Workloads map[string]int
	// Now and Interval decide which integrations are failing (see
	// IntegrationHealth).
	Now      time.Time
	Interval func(kind string) time.Duration
}

// sourceRank orders sources by how well they identify a machine; the best
// one gives the machine its ID, name and kind.
var sourceRank = map[string]int{EvidenceProxmox: 0, EvidenceAgent: 1, EvidenceSSH: 2, EvidenceSSHInventory: 3, EvidenceNodeInventory: 3, EvidenceLocal: 4, EvidenceManual: 5, EvidenceEndpoint: 6, EvidenceAppliance: 6, EvidenceLease: 7, EvidenceScan: 8}

type unit struct {
	ev   Evidence
	host *inventory.Host
	dev  *store.StoredDevice
}

// Machines merges stored hosts and scanned devices into machines. Units are
// merged when they share an address inside the scope, unless that would put
// two records of the same platform into one machine (two Proxmox guests, two
// agents): those stay apart, because a shared address there means a NAT,
// a VIP or a stale record rather than the same machine. Revoked agents and
// devices outside the scope are left out.
func Machines(in MachineInput) []Machine {
	paused, failing := map[string]bool{}, map[string]bool{}
	for _, it := range in.Integrations {
		var iv time.Duration
		if in.Interval != nil {
			iv = in.Interval(it.Kind)
		}
		switch IntegrationHealth(it, in.Now, iv) {
		case HealthOff:
			paused[it.ID] = true
		case HealthFailing:
			failing[it.ID] = true
		}
	}
	var units []unit
	for i := range in.Hosts {
		h := &in.Hosts[i]
		if h.State == inventory.HostRevoked {
			continue
		}
		ev := Evidence{
			Source: hostSource(*h), HostID: h.ID, IntegrationID: h.IntegrationID, Name: h.Name, Detail: h.Detail,
			Addresses: h.Addresses, LastSeen: h.LastContact, State: EvidenceActive,
		}
		ev.ReadsWorkloads = ev.Source != EvidenceProxmox && ev.Source != EvidenceLease
		switch {
		case h.IntegrationID != "" && paused[h.IntegrationID]:
			ev.State = EvidencePaused
		case h.State == inventory.HostStale, h.IntegrationID != "" && failing[h.IntegrationID]:
			ev.State = EvidenceStale
		}
		units = append(units, unit{ev: ev, host: h})
	}
	for i := range in.Devices {
		d := &in.Devices[i]
		a, err := netip.ParseAddr(d.Address)
		if err != nil || !in.Scope.Contains(a) {
			continue
		}
		units = append(units, unit{dev: d, ev: Evidence{
			Source: EvidenceScan, Name: d.Hostname, Detail: d.Label, Addresses: []string{d.Address},
			LastSeen: d.LastSeen, State: EvidenceActive,
		}})
	}

	// Addresses usable for merging: inside the scope, and not claimed by
	// two records of the same platform.
	claims := map[string][]int{}
	for i, u := range units {
		for _, a := range u.ev.Addresses {
			if mergeable(a, in.Scope) {
				claims[a] = append(claims[a], i)
			}
		}
		// MACs and machine-ids identify a machine across networks, so they
		// merge even without a shared address in the scope.
		if u.host != nil {
			for _, mac := range u.host.MACs {
				claims["mac:"+strings.ToLower(mac)] = append(claims["mac:"+strings.ToLower(mac)], i)
			}
			if u.host.MachineID != "" {
				claims["mid:"+u.host.MachineID] = append(claims["mid:"+u.host.MachineID], i)
			}
		}
	}
	addrs := make([]string, 0, len(claims))
	for a := range claims {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)

	parent := make([]int, len(units))
	sources := make([]map[string]bool, len(units))
	for i, u := range units {
		parent[i] = i
		sources[i] = map[string]bool{}
		// Several scans or routers may see one device; only platform
		// records must not merge with their own kind.
		if u.ev.Source != EvidenceScan && u.ev.Source != EvidenceLease {
			sources[i][u.ev.Source] = true
		}
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	for _, a := range addrs {
		us := claims[a]
		if ambiguous(units, us) {
			continue
		}
		for _, j := range us[1:] {
			x, y := find(us[0]), find(j)
			if x == y || overlaps(sources[x], sources[y]) {
				continue
			}
			parent[y] = x
			for s := range sources[y] {
				sources[x][s] = true
			}
		}
	}

	groups := map[int][]unit{}
	var roots []int
	for i := range units {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], units[i])
	}
	out := make([]Machine, 0, len(roots))
	for _, r := range roots {
		out = append(out, build(groups[r], in.Workloads))
	}
	resolveParents(out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Self != out[j].Self {
			return out[i].Self
		}
		if out[i].IsHost() != out[j].IsHost() {
			return out[i].IsHost()
		}
		return lessName(out[i], out[j])
	})
	return out
}

func lessName(a, b Machine) bool {
	x, y := strings.ToLower(a.Name), strings.ToLower(b.Name)
	if x != y {
		return x < y
	}
	return a.ID < b.ID
}

func hostSource(h inventory.Host) string {
	switch h.Source {
	case inventory.SourceProxmox:
		return EvidenceProxmox
	case inventory.SourceSSH:
		return EvidenceSSH
	case inventory.SourceSSHInventory:
		return EvidenceSSHInventory
	case inventory.SourceEndpoint:
		return EvidenceEndpoint
	case inventory.SourceNodeInventory:
		return EvidenceNodeInventory
	case inventory.SourceLease:
		return EvidenceLease
	case inventory.SourceAppliance:
		return EvidenceAppliance
	case inventory.SourceAgent:
		return EvidenceAgent
	case inventory.SourceManual:
		return EvidenceManual
	}
	return EvidenceLocal
}

// mergeable reports whether an address may tie records together: a valid
// unicast address inside the scope. Loopback and link-local addresses are
// the same on every machine.
func mergeable(a string, scope discovery.Scope) bool {
	ip, err := netip.ParseAddr(a)
	if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return scope.Contains(ip.Unmap())
}

// ambiguous reports whether two records of the same platform claim the
// address.
func ambiguous(units []unit, idx []int) bool {
	seen := map[string]bool{}
	for _, i := range idx {
		s := units[i].ev.Source
		if s == EvidenceScan || s == EvidenceLease {
			continue
		}
		if seen[s] {
			return true
		}
		seen[s] = true
	}
	return false
}

func overlaps(a, b map[string]bool) bool {
	for s := range a {
		if b[s] {
			return true
		}
	}
	return false
}

func build(us []unit, workloads map[string]int) Machine {
	sort.SliceStable(us, func(i, j int) bool { return sourceRank[us[i].ev.Source] < sourceRank[us[j].ev.Source] })
	m := Machine{State: MachineSeen}
	addrSeen := map[string]bool{}
	var reading, stale, pausedOnly bool
	for _, u := range us {
		m.Evidence = append(m.Evidence, u.ev)
		for _, a := range u.ev.Addresses {
			if !addrSeen[a] {
				addrSeen[a] = true
				m.Addresses = append(m.Addresses, a)
			}
		}
		if u.ev.LastSeen.After(m.LastSeen) {
			m.LastSeen = u.ev.LastSeen
		}
		if u.host != nil {
			m.HostIDs = append(m.HostIDs, u.host.ID)
			m.Keys = append(m.Keys, "host:"+u.host.ID)
			for _, mac := range u.host.MACs {
				mac = strings.ToLower(mac)
				if !slices.Contains(m.MACs, mac) {
					m.MACs = append(m.MACs, mac)
					m.Keys = append(m.Keys, "mac:"+mac)
				}
			}
			if u.host.ParentID != "" {
				m.parentRecords = append(m.parentRecords, u.host.ParentID)
			}
			if id := u.host.MachineID; id != "" && m.MachineID == "" {
				m.MachineID = id
				m.Keys = append(m.Keys, "mid:"+id)
			}
			m.Workloads += workloads[u.host.ID]
			if u.host.ID == inventory.LocalHostID {
				m.Self = true
			}
			if m.OS == "" {
				m.OS = u.host.OS
			}
		}
		if u.ev.ReadsWorkloads {
			switch u.ev.State {
			case EvidenceActive:
				reading = true
			case EvidenceStale:
				stale = true
			case EvidencePaused:
				pausedOnly = true
			}
		}
	}
	switch {
	case reading:
		m.State = MachineInventoried
	case stale:
		m.State = MachineStale
	case pausedOnly:
		m.State = MachinePaused
	}
	sortAddrs(m.Addresses)
	p := us[0]
	switch {
	case p.host != nil && p.ev.Source == EvidenceLease:
		m.ID, m.Kind = p.host.ID, "device"
	case p.host != nil:
		m.ID, m.Kind = p.host.ID, machineKind(*p.host)
	default:
		m.ID, m.Kind = "device:"+p.dev.Address, "device"
	}
	for _, u := range us {
		if u.ev.Name != "" {
			m.Name = u.ev.Name
			break
		}
	}
	if m.Name == "" && len(m.Addresses) > 0 {
		m.Name = m.Addresses[0]
	}
	return m
}

func machineKind(h inventory.Host) string {
	if h.Kind == inventory.HostProxmoxGuest {
		// The Proxmox API names the guest type; the node inventory names
		// the guest's distribution and marks containers by their ID.
		if h.OS == "LXC container" || (h.Source == inventory.SourceNodeInventory && strings.HasPrefix(h.ID, "pvelxc-")) {
			return "lxc"
		}
		return "vm"
	}
	return string(h.Kind)
}

func sortAddrs(as []string) {
	sort.SliceStable(as, func(i, j int) bool {
		x, ex := netip.ParseAddr(as[i])
		y, ey := netip.ParseAddr(as[j])
		if ex != nil || ey != nil {
			return as[i] < as[j]
		}
		if x.Is4() != y.Is4() {
			return x.Is4()
		}
		return x.Less(y)
	})
}

// MachineCounts summarises machines for the overview and the API.
type MachineCounts struct {
	// Hosts are machines a platform knows; Inventoried of them have their
	// workloads read now, Stale stopped reporting, Paused belong to a
	// switched-off integration.
	Hosts       int `json:"hosts"`
	Inventoried int `json:"inventoried"`
	Stale       int `json:"stale"`
	Paused      int `json:"paused"`
	// Devices were only found by the scan.
	Devices int `json:"devices"`
}

// CountMachines counts machines by state.
func CountMachines(ms []Machine) MachineCounts {
	var c MachineCounts
	for _, m := range ms {
		if !m.IsHost() {
			c.Devices++
			continue
		}
		c.Hosts++
		switch m.State {
		case MachineInventoried:
			c.Inventoried++
		case MachineStale:
			c.Stale++
		case MachinePaused:
			c.Paused++
		}
	}
	return c
}

// LastInventory is the newest report of an active source that reads
// workloads; zero when none reported.
func LastInventory(ms []Machine) time.Time {
	var t time.Time
	for _, m := range ms {
		for _, e := range m.Evidence {
			if e.ReadsWorkloads && e.State == EvidenceActive && e.LastSeen.After(t) {
				t = e.LastSeen
			}
		}
	}
	return t
}
