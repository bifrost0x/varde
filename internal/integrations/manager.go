// SPDX-License-Identifier: Apache-2.0

// Package integrations connects Varde to platforms through their official
// interfaces (ADR 0020): the Proxmox VE API with a read-only token and the
// Docker Engine API over SSH. Each integration is switched on and off on
// its own. Every connection is restricted to the networks the user allowed
// (discovery.Scope).
package integrations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/store"
)

// Store is what the manager persists.
type Store interface {
	inventory.SnapshotStore
	Integrations(ctx context.Context) ([]store.Integration, error)
	GetIntegration(ctx context.Context, id string) (store.Integration, error)
	CreateIntegration(ctx context.Context, in store.Integration) error
	DeleteIntegration(ctx context.Context, id string) error
	SetIntegrationEnabled(ctx context.Context, id string, enabled bool) error
	RecordIntegrationRun(ctx context.Context, id string, runErr error, status any, now time.Time) error
	SyncIntegrationHosts(ctx context.Context, integrationID string, hosts []inventory.Host) error
	RecordDevices(ctx context.Context, devs []discovery.Device, scanned func(addr string) bool, now time.Time) error
	RecordScanRun(ctx context.Context, r store.ScanRun) error
	LastScanRun(ctx context.Context) (store.ScanRun, error)
	Hosts(ctx context.Context) ([]inventory.Host, error)
	Workloads(ctx context.Context, f store.WorkloadFilter) ([]inventory.Workload, error)
	Identifications(ctx context.Context) (map[string]identify.Result, error)
	SetHostPackages(ctx context.Context, p store.HostPackages) error
	ApplyAgentInventory(ctx context.Context, hostID string, inv store.AgentInventory, now time.Time) (inventory.Changes, error)
}

// Options configures a Manager.
type Options struct {
	Store Store
	// SNMP is what scans send to read device descriptions; nil sends no
	// SNMP.
	SNMP    *discovery.SNMP
	DataDir string
	// Scope returns the networks Varde may contact; read on every
	// connection so a change applies immediately.
	Scope func() discovery.Scope
	// Changed is called after an integration changed the inventory.
	Changed func(ctx context.Context)
	Log     *slog.Logger
	// ProxmoxInterval, DockerResync and InventoryInterval pace the
	// collectors.
	ProxmoxInterval, DockerResync, InventoryInterval time.Duration
	// Catalog decides which packages and services are kept; nil keeps
	// none.
	Catalog func() *catalog.Catalog
	// ScanEvery returns the period of scheduled scans; zero or nil means
	// scans run only on request.
	ScanEvery func() time.Duration
	// Packages reads the package databases of images on Docker hosts;
	// nil reads none.
	Packages *docker.PackageReader
}

// Manager runs the enabled integrations and network scans.
type Manager struct {
	o   Options
	box *Box
	id  *Identity
	// inv is the second key, restricted to the inventory command. A host
	// can carry both key lines; one key could only force one command.
	inv *Identity
	// pve is the third key, for root on Proxmox nodes, restricted to the
	// container command.
	pve *Identity

	// dialOverride replaces the scope-checked dialer in tests, which run
	// against loopback servers outside any private range.
	dialOverride func(ctx context.Context, network, addr string) (net.Conn, error)

	mu      sync.Mutex
	ctx     context.Context
	running map[string]*runner
	wg      sync.WaitGroup
	scan    ScanState
}

type runner struct {
	cancel  context.CancelFunc
	trigger func()
}

// New prepares the key material under DataDir. Run starts the integrations.
func New(o Options) (*Manager, error) {
	if o.ProxmoxInterval <= 0 {
		o.ProxmoxInterval = 10 * time.Minute
	}
	if o.DockerResync <= 0 {
		o.DockerResync = 15 * time.Minute
	}
	if o.InventoryInterval <= 0 {
		o.InventoryInterval = time.Hour
	}
	box, err := OpenBox(filepath.Join(o.DataDir, "keys", "integrations.key"))
	if err != nil {
		return nil, err
	}
	id, err := LoadIdentity(filepath.Join(o.DataDir, "ssh", "id_ed25519"))
	if err != nil {
		return nil, err
	}
	inv, err := LoadIdentity(filepath.Join(o.DataDir, "ssh", "id_ed25519_inventory"))
	if err != nil {
		return nil, err
	}
	pve, err := LoadIdentity(filepath.Join(o.DataDir, "ssh", "id_ed25519_proxmox"))
	if err != nil {
		return nil, err
	}
	return &Manager{o: o, box: box, id: id, inv: inv, pve: pve, running: map[string]*runner{}}, nil
}

// Interval is how often an integration of the kind reads; zero for an
// unknown kind. It decides when an integration counts as failing.
func (m *Manager) Interval(kind string) time.Duration {
	switch kind {
	case KindProxmox:
		return m.o.ProxmoxInterval
	case KindDockerSSH:
		return m.o.DockerResync
	case KindSSHInventory, KindProxmoxLXC:
		return m.o.InventoryInterval
	}
	if _, ok := ServiceKinds[kind]; ok {
		return serviceInterval
	}
	return 0
}

// serviceInterval paces the service integrations.
const serviceInterval = 15 * time.Minute

// ProxmoxIdentity returns Varde's key for Proxmox nodes.
func (m *Manager) ProxmoxIdentity() *Identity { return m.pve }

// InventoryIdentity returns Varde's inventory key.
func (m *Manager) InventoryIdentity() *Identity { return m.inv }

// Identity returns Varde's SSH key.
func (m *Manager) Identity() *Identity { return m.id }

// Dial connects inside the current scope.
func (m *Manager) Dial() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if m.dialOverride != nil {
		return m.dialOverride
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return m.o.Scope().DialContext(&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second})(ctx, network, addr)
	}
}

// Run starts every enabled integration and blocks until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	last, err := m.o.Store.LastScanRun(ctx)
	switch {
	case err == nil:
		m.mu.Lock()
		m.scan = ScanState{Done: last.Addresses, Total: last.Addresses, Found: last.Found, Intercepted: last.Intercepted,
			Started: last.Started, Ended: last.Ended, Err: last.Error, Trigger: last.Trigger}
		m.mu.Unlock()
	case !errors.Is(err, store.ErrNotFound):
		m.o.Log.Error("loading the last scan failed", "err", err)
	}
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	ins, err := m.o.Store.Integrations(ctx)
	if err != nil {
		m.o.Log.Error("loading integrations failed", "err", err)
	}
	for _, in := range ins {
		if in.Enabled {
			m.start(in)
		}
	}
	m.wg.Go(func() { m.runSchedule(ctx) })
	<-ctx.Done()
	m.wg.Wait()
}

// runSchedule starts a scan when the period since the last one has passed.
// Scheduled scans use the same scanner and limits as manual ones.
func (m *Manager) runSchedule(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if m.scheduledScanDue(time.Now()) {
			if err := m.startScan("schedule"); err != nil && !errors.Is(err, ErrScanRunning) && !errors.Is(err, ErrNoScope) {
				m.o.Log.Warn("scheduled network scan not started", "err", err)
			}
		}
	}
}

// scheduledScanDue reports whether a scheduled scan should start at now.
func (m *Manager) scheduledScanDue(now time.Time) bool {
	if m.o.ScanEvery == nil {
		return false
	}
	every := m.o.ScanEvery()
	if every <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scan.Running {
		return false
	}
	last := m.scan.Ended
	if last.IsZero() {
		last = m.scan.Started
	}
	return now.Sub(last) >= every
}

func (m *Manager) start(in store.Integration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil || m.running[in.ID] != nil {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	r := &runner{cancel: cancel}
	m.running[in.ID] = r
	switch in.Kind {
	case KindProxmox:
		trig := make(chan struct{}, 1)
		r.trigger = func() {
			select {
			case trig <- struct{}{}:
			default:
			}
		}
		m.wg.Go(func() { m.runProxmox(ctx, in, trig) })
	case KindDockerSSH:
		m.wg.Go(func() { m.runDocker(ctx, in, r) })
	case KindSSHInventory:
		trig := make(chan struct{}, 1)
		r.trigger = func() {
			select {
			case trig <- struct{}{}:
			default:
			}
		}
		m.wg.Go(func() { m.runInventory(ctx, in, trig) })
	case KindProxmoxLXC:
		trig := make(chan struct{}, 1)
		r.trigger = func() {
			select {
			case trig <- struct{}{}:
			default:
			}
		}
		m.wg.Go(func() { m.runLXC(ctx, in, trig) })
	default:
		// Every service kind, the appliances included, runs the same
		// way; listing them here by hand left new kinds unscheduled.
		if _, ok := ServiceKinds[in.Kind]; !ok {
			m.o.Log.Warn("unknown integration kind", "kind", in.Kind, "id", in.ID)
			return
		}
		trig := make(chan struct{}, 1)
		r.trigger = func() {
			select {
			case trig <- struct{}{}:
			default:
			}
		}
		m.wg.Go(func() { m.runService(ctx, in, trig) })
	}
}

func (m *Manager) stop(id string) {
	m.mu.Lock()
	r := m.running[id]
	delete(m.running, id)
	m.mu.Unlock()
	if r != nil {
		r.cancel()
	}
}

// Trigger asks every running integration to collect now.
func (m *Manager) Trigger() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.running {
		if r.trigger != nil {
			r.trigger()
		}
	}
}

// TriggerIntegration asks one running integration to collect now. It
// reports false when the integration is not running (unknown or switched
// off).
func (m *Manager) TriggerIntegration(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.running[id]
	if r == nil {
		return false
	}
	if r.trigger != nil {
		r.trigger()
	}
	return true
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AddProxmox verifies the connection and stores a Proxmox integration.
func (m *Manager) AddProxmox(ctx context.Context, cfg ProxmoxConfig, secret, actor string, now time.Time) (store.Integration, ProxmoxStatus, error) {
	u, err := ParseProxmoxURL(cfg.URL)
	if err != nil {
		return store.Integration{}, ProxmoxStatus{}, err
	}
	cfg.URL = u.String()
	pc, err := NewProxmox(cfg, secret, m.Dial())
	if err != nil {
		return store.Integration{}, ProxmoxStatus{}, err
	}
	st, err := pc.Collect(ctx)
	if err != nil {
		return store.Integration{}, ProxmoxStatus{}, err
	}
	in := store.Integration{ID: newID(), Kind: KindProxmox, Name: "Proxmox " + u.Hostname(), Address: u.Hostname(), Enabled: true, CreatedBy: actor, CreatedAt: now}
	if in.Config, err = json.Marshal(cfg); err != nil {
		return in, st, err
	}
	if in.Secret, err = m.box.Seal(in.ID, []byte(secret)); err != nil {
		return in, st, err
	}
	if err := m.o.Store.CreateIntegration(ctx, in); err != nil {
		return in, st, err
	}
	if err := m.storeProxmox(ctx, in, st, now); err != nil {
		return in, st, err
	}
	m.start(in)
	return in, st, nil
}

// AddDockerSSH verifies the SSH connection and the Docker API and stores the
// integration.
func (m *Manager) AddDockerSSH(ctx context.Context, cfg DockerSSHConfig, actor string, now time.Time) (store.Integration, string, error) {
	conn, err := NewDockerSSH(cfg, m.id, m.Dial())
	if err != nil {
		return store.Integration{}, "", err
	}
	defer conn.Close()
	client := docker.NewDialer(conn.DialDocker)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	v, err := client.Negotiate(cctx)
	if err != nil {
		return store.Integration{}, "", fmt.Errorf("reading the Docker API over SSH: %w", err)
	}
	in := store.Integration{ID: newID(), Kind: KindDockerSSH, Name: "Docker " + cfg.Address, Address: cfg.Address, Enabled: true, CreatedBy: actor, CreatedAt: now}
	if in.Config, err = json.Marshal(cfg); err != nil {
		return in, "", err
	}
	if err := m.o.Store.CreateIntegration(ctx, in); err != nil {
		return in, "", err
	}
	m.start(in)
	return in, v.Version, nil
}

// AddSSHInventory verifies that the host runs the inventory command and
// stores the integration.
func (m *Manager) AddSSHInventory(ctx context.Context, cfg DockerSSHConfig, actor string, now time.Time) (store.Integration, InventoryStatus, error) {
	conn, err := NewDockerSSH(cfg, m.inv, m.Dial())
	if err != nil {
		return store.Integration{}, InventoryStatus{}, err
	}
	defer conn.Close()
	out, err := conn.RunInventory(ctx)
	if err != nil {
		return store.Integration{}, InventoryStatus{}, err
	}
	inv, err := ParseInventory(out)
	if err != nil {
		return store.Integration{}, InventoryStatus{}, err
	}
	in := store.Integration{ID: newID(), Kind: KindSSHInventory, Name: "Packages " + cfg.Address, Address: cfg.Address, Enabled: true, CreatedBy: actor, CreatedAt: now}
	if in.Config, err = json.Marshal(cfg); err != nil {
		return in, InventoryStatus{}, err
	}
	if err := m.o.Store.CreateIntegration(ctx, in); err != nil {
		return in, InventoryStatus{}, err
	}
	st, err := m.storeInventory(ctx, in, cfg, inv, now)
	if err != nil {
		return in, st, err
	}
	m.start(in)
	return in, st, nil
}

func (m *Manager) runInventory(ctx context.Context, in store.Integration, trig <-chan struct{}) {
	var cfg DockerSSHConfig
	if err := json.Unmarshal(in.Config, &cfg); err != nil {
		m.record(ctx, in.ID, fmt.Errorf("invalid configuration: %w", err), nil)
		return
	}
	// The first read happened when the integration was added or at the
	// last start; wait a little so a restart does not hit every host at
	// once.
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-trig:
		case <-t.C:
		}
		err := m.readInventory(ctx, in, cfg)
		if err != nil && ctx.Err() == nil {
			m.o.Log.Warn("package inventory failed", "integration", in.Name, "err", err)
			m.record(ctx, in.ID, err, nil)
		}
		t.Reset(m.o.InventoryInterval)
	}
}

func (m *Manager) readInventory(ctx context.Context, in store.Integration, cfg DockerSSHConfig) error {
	conn, err := NewDockerSSH(cfg, m.inv, m.Dial())
	if err != nil {
		return err
	}
	defer conn.Close()
	out, err := conn.RunInventory(ctx)
	if err != nil {
		return err
	}
	inv, err := ParseInventory(out)
	if err != nil {
		return err
	}
	_, err = m.storeInventory(ctx, in, cfg, inv, time.Now())
	return err
}

// storeInventory records the host with the packages and services the
// catalog knows.
func (m *Manager) storeInventory(ctx context.Context, in store.Integration, cfg DockerSSHConfig, inv HostInventory, now time.Time) (InventoryStatus, error) {
	var cat *catalog.Catalog
	if m.o.Catalog != nil {
		cat = m.o.Catalog()
	}
	st := InventoryStatus{OS: inv.OS, Packages: len(inv.Packages), Services: len(inv.Services)}
	var pkgs, svcs []inventory.Workload
	if cat != nil {
		pkgs, svcs, _ = InventoryWorkloads(cat, inv)
	}
	st.Apps = len(pkgs) + len(svcs)
	// Every source package is checked against the distribution's data.
	pkgs = append(pkgs, SystemWorkloads(cat, inv)...)
	name := inv.Hostname
	if name == "" {
		name = cfg.Address
	}
	h := inventory.Host{
		ID: "sshinv-" + in.ID, Name: name, Kind: inventory.HostLinux, Source: inventory.SourceSSHInventory, OS: inv.OS,
		Addresses: []string{cfg.Address}, LastContact: now, IntegrationID: in.ID,
		Detail: fmt.Sprintf("%d packages, %d services read", st.Packages, st.Services),
		MACs:   inv.MACs, MachineID: inv.MachineID,
	}
	if err := m.o.Store.SyncIntegrationHosts(ctx, in.ID, []inventory.Host{h}); err != nil {
		return st, err
	}
	// The full inventory: every package, not only those of catalog apps.
	if err := m.o.Store.SetHostPackages(ctx, store.HostPackages{HostID: h.ID, Distro: inv.Distro, OS: inv.OS, Packages: inv.Packages, Read: now,
		Kernel: inv.Kernel, Reboot: RebootReason(inv), Listen: inv.Listen}); err != nil {
		return st, err
	}
	var changed bool
	for _, set := range []struct {
		kind inventory.Kind
		ws   []inventory.Workload
	}{{inventory.KindPackage, pkgs}, {inventory.KindService, svcs}} {
		c, err := m.o.Store.ApplySnapshot(ctx, h.ID, set.kind, set.ws, now)
		if err != nil {
			return st, err
		}
		changed = changed || c.Any()
	}
	m.record(ctx, in.ID, nil, st)
	if changed && m.o.Changed != nil {
		m.o.Changed(ctx)
	}
	return st, nil
}

// StoreAgentInventory records the host inventory an agent delivered: the
// output of InventoryCommand run on the host, parsed as the SSH inventory
// is, since the agent is no more trusted than a host answering over SSH.
// It does not trigger analysis; the agent listener does.
func (m *Manager) StoreAgentInventory(ctx context.Context, hostID string, raw []byte, now time.Time) (bool, error) {
	inv, err := ParseInventory(raw)
	if err != nil {
		return false, fmt.Errorf("%w: %w", wire.ErrBadInventory, err)
	}
	var pkgs, svcs []inventory.Workload
	if m.o.Catalog != nil {
		if cat := m.o.Catalog(); cat != nil {
			pkgs, svcs, _ = InventoryWorkloads(cat, inv)
		}
	}
	pkgs = append(pkgs, SystemWorkloads(m.catalog(), inv)...)
	c, err := m.o.Store.ApplyAgentInventory(ctx, hostID, store.AgentInventory{
		MACs: inv.MACs, MachineID: inv.MachineID,
		Packages: store.HostPackages{Distro: inv.Distro, OS: inv.OS, Packages: inv.Packages, Read: now, Kernel: inv.Kernel, Reboot: RebootReason(inv), Listen: inv.Listen},
		Apps:     pkgs, Services: svcs,
	}, now)
	return c.Any(), err
}

// Remove stops an integration and deletes it with the hosts it reported.
func (m *Manager) Remove(ctx context.Context, id string) error {
	m.stop(id)
	return m.o.Store.DeleteIntegration(ctx, id)
}

// SetEnabled switches an integration on or off.
func (m *Manager) SetEnabled(ctx context.Context, id string, enabled bool) error {
	if err := m.o.Store.SetIntegrationEnabled(ctx, id, enabled); err != nil {
		return err
	}
	if !enabled {
		m.stop(id)
		return nil
	}
	in, err := m.o.Store.GetIntegration(ctx, id)
	if err != nil {
		return err
	}
	m.start(in)
	return nil
}

func (m *Manager) runProxmox(ctx context.Context, in store.Integration, trig <-chan struct{}) {
	var cfg ProxmoxConfig
	if err := json.Unmarshal(in.Config, &cfg); err != nil {
		m.record(ctx, in.ID, fmt.Errorf("invalid configuration: %w", err), nil)
		return
	}
	secret, err := m.box.Open(in.ID, in.Secret)
	if err != nil {
		m.record(ctx, in.ID, err, nil)
		return
	}
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-trig:
		case <-t.C:
		}
		pc, err := NewProxmox(cfg, string(secret), m.Dial())
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			var st ProxmoxStatus
			st, err = pc.Collect(cctx)
			cancel()
			if err == nil {
				err = m.storeProxmox(ctx, in, st, time.Now())
			}
		}
		if err != nil && ctx.Err() == nil {
			m.o.Log.Warn("Proxmox collection failed", "integration", in.Name, "err", err)
			m.record(ctx, in.ID, err, nil)
		}
		t.Reset(m.o.ProxmoxInterval)
	}
}

// storeProxmox records nodes and guests as hosts and the full status for
// the network page.
func (m *Manager) storeProxmox(ctx context.Context, in store.Integration, st ProxmoxStatus, now time.Time) error {
	var hosts []inventory.Host
	for _, n := range st.Nodes {
		state := "online"
		if !n.Online {
			state = "offline"
		}
		hosts = append(hosts, inventory.Host{
			ID: "pve-" + in.ID + "-node-" + n.Name, Name: n.Name, Kind: inventory.HostBareMetal, Source: inventory.SourceProxmox,
			OS: "Proxmox VE " + st.Version, Addresses: n.Addresses, LastContact: now, IntegrationID: in.ID,
			Detail: "Proxmox node, " + state,
		})
	}
	for _, g := range st.Guests {
		os := "QEMU VM"
		if g.Type == "lxc" {
			os = "LXC container"
		}
		detail := g.Status + " on " + g.Node
		if g.AddressNote != "" {
			detail += "; " + g.AddressNote
		}
		hosts = append(hosts, inventory.Host{
			ID: "pve-" + in.ID + "-" + strconv.Itoa(g.VMID), Name: g.Name, Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox,
			OS: os, Addresses: g.Addresses, LastContact: now, IntegrationID: in.ID, Detail: detail, MACs: g.MACs,
			ParentID: "pve-" + in.ID + "-node-" + g.Node,
		})
	}
	if err := m.o.Store.SyncIntegrationHosts(ctx, in.ID, hosts); err != nil {
		return err
	}
	// The API reports the pve-manager version of the node Varde talks to;
	// it becomes a package workload there, so the catalog entry for
	// Proxmox VE checks it against advisories.
	apiNode := proxmoxAPINode(st, in.Address)
	for _, n := range st.Nodes {
		var ws []inventory.Workload
		if n.Name == apiNode && st.Version != "" {
			ws = []inventory.Workload{{Kind: inventory.KindPackage, RuntimeID: "dpkg:pve-manager", Name: "pve-manager", State: "installed",
				Package: &inventory.Package{Manager: "dpkg", Name: "pve-manager", Version: st.Version}}}
		}
		if _, err := m.o.Store.ApplySnapshot(ctx, "pve-"+in.ID+"-node-"+n.Name, inventory.KindPackage, ws, now); err != nil {
			return err
		}
	}
	m.record(ctx, in.ID, nil, st)
	if m.o.Changed != nil {
		m.o.Changed(ctx)
	}
	return nil
}

// proxmoxAPINode is the node the integration's address belongs to; with a
// single node, that node. Empty when it cannot be told.
func proxmoxAPINode(st ProxmoxStatus, address string) string {
	for _, n := range st.Nodes {
		for _, a := range n.Addresses {
			if a == address {
				return n.Name
			}
		}
	}
	if len(st.Nodes) == 1 {
		return st.Nodes[0].Name
	}
	return ""
}

// DockerStatus is what the last successful Docker sync saw.
type DockerStatus struct {
	Host       string `json:"host"`
	Version    string `json:"version"`
	Containers int    `json:"containers"`
}

func (m *Manager) runDocker(ctx context.Context, in store.Integration, r *runner) {
	var cfg DockerSSHConfig
	if err := json.Unmarshal(in.Config, &cfg); err != nil {
		m.record(ctx, in.ID, fmt.Errorf("invalid configuration: %w", err), nil)
		return
	}
	conn, err := NewDockerSSH(cfg, m.id, m.Dial())
	if err != nil {
		m.record(ctx, in.ID, err, nil)
		return
	}
	defer conn.Close()
	client := docker.NewDialer(conn.DialDocker)
	dc := docker.NewCollector(client, m.o.Log)
	dc.Packages = m.o.Packages
	col := &recordingCollector{Collector: dc, m: m, id: in.ID, client: client}
	sy := inventory.NewSyncer(inventory.SyncerConfig{
		HostID: "ssh-" + in.ID, HostKind: inventory.HostDocker, Source: inventory.SourceSSH,
		Collector: col, Store: m.o.Store, Log: m.o.Log, Resync: m.o.DockerResync,
		IntegrationID: in.ID, Addresses: []string{cfg.Address},
		OnChange: func(inventory.Changes) {
			if m.o.Changed != nil {
				m.o.Changed(ctx)
			}
		},
	})
	m.mu.Lock()
	r.trigger = sy.Trigger
	m.mu.Unlock()
	sy.Run(ctx)
}

// recordingCollector stores the outcome of every list for the network page.
type recordingCollector struct {
	*docker.Collector
	m      *Manager
	id     string
	client *docker.Client
}

func (c *recordingCollector) List(ctx context.Context) (inventory.Snapshot, error) {
	snap, err := c.Collector.List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			c.m.record(ctx, c.id, err, nil)
		}
		return snap, err
	}
	st := DockerStatus{Host: snap.Host.Name, Containers: len(snap.Workloads)}
	if v, verr := c.client.Negotiate(ctx); verr == nil {
		st.Version = v.Version
	}
	c.m.record(ctx, c.id, nil, st)
	return snap, nil
}

func (m *Manager) record(ctx context.Context, id string, runErr error, status any) {
	if err := m.o.Store.RecordIntegrationRun(context.WithoutCancel(ctx), id, runErr, status, time.Now()); err != nil {
		m.o.Log.Error("recording integration run failed", "id", id, "err", err)
	}
}

// ScanState describes the current or last network scan.
type ScanState struct {
	Running        bool
	Done, Total    int
	Found          int
	Intercepted    []int
	Started, Ended time.Time
	Err            string
	// Trigger is "manual" or "schedule".
	Trigger string
}

// ErrScanRunning is returned when a scan is already in progress.
var ErrScanRunning = errors.New("a scan is already running")

// ErrNoScope is returned when no network is allowed.
var ErrNoScope = errors.New("allow at least one network range first")

// Scan returns the state of the current or last scan.
func (m *Manager) Scan() ScanState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scan
}

// StartScan scans the allowed IPv4 ranges in the background.
func (m *Manager) StartScan() error { return m.startScan("manual") }

func (m *Manager) startScan(trigger string) error {
	scope := m.o.Scope()
	if scope.Empty() {
		return ErrNoScope
	}
	addrs, err := scope.Addresses()
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("the allowed ranges contain no IPv4 addresses to scan")
	}
	sc := discovery.NewScanner(scope)
	sc.SNMP = m.o.SNMP
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil {
		return errors.New("not running")
	}
	if m.scan.Running {
		return ErrScanRunning
	}
	m.scan = ScanState{Running: true, Total: len(addrs) * len(sc.Ports), Started: time.Now(), Trigger: trigger}
	ctx := m.ctx
	m.wg.Go(func() {
		res, err := sc.Scan(ctx, addrs, func(done, _ int) {
			m.mu.Lock()
			m.scan.Done = done
			m.mu.Unlock()
		})
		devs := res.Devices
		if err == nil {
			scanned := map[string]bool{}
			for _, a := range addrs {
				scanned[a.String()] = true
			}
			err = m.o.Store.RecordDevices(ctx, devs, func(a string) bool { return scanned[a] }, time.Now())
		}
		if err == nil {
			// Version endpoints are read after the scan, from the devices
			// it found; a failure there does not fail the scan.
			if verr := m.readVersions(ctx, devs, time.Now()); verr != nil && ctx.Err() == nil {
				m.o.Log.Warn("reading version endpoints failed", "err", verr)
			}
		}
		m.mu.Lock()
		m.scan.Running, m.scan.Ended, m.scan.Found, m.scan.Intercepted = false, time.Now(), len(devs), res.Intercepted
		if err != nil {
			m.scan.Err = err.Error()
		}
		run := store.ScanRun{Trigger: trigger, Networks: scope.String(), Started: m.scan.Started, Ended: m.scan.Ended,
			Addresses: len(addrs), Found: m.scan.Found, Intercepted: m.scan.Intercepted, Error: m.scan.Err}
		m.mu.Unlock()
		if rerr := m.o.Store.RecordScanRun(context.WithoutCancel(ctx), run); rerr != nil {
			m.o.Log.Error("recording the scan failed", "err", rerr)
		}
		if err != nil {
			m.o.Log.Warn("network scan failed", "err", err)
			return
		}
		m.o.Log.Info("network scan complete", "addresses", len(addrs), "devices", len(devs))
	})
	return nil
}

// AddProxmoxLXC verifies that the node runs the container command and
// stores the integration.
func (m *Manager) AddProxmoxLXC(ctx context.Context, cfg DockerSSHConfig, actor string, now time.Time) (store.Integration, LXCStatus, error) {
	cts, err := m.readLXCOnce(ctx, cfg)
	if err != nil {
		return store.Integration{}, LXCStatus{}, err
	}
	in := store.Integration{ID: newID(), Kind: KindProxmoxLXC, Name: "Containers on " + cfg.Address, Address: cfg.Address, Enabled: true, CreatedBy: actor, CreatedAt: now}
	if in.Config, err = json.Marshal(cfg); err != nil {
		return in, LXCStatus{}, err
	}
	if err := m.o.Store.CreateIntegration(ctx, in); err != nil {
		return in, LXCStatus{}, err
	}
	st, err := m.storeLXC(ctx, in, cts, now)
	if err != nil {
		return in, st, err
	}
	m.start(in)
	return in, st, nil
}

func (m *Manager) readLXCOnce(ctx context.Context, cfg DockerSSHConfig) ([]ContainerInventory, error) {
	conn, err := NewDockerSSH(cfg, m.pve, m.Dial())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	out, err := conn.runFixed(ctx, "varde-proxmox-lxc", lxcOutputLimit, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	return ParseLXCInventory(out)
}

func (m *Manager) runLXC(ctx context.Context, in store.Integration, trig <-chan struct{}) {
	var cfg DockerSSHConfig
	if err := json.Unmarshal(in.Config, &cfg); err != nil {
		m.record(ctx, in.ID, fmt.Errorf("invalid configuration: %w", err), nil)
		return
	}
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-trig:
		case <-t.C:
		}
		cts, err := m.readLXCOnce(ctx, cfg)
		if err == nil {
			_, err = m.storeLXC(ctx, in, cts, time.Now())
		}
		if err != nil && ctx.Err() == nil {
			m.o.Log.Warn("container inventory failed", "integration", in.Name, "err", err)
			m.record(ctx, in.ID, err, nil)
		}
		t.Reset(m.o.InventoryInterval)
	}
}

// storeLXC records one host per running guest of the node (LXC container
// or VM) with its full package list, the packages the catalog knows and the
// Docker containers inside. The MAC ties it to the guest Proxmox reports.
func (m *Manager) storeLXC(ctx context.Context, in store.Integration, cts []ContainerInventory, now time.Time) (LXCStatus, error) {
	var cat *catalog.Catalog
	if m.o.Catalog != nil {
		cat = m.o.Catalog()
	}
	var st LXCStatus
	hosts := make([]inventory.Host, 0, len(cts))
	work := map[string][]inventory.Workload{}
	docker := map[string][]inventory.Workload{}
	for _, ct := range cts {
		prefix, label := "pvelxc-", "container"
		switch ct.Kind {
		case GuestVM:
			prefix, label = "pvevm-", "VM"
			if ct.NoAgent {
				st.NoAgent++
			} else {
				st.VMs++
			}
		default:
			st.Containers++
		}
		id := prefix + in.ID + "-" + strconv.Itoa(ct.VMID)
		name := ct.Hostname
		if name == "" {
			name = label + " " + strconv.Itoa(ct.VMID)
		}
		detail := fmt.Sprintf("%s %d on %s, %d packages and %d Docker containers read", label, ct.VMID, in.Address, len(ct.Packages), len(ct.Containers))
		if ct.NoAgent {
			detail = fmt.Sprintf("VM %d on %s: the QEMU guest agent does not answer, so nothing inside is read; install qemu-guest-agent and enable it in the VM options", ct.VMID, in.Address)
		}
		hosts = append(hosts, inventory.Host{
			ID: id, Name: name, Kind: inventory.HostProxmoxGuest, Source: inventory.SourceNodeInventory, OS: ct.OS,
			LastContact: now, IntegrationID: in.ID, MACs: ct.MACs, Detail: detail,
		})
		st.Packages += len(ct.Packages)
		st.Docker += len(ct.Containers)
		if cat != nil {
			pkgs, _, _ := InventoryWorkloads(cat, ct.HostInventory)
			st.Apps += len(pkgs)
			work[id] = pkgs
		}
		work[id] = append(work[id], SystemWorkloads(cat, ct.HostInventory)...)
		docker[id] = guestContainers(ct.Containers)
	}
	if err := m.o.Store.SyncIntegrationHosts(ctx, in.ID, hosts); err != nil {
		return st, err
	}
	for i, ct := range cts {
		if ct.NoAgent {
			continue
		}
		if err := m.o.Store.SetHostPackages(ctx, store.HostPackages{HostID: hosts[i].ID, Distro: ct.Distro, OS: ct.OS, Packages: ct.Packages, Read: now}); err != nil {
			return st, err
		}
	}
	changed := false
	for _, h := range hosts {
		for _, set := range []struct {
			kind inventory.Kind
			ws   []inventory.Workload
		}{{inventory.KindPackage, work[h.ID]}, {inventory.KindContainer, docker[h.ID]}} {
			c, err := m.o.Store.ApplySnapshot(ctx, h.ID, set.kind, set.ws, now)
			if err != nil {
				return st, err
			}
			changed = changed || c.Any()
		}
	}
	m.record(ctx, in.ID, nil, st)
	if changed && m.o.Changed != nil {
		m.o.Changed(ctx)
	}
	return st, nil
}

// guestContainers turns the Docker containers a guest listed into
// container workloads, identified like the containers of a Docker host.
func guestContainers(cs []GuestContainer) []inventory.Workload {
	out := make([]inventory.Workload, 0, len(cs))
	for _, c := range cs {
		labels := c.Labels
		out = append(out, inventory.Workload{
			Kind: inventory.KindContainer, RuntimeID: c.ID, Name: c.Name, State: c.State,
			Container: &inventory.Container{
				ImageRef: c.Image, ImageID: c.ImageID, RepoDigests: c.RepoDigests, Labels: labels,
				ComposeProject: labels["com.docker.compose.project"], ComposeService: labels["com.docker.compose.service"],
			},
		})
	}
	return out
}

// AddService verifies a service integration (Traefik, Nginx Proxy Manager,
// Fritz!Box, OPNsense) by reading it once and stores it with the secret
// sealed.
func (m *Manager) AddService(ctx context.Context, kind string, cfg ServiceConfig, secret, actor string, now time.Time) (store.Integration, ServiceStatus, error) {
	sk, ok := ServiceKinds[kind]
	if !ok {
		return store.Integration{}, ServiceStatus{}, fmt.Errorf("unknown service kind %q", kind)
	}
	u, err := ParseServiceURL(cfg.URL, sk)
	if err != nil {
		return store.Integration{}, ServiceStatus{}, err
	}
	cfg.URL = u.String()
	c, err := newServiceClient(cfg, sk, secret, m.Dial())
	if err != nil {
		return store.Integration{}, ServiceStatus{}, err
	}
	// The same bound as a scheduled read: a slow service must not hold the
	// setup request for long.
	ctx, cancel := context.WithTimeout(ctx, serviceReadTimeout)
	defer cancel()
	st, err := readService(ctx, kind, c)
	if err != nil {
		return store.Integration{}, st, err
	}
	in := store.Integration{ID: newID(), Kind: kind, Name: sk.Name + " " + u.Hostname(), Address: u.Hostname(), Enabled: true, CreatedBy: actor, CreatedAt: now}
	if in.Config, err = json.Marshal(cfg); err != nil {
		return in, st, err
	}
	if secret != "" {
		if in.Secret, err = m.box.Seal(in.ID, []byte(secret)); err != nil {
			return in, st, err
		}
	}
	if err := m.o.Store.CreateIntegration(ctx, in); err != nil {
		return in, st, err
	}
	if err := m.storeService(ctx, in, st, now); err != nil {
		return in, st, err
	}
	m.start(in)
	return in, st, nil
}

func (m *Manager) runService(ctx context.Context, in store.Integration, trig <-chan struct{}) {
	var cfg ServiceConfig
	if err := json.Unmarshal(in.Config, &cfg); err != nil {
		m.record(ctx, in.ID, fmt.Errorf("invalid configuration: %w", err), nil)
		return
	}
	secret := ""
	if len(in.Secret) > 0 {
		b, err := m.box.Open(in.ID, in.Secret)
		if err != nil {
			m.record(ctx, in.ID, err, nil)
			return
		}
		secret = string(b)
	}
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-trig:
		case <-t.C:
		}
		c, err := newServiceClient(cfg, ServiceKinds[in.Kind], secret, m.Dial())
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, serviceReadTimeout)
			var st ServiceStatus
			st, err = readService(cctx, in.Kind, c)
			cancel()
			if err == nil {
				err = m.storeService(ctx, in, st, time.Now())
			}
		}
		if err != nil && ctx.Err() == nil {
			m.o.Log.Warn("service integration failed", "integration", in.Name, "err", err)
			m.record(ctx, in.ID, err, nil)
		}
		t.Reset(serviceInterval)
	}
}

// storeService records LAN clients as device records (MAC and name tie
// them to the machines other sources know); routes stay in the status.
func (m *Manager) storeService(ctx context.Context, in store.Integration, st ServiceStatus, now time.Time) error {
	sk := ServiceKinds[in.Kind]
	if sk.Clients || sk.Appliance || st.System != nil || len(st.Devices) > 0 {
		// One sync for all hosts of the integration: it replaces the
		// earlier set, so the clients and the device itself go together.
		hosts := make([]inventory.Host, 0, len(st.Clients)+1)
		seen := map[string]bool{}
		for _, c := range st.Clients {
			if seen[c.MAC] {
				continue
			}
			seen[c.MAC] = true
			hosts = append(hosts, inventory.Host{
				ID: "lan-" + in.ID + "-" + strings.ReplaceAll(c.MAC, ":", ""), Name: c.Name, Kind: inventory.HostDevice,
				Source: inventory.SourceLease, Addresses: []string{c.IP}, MACs: []string{c.MAC}, LastContact: now,
				IntegrationID: in.ID, Detail: "known to " + in.Name,
			})
		}
		if st.System != nil {
			hosts = append(hosts, applianceHost(in, *st.System, now))
		}
		devices := networkDeviceSystems(in, st.Devices, now)
		for _, d := range devices {
			hosts = append(hosts, d.host)
		}
		if err := m.o.Store.SyncIntegrationHosts(ctx, in.ID, hosts); err != nil {
			return err
		}
		for _, d := range devices {
			if err := m.storeFirmwareOn(ctx, d.host.ID, d.sys, now); err != nil {
				return err
			}
		}
	}
	if st.System != nil {
		if err := m.storeFirmware(ctx, in, *st.System, now); err != nil {
			return err
		}
	}
	m.record(ctx, in.ID, nil, st)
	if m.o.Changed != nil {
		m.o.Changed(ctx)
	}
	return nil
}

// applianceHost is the system an appliance integration reads; its
// firmware is a package workload on it (storeFirmware), which the catalog
// entry of the product checks against advisories, as the Proxmox
// integration does with pve-manager.
func applianceHost(in store.Integration, sys ApplianceSystem, now time.Time) inventory.Host {
	name := sys.Name
	if name == "" {
		name = in.Address
	}
	osName := sys.Product + " " + sys.Raw
	if sys.Model != "" {
		osName += " (" + sys.Model + ")"
	}
	return inventory.Host{ID: applianceHostID(in), Name: name, Kind: inventory.HostAppliance, Source: inventory.SourceAppliance,
		OS: osName, Addresses: []string{in.Address}, LastContact: now, IntegrationID: in.ID, Detail: "read through " + in.Name}
}

func applianceHostID(in store.Integration) string { return "app-" + in.ID }

func (m *Manager) storeFirmware(ctx context.Context, in store.Integration, sys ApplianceSystem, now time.Time) error {
	return m.storeFirmwareOn(ctx, applianceHostID(in), sys, now)
}

// networkDevice is a device a controller manages, as a system of its own
// with its firmware.
type networkDevice struct {
	host inventory.Host
	sys  ApplianceSystem
}

// networkDeviceSystems turns the devices of a controller (UniFi access
// points, switches, gateways) into systems with their firmware. The MAC
// ties each to the scan's and the router's records of the same device.
func networkDeviceSystems(in store.Integration, devs []NetworkDevice, now time.Time) []networkDevice {
	var out []networkDevice
	seen := map[string]bool{}
	for _, d := range devs {
		pkg := unifiFirmwarePackage(d.Model)
		ver, ok := cleanVersion(d.Firmware)
		if pkg == "" || !ok || !firmwareNumber.MatchString(ver) || d.MAC == "" || seen[d.MAC] {
			continue
		}
		seen[d.MAC] = true
		name := d.Name
		if name == "" {
			name = d.Model
		}
		h := inventory.Host{ID: "dev-" + in.ID + "-" + strings.ReplaceAll(d.MAC, ":", ""), Name: name, Kind: inventory.HostAppliance,
			Source: inventory.SourceAppliance, OS: "UniFi " + d.Model + " firmware " + ver, MACs: []string{d.MAC}, LastContact: now,
			IntegrationID: in.ID, Detail: "managed by " + in.Name}
		if d.IP != "" {
			h.Addresses = []string{d.IP}
		}
		out = append(out, networkDevice{host: h, sys: ApplianceSystem{Product: "UniFi", Model: d.Model, Package: pkg, Version: ver, Raw: ver}})
	}
	return out
}

// firmwareNumber accepts dotted firmware versions ("6.6.77",
// "7.1.66.15432").
var firmwareNumber = regexp.MustCompile(`^\d+(?:\.\d+){1,4}$`)

// unifiFirmwarePackage names the firmware line of a UniFi model: access
// points, switches and gateways or consoles each share one.
func unifiFirmwarePackage(model string) string {
	m := strings.ToUpper(model)
	switch {
	case strings.HasPrefix(m, "USW"), strings.HasPrefix(m, "US-"), strings.HasPrefix(m, "US8"), strings.HasPrefix(m, "US16"), strings.HasPrefix(m, "US24"), strings.HasPrefix(m, "US48"):
		return "unifi-switch"
	case strings.HasPrefix(m, "UDM"), strings.HasPrefix(m, "UCG"), strings.HasPrefix(m, "UXG"), strings.HasPrefix(m, "UDR"), strings.HasPrefix(m, "USG"), strings.HasPrefix(m, "UDW"), strings.HasPrefix(m, "UX"):
		return "unifi-gateway"
	case strings.HasPrefix(m, "U6"), strings.HasPrefix(m, "U7"), strings.HasPrefix(m, "UAP"), strings.HasPrefix(m, "U5"), strings.HasPrefix(m, "UAL"), strings.HasPrefix(m, "UK"), strings.HasPrefix(m, "E7"):
		return "unifi-ap"
	}
	return ""
}

func (m *Manager) storeFirmwareOn(ctx context.Context, hostID string, sys ApplianceSystem, now time.Time) error {
	w := inventory.Workload{Kind: inventory.KindPackage, RuntimeID: "firmware:" + sys.Package, Name: sys.Package, State: "installed",
		Package: &inventory.Package{Manager: "firmware", Name: sys.Package, Version: sys.Version}}
	_, err := m.o.Store.ApplySnapshot(ctx, hostID, inventory.KindPackage, []inventory.Workload{w}, now)
	return err
}

// catalog returns the current catalog, nil when none is configured.
func (m *Manager) catalog() *catalog.Catalog {
	if m.o.Catalog == nil {
		return nil
	}
	return m.o.Catalog()
}
