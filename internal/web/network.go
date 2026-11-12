// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
)

// deviceRow is a scanned device with what covers it.
type deviceRow struct {
	store.StoredDevice
	// Machine is the host the device belongs to; Covered names the other
	// sources that know it.
	Machine coverage.Machine
	Covered []string
	// CanProxmox, CanDocker, CanPackages and CanLXC offer the matching
	// setup.
	CanProxmox, CanDocker, CanPackages, CanLXC bool
	// CanAgent recommends installing the agent: the full inventory.
	CanAgent bool
	// Service is the integration to offer for a recognised product.
	Service  string
	Insecure bool
	// Hint says what Varde can do with a recognised platform it has no
	// connection for.
	Hint string
}

type integrationRow struct {
	store.Integration
	// Health is the state shown in the badge (coverage.IntegrationHealth).
	Health    string
	Proxmox   *integrations.ProxmoxStatus
	Docker    *integrations.DockerStatus
	Inventory *integrations.InventoryStatus
	LXC       *integrations.LXCStatus
	Service   *integrations.ServiceStatus
	// Routes are the proxy routes with the machine each backend belongs
	// to.
	Routes []routeRow
	// CanLXC offers reading the containers of this Proxmox node.
	CanLXC bool
}

type networkData struct {
	Networks   string
	NetworkErr string
	Scope      []string
	Scan       integrations.ScanState
	Percent    int
	Devices    []deviceRow
	Machines   systemCounts
	// ScanEvery is the stored period of scheduled scans; ScanPeriods are
	// the choices.
	ScanEvery   string
	ScanPeriods []scanPeriod
	// Steps are the next setup steps, ranked by what they unlock.
	Steps       []step
	Integration []integrationRow
	// ServiceKinds are the service integrations that can be added.
	ServiceKinds []serviceKindRow
}

type serviceKindRow struct{ Kind, Name string }

func serviceKindList() []serviceKindRow {
	var out []serviceKindRow
	for k, v := range integrations.ServiceKinds {
		out = append(out, serviceKindRow{k, v.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// routeRow is a proxy route with what Varde knows about its backend.
type routeRow struct {
	Host, Backend, Machine string
	// Public: the host is under a public domain. Checked: the backend
	// machine has a workload Varde can check against advisories.
	Public, Checked bool
}

func (a *app) routeRows(s *snapshot, routes []integrations.Route) []routeRow {
	byAddr := map[string]*coverage.Machine{}
	for i := range s.machines {
		for _, addr := range s.machines[i].Addresses {
			byAddr[addr] = &s.machines[i]
		}
	}
	assessable := map[string]bool{}
	for _, wl := range s.workloads {
		if coverage.Assessable(s.ids[wl.ID]) {
			if m := s.hostOf[wl.HostID]; m != nil {
				assessable[m.ID] = true
			}
		}
	}
	public := a.d.Settings.Get().PublicDomains
	var out []routeRow
	for _, rt := range routes {
		row := routeRow{Host: rt.Host, Public: coverage.UnderSuffix(rt.Host, public)}
		for _, b := range rt.Backends {
			row.Backend = b
			host, _, err := net.SplitHostPort(b)
			if err != nil {
				host = b
			}
			if m := byAddr[host]; m != nil {
				row.Machine, row.Checked = m.Name, assessable[m.ID]
				break
			}
		}
		out = append(out, row)
	}
	return out
}

func (a *app) network(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	a.renderNetwork(w, r, cur, http.StatusOK, "")
}

func (a *app) renderNetwork(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, scopeErr string) {
	if a.d.Network == nil {
		a.renderError(w, r, cur, http.StatusNotFound, "Not available", "Network discovery is not configured.")
		return
	}
	ctx := r.Context()
	scope := a.d.Settings.Get().Networks
	d := networkData{Networks: a.d.Settings.UIValue(settings.KeyNetworks), NetworkErr: scopeErr, Scan: a.d.Network.Scan(),
		ScanEvery: scanEveryValue(a.d.Settings), ScanPeriods: scanPeriods}
	for _, p := range scope.Networks() {
		d.Scope = append(d.Scope, p.String())
	}
	if d.Scan.Total > 0 {
		d.Percent = min(100, d.Scan.Done*100/d.Scan.Total)
	}
	ins, err := a.d.Store.Integrations(ctx)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	hasProxmox, hasDocker, hasPackages, hasLXC := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	kinds := map[string]bool{}
	for _, in := range ins {
		kinds[in.Kind+"@"+in.Address] = true
		row := integrationRow{Integration: in, Health: coverage.IntegrationHealth(in, a.d.Now(), a.interval(in.Kind))}
		switch in.Kind {
		case integrations.KindProxmox:
			var st integrations.ProxmoxStatus
			if json.Unmarshal(in.Status, &st) == nil && st.Version != "" {
				row.Proxmox = &st
			}
			hasProxmox[in.Address] = true
		case integrations.KindDockerSSH:
			var st integrations.DockerStatus
			if json.Unmarshal(in.Status, &st) == nil && st.Host != "" {
				row.Docker = &st
			}
			hasDocker[in.Address] = true
		case integrations.KindSSHInventory:
			var st integrations.InventoryStatus
			if json.Unmarshal(in.Status, &st) == nil && st.Packages+st.Services > 0 {
				row.Inventory = &st
			}
			hasPackages[in.Address] = true
		case integrations.KindProxmoxLXC:
			var st integrations.LXCStatus
			if json.Unmarshal(in.Status, &st) == nil && st.Containers > 0 {
				row.LXC = &st
			}
			hasLXC[in.Address] = true
		default:
			if _, ok := integrations.ServiceKinds[in.Kind]; ok {
				var st integrations.ServiceStatus
				if json.Unmarshal(in.Status, &st) == nil {
					row.Service = &st
				}
			}
		}
		d.Integration = append(d.Integration, row)
	}
	for i := range d.Integration {
		in := d.Integration[i]
		d.Integration[i].CanLXC = in.Kind == integrations.KindProxmox && !hasLXC[in.Address]
	}
	snap, err := a.load(ctx, false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	rows, err := a.systemRows(ctx, snap)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	agentFor := map[string]bool{}
	for _, addr := range a.agentCandidates(snap, rows) {
		agentFor[addr] = true
	}
	// A device row shows the host it belongs to; the host comes from the
	// same merge as on every other page.
	machineOf := map[string]coverage.Machine{}
	for _, m := range snap.machines {
		for _, e := range m.Evidence {
			if e.Source == coverage.EvidenceScan {
				machineOf[e.Addresses[0]] = m
			}
		}
	}
	for _, dv := range snap.devices {
		addr, err := netip.ParseAddr(dv.Address)
		if err != nil || !scope.Contains(addr) {
			continue
		}
		m := machineOf[dv.Address]
		row := deviceRow{StoredDevice: dv, Machine: m}
		for _, e := range m.Evidence {
			if e.Source != coverage.EvidenceScan {
				row.Covered = append(row.Covered, evidenceName(e))
			}
		}
		for _, s := range dv.Services {
			row.Insecure = row.Insecure || s.Insecure
			if s.Proto == discovery.ProtoSSH && !hasDocker[dv.Address] && !m.Has(coverage.EvidenceSSH) && !m.Self {
				row.CanDocker = true
			}
			if s.Proto == discovery.ProtoSSH && !hasPackages[dv.Address] && !m.Has(coverage.EvidenceSSHInventory) && !m.Self {
				row.CanPackages = true
			}
		}
		row.CanAgent = agentFor[dv.Address]
		row.Service, row.Hint = serviceFor(dv, kinds)
		row.CanProxmox = dv.Kind == discovery.KindProxmox && !hasProxmox[dv.Address]
		row.CanLXC = dv.Kind == discovery.KindProxmox && !hasLXC[dv.Address]
		// A Proxmox node is read through its API, not as a Docker host.
		if dv.Kind == discovery.KindProxmox || dv.Kind == discovery.KindProxmoxBackup {
			row.CanDocker = false
		}
		d.Devices = append(d.Devices, row)
	}
	d.Machines = systemCounts{MachineCounts: coverage.CountMachines(snap.machines), Read: readSystems(rows)}
	d.Steps = a.setupSteps(snap, rows)
	d.ServiceKinds = serviceKindList()
	for i := range d.Integration {
		if st := d.Integration[i].Service; st != nil {
			d.Integration[i].Routes = a.routeRows(snap, st.Routes)
		}
	}
	sort.SliceStable(d.Devices, func(i, j int) bool {
		x, _ := netip.ParseAddr(d.Devices[i].Address)
		y, _ := netip.ParseAddr(d.Devices[j].Address)
		return x.Less(y)
	})
	v := view{Title: "Connections", Nav: "connections", Tabs: tabs("connections", "/connections"), Data: d}
	if d.Scan.Running {
		v.Refresh = 3
	}
	a.page(w, r, cur, status, "network", v)
}

type scanPeriod struct{ Value, Label string }

// scanPeriods are the choices for scheduled scans, in settings.ScanPeriods.
var scanPeriods = []scanPeriod{{"off", "Off, only on request"}, {"6h", "Every 6 hours"}, {"24h", "Daily"}, {"168h", "Weekly"}}

func scanEveryValue(s *settings.Service) string {
	if v := s.UIValue(settings.KeyScanEvery); v != "" {
		return v
	}
	return "off"
}

// evidenceName describes a non-scan source of a device's host.
func evidenceName(e coverage.Evidence) string {
	switch e.Source {
	case coverage.EvidenceProxmox:
		return "Proxmox " + e.Name
	case coverage.EvidenceSSH:
		return "Docker over SSH (" + e.Name + ")"
	case coverage.EvidenceSSHInventory:
		return "Packages over SSH (" + e.Name + ")"
	case coverage.EvidenceAgent:
		return "Agent " + e.Name
	case coverage.EvidenceLocal:
		return "This Varde server"
	}
	return e.Name
}

// checkScope validates network ranges for both places that set them, the
// network and the settings page.
func checkScope(v string) error {
	if len(v) > 1024 {
		return errors.New("the list of ranges is too long")
	}
	_, err := discovery.ParseScope(v)
	return err
}

func (a *app) saveScope(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	v := strings.TrimSpace(r.PostFormValue("networks"))
	if err := checkScope(v); err != nil {
		a.renderNetwork(w, r, cur, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.d.Settings.Update(r.Context(), map[string]string{settings.KeyNetworks: v}, cur.User.Username, a.d.Now()); err != nil {
		a.renderNetwork(w, r, cur, http.StatusBadRequest, err.Error())
		return
	}
	a.audit(r, cur, "network.scope", "", v)
	http.Redirect(w, r, "/connections?ok=scope", http.StatusSeeOther)
}

func (a *app) startScan(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if a.d.Network == nil {
		a.renderError(w, r, cur, http.StatusNotFound, "Not available", "Network discovery is not configured.")
		return
	}
	if err := a.d.Network.StartScan(); err != nil {
		a.renderNetwork(w, r, cur, http.StatusConflict, err.Error())
		return
	}
	a.audit(r, cur, "network.scan", "", a.d.Settings.Get().Networks.String())
	http.Redirect(w, r, "/connections?ok=scan-started", http.StatusSeeOther)
}

// connectData drives the two-step setup pages.
type connectData struct {
	Kind, Step, Error string
	// Proxmox
	URL, TokenID, Fingerprint string
	// Docker over SSH
	Address, User, Port, HostKey, HostKeyFingerprint, HostKeyFile, KeyLine string
	// Install is the shell snippet that adds KeyLine on the host.
	Install string
	// Service integrations (Traefik, Nginx Proxy Manager, Fritz!Box,
	// OPNsense): Service describes the kind; Plain warns about http.
	Service *integrations.ServiceKind
	Plain   bool
}

func (a *app) connectForm(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	kind := r.PathValue("kind")
	addr := strings.TrimSpace(r.URL.Query().Get("address"))
	if _, err := netip.ParseAddr(addr); err != nil {
		addr = ""
	}
	d := connectData{Kind: kind, Step: "address"}
	switch {
	case kind == "proxmox":
		if addr != "" {
			d.URL = "https://" + net.JoinHostPort(addr, "8006")
		}
	case kind == "docker", kind == "packages":
		d.Address, d.Port, d.User = addr, "22", "varde"
	case kind == "proxmox-lxc":
		d.Address, d.Port, d.User = addr, "22", "root"
	case isServiceKind(kind):
		if addr != "" {
			if u, err := integrations.ParseServiceURL(addr, integrations.ServiceKinds[kind]); err == nil {
				d.URL = u.String()
			}
		}
	default:
		a.renderError(w, r, cur, http.StatusNotFound, "Not found", "Unknown integration.")
		return
	}
	a.renderConnect(w, r, cur, http.StatusOK, d)
}

func (a *app) renderConnect(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, d connectData) {
	if a.d.Network == nil {
		a.renderError(w, r, cur, http.StatusNotFound, "Not available", "Network discovery is not configured.")
		return
	}
	title := "Connect Proxmox VE"
	if sk, ok := integrations.ServiceKinds[d.Kind]; ok {
		title, d.Service = "Connect "+sk.Name, &sk
	}
	switch d.Kind {
	case "docker":
		title = "Connect a Docker host"
		d.KeyLine = a.d.Network.Identity().AuthorizedLine()
	case "packages":
		title = "Read packages over SSH"
		d.KeyLine = a.d.Network.InventoryIdentity().InventoryLine()
	case "proxmox-lxc":
		title = "Read every guest of a Proxmox node"
		d.KeyLine = a.d.Network.ProxmoxIdentity().LXCLine()
	}
	if d.KeyLine != "" {
		d.Install = integrations.InstallCommand(d.User, d.KeyLine, d.Kind == "docker")
	}
	a.page(w, r, cur, status, "connect", view{Title: title, Nav: "connections", Tabs: tabs("connections", "/connections"), Data: d})
}

func (a *app) connect(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if a.d.Network == nil {
		a.renderError(w, r, cur, http.StatusNotFound, "Not available", "Network discovery is not configured.")
		return
	}
	switch kind := r.PathValue("kind"); {
	case kind == "proxmox":
		a.connectProxmox(w, r, cur)
	case kind == "docker", kind == "packages", kind == "proxmox-lxc":
		a.connectSSH(w, r, cur, kind)
	case isServiceKind(kind):
		a.connectService(w, r, cur, kind)
	default:
		a.renderError(w, r, cur, http.StatusNotFound, "Not found", "Unknown integration.")
	}
}

func (a *app) connectProxmox(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	d := connectData{Kind: "proxmox", Step: "address", URL: strings.TrimSpace(r.PostFormValue("url")),
		TokenID: strings.TrimSpace(r.PostFormValue("token_id"))}
	fail := func(status int, msg string) {
		d.Error = msg
		a.renderConnect(w, r, cur, status, d)
	}
	u, err := integrations.ParseProxmoxURL(d.URL)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	d.URL = u.String()
	if r.PostFormValue("step") == "address" {
		fp, err := integrations.ServerFingerprint(ctx, d.URL, a.d.Network.Dial())
		if err != nil {
			fail(http.StatusBadGateway, scopeHint(err))
			return
		}
		d.Fingerprint, d.Step = fp, "token"
		a.renderConnect(w, r, cur, http.StatusOK, d)
		return
	}
	d.Step, d.Fingerprint = "token", r.PostFormValue("fingerprint")
	if r.PostFormValue("confirm") != "yes" {
		fail(http.StatusBadRequest, "Compare the fingerprint with the one Proxmox shows and confirm it.")
		return
	}
	secret := strings.TrimSpace(r.PostFormValue("secret"))
	if secret == "" || len(secret) > 256 {
		fail(http.StatusBadRequest, "Enter the token secret Proxmox showed when the token was created.")
		return
	}
	in, st, err := a.d.Network.AddProxmox(ctx, integrations.ProxmoxConfig{URL: d.URL, TokenID: d.TokenID, Fingerprint: d.Fingerprint}, secret, cur.User.Username, a.d.Now())
	if errors.Is(err, store.ErrConflict) {
		fail(http.StatusConflict, "This Proxmox node is already connected.")
		return
	}
	if err != nil {
		fail(http.StatusBadGateway, scopeHint(err))
		return
	}
	a.audit(r, cur, "integration.add", in.ID, "proxmox "+in.Address+", "+strconv.Itoa(len(st.Guests))+" guests")
	http.Redirect(w, r, "/connections?ok=connected#integrations", http.StatusSeeOther)
}

// connectSSH sets up Docker over SSH (kind "docker") or the package
// inventory (kind "packages"); both pin the host key the same way.
func (a *app) connectSSH(w http.ResponseWriter, r *http.Request, cur *auth.Current, kind string) {
	ctx := r.Context()
	d := connectData{Kind: kind, Step: "address", Address: strings.TrimSpace(r.PostFormValue("address")),
		User: strings.TrimSpace(r.PostFormValue("user")), Port: strings.TrimSpace(r.PostFormValue("port"))}
	fail := func(status int, msg string) {
		d.Error = msg
		a.renderConnect(w, r, cur, status, d)
	}
	port, err := strconv.Atoi(d.Port)
	cfg := integrations.DockerSSHConfig{Address: d.Address, Port: port, User: d.User}
	if err != nil {
		cfg.Port = 0
	}
	if err := cfg.Validate(); err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	key, err := integrations.FetchHostKey(ctx, cfg.Target(), a.d.Network.Dial())
	if err != nil {
		fail(http.StatusBadGateway, scopeHint(err))
		return
	}
	d.Step, d.HostKeyFingerprint, d.HostKeyFile = "key", integrations.Fingerprint(key), integrations.KeyFile(key)
	if r.PostFormValue("step") == "address" {
		a.renderConnect(w, r, cur, http.StatusOK, d)
		return
	}
	// The key is read again and must match what the user confirmed.
	if r.PostFormValue("fingerprint") != d.HostKeyFingerprint {
		fail(http.StatusConflict, "The host key changed while you were setting up. Compare the new fingerprint and confirm again.")
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		fail(http.StatusBadRequest, "Compare the host key fingerprint and confirm it.")
		return
	}
	cfg.HostKey = integrations.MarshalHostKey(key)
	var in store.Integration
	var detail string
	switch kind {
	case "packages":
		var st integrations.InventoryStatus
		in, st, err = a.d.Network.AddSSHInventory(ctx, cfg, cur.User.Username, a.d.Now())
		detail = fmt.Sprintf("ssh-inventory %s@%s, %d packages, %d apps", cfg.User, cfg.Target(), st.Packages, st.Apps)
	case "proxmox-lxc":
		var st integrations.LXCStatus
		in, st, err = a.d.Network.AddProxmoxLXC(ctx, cfg, cur.User.Username, a.d.Now())
		detail = fmt.Sprintf("proxmox-lxc %s@%s, %d containers, %d apps", cfg.User, cfg.Target(), st.Containers, st.Apps)
	default:
		var version string
		in, version, err = a.d.Network.AddDockerSSH(ctx, cfg, cur.User.Username, a.d.Now())
		detail = "docker-ssh " + cfg.User + "@" + cfg.Target() + ", Docker " + version
	}
	if errors.Is(err, store.ErrConflict) {
		fail(http.StatusConflict, "This host is already connected.")
		return
	}
	if err != nil {
		fail(http.StatusBadGateway, scopeHint(err))
		return
	}
	a.audit(r, cur, "integration.add", in.ID, detail)
	http.Redirect(w, r, "/connections?ok=connected#integrations", http.StatusSeeOther)
}

// connectService sets up a service integration: address, certificate
// confirmation for https, then the credential, which is checked by reading
// once before anything is stored.
func (a *app) connectService(w http.ResponseWriter, r *http.Request, cur *auth.Current, kind string) {
	ctx := r.Context()
	sk := integrations.ServiceKinds[kind]
	d := connectData{Kind: kind, Step: "address", URL: strings.TrimSpace(r.PostFormValue("url")), User: strings.TrimSpace(r.PostFormValue("user"))}
	fail := func(status int, msg string) {
		d.Error = msg
		a.renderConnect(w, r, cur, status, d)
	}
	u, err := integrations.ParseServiceURL(d.URL, sk)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	d.URL, d.Plain = u.String(), u.Scheme == "http"
	if len(d.User) > 128 || strings.ContainsAny(d.User, "\r\n") {
		fail(http.StatusBadRequest, "The user name is too long.")
		return
	}
	if r.PostFormValue("step") == "address" {
		if u.Scheme == "https" {
			fp, err := integrations.TLSFingerprint(ctx, u, a.d.Network.Dial())
			if err != nil {
				fail(http.StatusBadGateway, scopeHint(err))
				return
			}
			d.Fingerprint = fp
		} else if _, err := a.d.Network.Dial()(ctx, "tcp", u.Host); err != nil {
			// Plain http: check the scope and reachability before asking
			// for a credential.
			fail(http.StatusBadGateway, scopeHint(err))
			return
		}
		d.Step = "credential"
		a.renderConnect(w, r, cur, http.StatusOK, d)
		return
	}
	d.Step, d.Fingerprint = "credential", r.PostFormValue("fingerprint")
	if u.Scheme == "https" && r.PostFormValue("confirm") != "yes" {
		fail(http.StatusBadRequest, "Compare the fingerprint with the one the service shows and confirm it.")
		return
	}
	secret := r.PostFormValue("secret")
	if len(secret) > 512 || (secret == "" && !sk.UserOptional) || (d.User == "" && !sk.UserOptional) {
		fail(http.StatusBadRequest, "Enter the user and password (or API key and secret) described above.")
		return
	}
	in, st, err := a.d.Network.AddService(ctx, kind, integrations.ServiceConfig{URL: d.URL, User: d.User, Fingerprint: d.Fingerprint}, secret, cur.User.Username, a.d.Now())
	if errors.Is(err, store.ErrConflict) {
		fail(http.StatusConflict, sk.Name+" at this address is already connected.")
		return
	}
	if err != nil {
		fail(http.StatusBadGateway, scopeHint(err))
		return
	}
	a.audit(r, cur, "integration.add", in.ID, fmt.Sprintf("%s %s, %d routes, %d clients", kind, d.URL, len(st.Routes), len(st.Clients)))
	http.Redirect(w, r, "/connections?ok=connected#integrations", http.StatusSeeOther)
}

// scopeHint adds the next step when a connection was refused because the
// address is outside the allowed networks.
func scopeHint(err error) string {
	if errors.Is(err, discovery.ErrOutOfScope) {
		return "The address is outside the network ranges Varde may contact. Add its range under Connections first."
	}
	return err.Error()
}

func (a *app) integrationAction(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if a.d.Network == nil {
		a.renderError(w, r, cur, http.StatusNotFound, "Not available", "Network discovery is not configured.")
		return
	}
	ctx := r.Context()
	id, action := r.PathValue("id"), r.PathValue("action")
	var err error
	var code string
	switch action {
	case "delete":
		err, code = a.d.Network.Remove(ctx, id), "removed"
	case "enable":
		err, code = a.d.Network.SetEnabled(ctx, id, true), "enabled"
	case "disable":
		err, code = a.d.Network.SetEnabled(ctx, id, false), "disabled"
	case "sync":
		// Only the chosen integration reads now, and only an existing,
		// enabled one.
		var in store.Integration
		if in, err = a.d.Store.GetIntegration(ctx, id); err == nil {
			code = "synced"
			if !in.Enabled || !a.d.Network.TriggerIntegration(id) {
				code = "not-running"
			}
		}
	default:
		a.renderError(w, r, cur, http.StatusNotFound, "Not found", "Unknown action.")
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		a.renderError(w, r, cur, http.StatusNotFound, "Not found", "The integration does not exist.")
		return
	}
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "integration."+action, id, "")
	if action == "delete" {
		a.d.Analyze(ctx)
	}
	http.Redirect(w, r, "/connections?ok="+code+"#integrations", http.StatusSeeOther)
}

// productServices are the integrations Varde offers for a product the scan
// recognised.
var productServices = map[string]string{
	"UniFi OS (gateway or console)": integrations.KindUniFi,
	"OPNsense":                      integrations.KindOPNsense,
	"FRITZ!Box":                     integrations.KindFritzBox,
	"Synology NAS":                  integrations.KindSynology,
	"QNAP NAS":                      integrations.KindQNAP,
	"TrueNAS":                       integrations.KindTrueNAS,
	"Unraid":                        integrations.KindUnraid,
	"Home Assistant":                integrations.KindHomeAssistant,
}

// serviceFor returns the integration to offer for a device, unless one is
// connected for its address, and a hint for products Varde reads another
// way.
func serviceFor(dv store.StoredDevice, connected map[string]bool) (kind, hint string) {
	if k, ok := productServices[dv.Label]; ok && !connected[k+"@"+dv.Address] {
		if integrations.ServiceKinds[k].Appliance {
			return k, "Reads its system version and checks it against advisories."
		}
		return k, "Its client list names the devices of your network and ties systems to their addresses."
	}
	if dv.Kind == discovery.KindPortainer {
		return "", "Portainer manages Docker here. The agent on this host reads its containers with their images and versions."
	}
	return "", ""
}

// isServiceKind reports whether kind is one of the service integrations.
func isServiceKind(kind string) bool {
	_, ok := integrations.ServiceKinds[kind]
	return ok
}
