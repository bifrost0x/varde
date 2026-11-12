// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func withNetwork(t *testing.T) func(*Deps) {
	return func(d *Deps) {
		set := d.Settings
		m, err := integrations.New(integrations.Options{
			Store: d.Store, DataDir: t.TempDir(), Log: slog.New(slog.DiscardHandler),
			Scope: func() discovery.Scope { return set.Get().Networks },
		})
		if err != nil {
			t.Fatal(err)
		}
		d.Network = m
	}
}

func TestNetworkPage(t *testing.T) {
	h := newHarness(t, withNetwork(t))
	csrf := h.signIn(t)
	post := func(path string, form url.Values) (*http.Response, string) {
		form.Set("csrf", csrf)
		return h.do(t, "POST", path, form, nil)
	}
	if resp, body := post("/connections/scope", url.Values{"networks": {"8.8.8.0/24"}}); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not a private range") {
		t.Fatalf("public range: %d", resp.StatusCode)
	}
	if resp, _ := post("/connections/scope", url.Values{"networks": {"192.168.1.0/24"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save scope: %d", resp.StatusCode)
	}
	_ = h.store.RecordDevices(t.Context(), []discovery.Device{
		{Address: "192.168.1.10", Hostname: "pve1", Kind: discovery.KindProxmox, Label: "Proxmox VE", Services: []discovery.Service{{Port: 22, Proto: discovery.ProtoSSH}, {Port: 8006, Proto: discovery.ProtoHTTPS, Product: "Proxmox VE"}}},
		{Address: "192.168.1.20", Kind: discovery.KindDocker, Label: "Docker host (API open without authentication)", Services: []discovery.Service{{Port: 22, Proto: discovery.ProtoSSH}, {Port: 2375, Proto: discovery.ProtoDocker, Insecure: true}}},
		{Address: "10.9.9.9", Kind: discovery.KindWeb, Label: "Out of scope"},
	}, nil, time.Now())
	_, body := h.do(t, "GET", "/connections", nil, nil)
	for _, want := range []string{"192.168.1.10", "pve1", "Connect Proxmox", "/connections/connect/proxmox?address=192.168.1.10", "/connections/connect/docker?address=192.168.1.20", "open without password"} {
		if !strings.Contains(body, want) {
			t.Errorf("network page lacks %q", want)
		}
	}
	if strings.Contains(body, "/connections/connect/docker?address=192.168.1.10") {
		t.Error("Docker over SSH offered for a Proxmox node")
	}
	if strings.Contains(body, "10.9.9.9") {
		t.Error("device outside the scope listed")
	}
	_, body = h.do(t, "GET", "/connections/connect/docker?address=192.168.1.10", nil, nil)
	if !strings.Contains(body, `value="192.168.1.10"`) {
		t.Error("docker setup not prefilled")
	}
	// Connecting outside the allowed ranges is refused before any network access.
	resp, body := post("/connections/connect/docker", url.Values{"step": {"address"}, "address": {"10.9.9.9"}, "port": {"22"}, "user": {"varde"}})
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "outside the network ranges") {
		t.Errorf("out-of-scope connect: %d", resp.StatusCode)
	}
	resp, body = post("/connections/connect/proxmox", url.Values{"step": {"address"}, "url": {"https://10.9.9.9:8006"}})
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "outside the network ranges") {
		t.Errorf("out-of-scope proxmox: %d", resp.StatusCode)
	}
	if resp, _ := post("/connections/integrations/nope/delete", url.Values{}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete unknown: %d", resp.StatusCode)
	}
	log, _ := h.store.AuditLog(t.Context(), 5)
	if len(log) == 0 || log[len(log)-1].Action == "" {
		t.Error("audit log empty")
	}
}

// The package setup offers its own key line, is offered for SSH devices, and
// refuses addresses outside the allowed networks before connecting.
func TestPackagesSetup(t *testing.T) {
	h := newHarness(t, withNetwork(t))
	csrf := h.signIn(t)
	post := func(path string, form url.Values) (*http.Response, string) {
		form.Set("csrf", csrf)
		return h.do(t, "POST", path, form, nil)
	}
	if resp, _ := post("/connections/scope", url.Values{"networks": {"192.168.1.0/24"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save scope: %d", resp.StatusCode)
	}
	_ = h.store.RecordDevices(t.Context(), []discovery.Device{
		{Address: "192.168.1.30", Kind: discovery.KindSSH, Label: "SSH", Services: []discovery.Service{{Port: 22, Proto: discovery.ProtoSSH}}},
	}, nil, time.Now())
	_, body := h.do(t, "GET", "/connections", nil, nil)
	if !strings.Contains(body, "/connections/connect/packages?address=192.168.1.30") {
		t.Error("package setup not offered for an SSH device")
	}
	_, body = h.do(t, "GET", "/connections/connect/packages?address=192.168.1.30", nil, nil)
	if !strings.Contains(body, "Read packages over SSH") || !strings.Contains(body, `value="192.168.1.30"`) || !strings.Contains(body, `action="/connections/connect/packages"`) {
		t.Error("package setup page wrong")
	}
	resp, body := post("/connections/connect/packages", url.Values{"step": {"address"}, "address": {"10.9.9.9"}, "port": {"22"}, "user": {"varde"}})
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "outside the network ranges") {
		t.Errorf("out-of-scope package setup: %d", resp.StatusCode)
	}
}

// Scheduled scans are off by default and set on the network page or in the
// settings; only the offered periods are accepted.
func TestScanSchedule(t *testing.T) {
	h := newHarness(t, withNetwork(t))
	csrf := h.signIn(t)
	if resp, _ := h.do(t, "POST", "/connections/scope", url.Values{"csrf": {csrf}, "networks": {"192.168.1.0/24"}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("scope")
	}
	_, body := h.do(t, "GET", "/connections", nil, nil)
	if !strings.Contains(body, `<option value="off" selected>`) {
		t.Error("scheduled scans not off by default")
	}
	if resp, _ := h.do(t, "POST", "/settings", url.Values{"csrf": {csrf}, "return": {"network"}, "DISCOVERY_SCAN_EVERY": {"1m"}}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unsupported period accepted: %d", resp.StatusCode)
	}
	resp, _ := h.do(t, "POST", "/settings", url.Values{"csrf": {csrf}, "return": {"network"}, "DISCOVERY_SCAN_EVERY": {"24h"}}, nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/connections") {
		t.Fatalf("save: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, page := range []string{"/connections", "/settings"} {
		if _, body := h.do(t, "GET", page, nil, nil); !strings.Contains(body, `<option value="24h" selected>`) {
			t.Errorf("%s does not show the daily schedule", page)
		}
	}
}

// The checklist suggests the step that reveals the most first, and names
// what Varde may do afterwards.
func TestSetupSteps(t *testing.T) {
	h := newHarness(t, withNetwork(t))
	csrf := h.signIn(t)
	if _, body := h.do(t, "GET", "/", nil, nil); !strings.Contains(body, "Allow your networks") {
		t.Error("first step is not allowing networks")
	}
	if resp, _ := h.do(t, "POST", "/connections/scope", url.Values{"csrf": {csrf}, "networks": {"192.168.1.0/24"}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("scope")
	}
	now := time.Now()
	_ = h.store.RecordDevices(t.Context(), []discovery.Device{
		{Address: "192.168.1.10", Kind: discovery.KindProxmox, Label: "Proxmox VE", Services: []discovery.Service{{Port: 8006, Proto: discovery.ProtoHTTPS}}},
		{Address: "192.168.1.11", Kind: discovery.KindProxmox, Label: "Proxmox VE", Services: []discovery.Service{{Port: 8006, Proto: discovery.ProtoHTTPS}}},
		{Address: "192.168.1.20", Kind: discovery.KindDocker, Label: "Docker", Services: []discovery.Service{{Port: 22, Proto: discovery.ProtoSSH}}},
	}, nil, now)
	if err := h.store.CreateIntegration(t.Context(), store.Integration{ID: "px", Kind: integrations.KindProxmox, Name: "Proxmox", Address: "192.168.1.10", Enabled: true, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		_ = h.store.UpsertHost(t.Context(), inventory.Host{ID: fmt.Sprintf("pve-px-%d", 100+i), Name: fmt.Sprintf("ct%d", i), Kind: inventory.HostProxmoxGuest,
			Source: inventory.SourceProxmox, OS: "LXC container", IntegrationID: "px", LastContact: now})
	}
	_, body := h.do(t, "GET", "/connections", nil, nil)
	first := strings.Index(body, "Read the full inventory of 3 guests on 192.168.1.10")
	proxmox := strings.Index(body, "Connect Proxmox VE at 192.168.1.11")
	docker := strings.Index(body, "Read the containers on 192.168.1.20")
	// A new cluster may reveal more than three containers; it comes first.
	if first < 0 || proxmox < 0 || docker < 0 || proxmox > first || first > docker {
		t.Errorf("steps missing or not ranked by impact (%d, %d, %d)", first, proxmox, docker)
	}
	if strings.Contains(body, "Connect Proxmox VE at 192.168.1.10") {
		t.Error("connected node offered again")
	}
	// The second node turns out to belong to the connected cluster.
	_ = h.store.UpsertHost(t.Context(), inventory.Host{ID: "pve-px-node-pve2", Name: "pve2", Kind: inventory.HostBareMetal,
		Source: inventory.SourceProxmox, Addresses: []string{"192.168.1.11"}, IntegrationID: "px", LastContact: now})
	if _, body = h.do(t, "GET", "/connections", nil, nil); strings.Contains(body, "Connect Proxmox VE at 192.168.1.11") {
		t.Error("node of the connected cluster offered as a new Proxmox")
	}
	if !strings.Contains(body, "can only run one fixed, read-only command") {
		t.Error("step does not say what Varde may do")
	}
}

// Service setup: the address is checked against the scope before anything
// is asked, plain http is flagged, and a credential is required where the
// service has no anonymous read.
func TestServiceSetup(t *testing.T) {
	h := newHarness(t, withNetwork(t))
	csrf := h.signIn(t)
	post := func(path string, form url.Values) (*http.Response, string) {
		form.Set("csrf", csrf)
		return h.do(t, "POST", path, form, nil)
	}
	if resp, _ := post("/connections/scope", url.Values{"networks": {"192.168.1.0/24"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("scope")
	}
	_, body := h.do(t, "GET", "/connections", nil, nil)
	for _, k := range []string{"traefik", "npm", "fritzbox", "opnsense"} {
		if !strings.Contains(body, "/connections/connect/"+k) {
			t.Errorf("no setup offered for %s", k)
		}
	}
	_, body = h.do(t, "GET", "/connections/connect/npm", nil, nil)
	if !strings.Contains(body, "Proxy Hosts: View") {
		t.Error("NPM setup does not name the view-only permission")
	}
	if resp, body := post("/connections/connect/opnsense", url.Values{"step": {"address"}, "url": {"https://10.9.9.9"}}); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "outside the network ranges") {
		t.Errorf("out-of-scope service: %d", resp.StatusCode)
	}
	if resp, body := post("/connections/connect/npm", url.Values{"step": {"credential"}, "url": {"http://192.168.1.5:81"}}); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Enter the user") {
		t.Errorf("missing credential: %d", resp.StatusCode)
	}
}

// Step 3 of the SSH setups gives commands to paste into a shell: the
// authorized_keys line alone is no command and fails when run.
func TestConnectInstallCommands(t *testing.T) {
	deps := testDeps(t, withNetwork(t))
	r, err := newRenderer()
	if err != nil {
		t.Fatal(err)
	}
	a := &app{d: deps, r: r}
	for _, c := range []struct {
		kind, user string
		want, not  []string
	}{
		{"docker", "varde", []string{"useradd -m -s /bin/sh varde", "usermod -aG docker varde", `command=&#34;docker system dial-stdio&#34;`}, nil},
		{"packages", "varde", []string{"useradd -m -s /bin/sh varde", "varde-inventory"}, []string{"usermod -aG docker"}},
		{"proxmox-lxc", "root", []string{"/root/.ssh/authorized_keys"}, []string{"useradd", "usermod"}},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/connections/connect/"+c.kind, nil)
		a.renderConnect(rec, req, &auth.Current{User: store.User{Username: "admin"}}, http.StatusOK, connectData{Kind: c.kind, Step: "key", User: c.user, Address: "192.168.1.20", Port: "22"})
		body := rec.Body.String()
		for _, w := range append([]string{`id="install"`, "&lt;&lt;&#39;VARDE_KEY&#39;", "Or add the line yourself", `id="keyline"`}, c.want...) {
			if !strings.Contains(body, w) {
				t.Errorf("%s: step 3 lacks %q", c.kind, w)
			}
		}
		for _, w := range c.not {
			if strings.Contains(body, w) {
				t.Errorf("%s: step 3 contains %q", c.kind, w)
			}
		}
	}
	// A user name that is not plain gets no commands, only the line.
	rec := httptest.NewRecorder()
	a.renderConnect(rec, httptest.NewRequest("GET", "/connections/connect/packages", nil), &auth.Current{User: store.User{Username: "admin"}}, http.StatusOK, connectData{Kind: "packages", Step: "key", User: "x;reboot", Address: "192.168.1.20", Port: "22"})
	if body := rec.Body.String(); strings.Contains(body, `id="install"`) || !strings.Contains(body, `id="keyline"`) {
		t.Error("unsafe user name: commands shown or line missing")
	}
}
