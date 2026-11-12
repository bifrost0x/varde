// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

const networkToken = "network-test-token-0123456789abcdef"

func networkSetup(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	scope, err := discovery.ParseScope("10.10.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Store: st, Token: networkToken, Log: slog.New(slog.DiscardHandler),
		Scope: func() discovery.Scope { return scope }, Interval: func(string) time.Duration { return 10 * time.Minute }})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, st
}

func getJSON(t *testing.T, srv *httptest.Server, path string, out any) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), "GET", srv.URL+Prefix+path, nil)
	req.Header.Set("Authorization", "Bearer "+networkToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	return resp.StatusCode, string(b)
}

func TestNetworkEndpoints(t *testing.T) {
	srv, st := networkSetup(t)
	ctx, now := t.Context(), time.Now()
	if err := st.CreateIntegration(ctx, store.Integration{ID: "pve", Kind: "proxmox", Name: "Proxmox pve", Address: "10.10.1.253",
		Config: json.RawMessage(`{"token_id":"varde@pve!varde","fingerprint":"AA:BB"}`), Secret: []byte("sealed-secret-bytes"), Enabled: true, CreatedBy: "admin", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordIntegrationRun(ctx, "pve", nil, map[string]any{"version": "9.0.3"}, now); err != nil {
		t.Fatal(err)
	}
	for _, h := range []inventory.Host{
		{ID: "pve-pve-101", Name: "docker-vm", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceProxmox, OS: "QEMU VM", Addresses: []string{"10.10.1.20"}, IntegrationID: "pve", LastContact: now},
		{ID: "ssh-x", Name: "docker-vm.lan", Kind: inventory.HostDocker, Source: inventory.SourceSSH, Addresses: []string{"10.10.1.20"}, LastContact: now},
	} {
		if err := st.UpsertHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordDevices(ctx, []discovery.Device{
		{Address: "10.10.1.20", Kind: discovery.KindSSH, Label: "SSH"},
		{Address: "10.10.1.99", Kind: discovery.KindWeb, Label: "Web"},
		{Address: "192.168.5.5", Kind: discovery.KindWeb, Label: "outside the scope"},
	}, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordScanRun(ctx, store.ScanRun{Trigger: "manual", Networks: "10.10.1.0/24", Started: now, Ended: now, Addresses: 254, Found: 3}); err != nil {
		t.Fatal(err)
	}

	var merged struct {
		Hosts []struct {
			ID       string            `json:"id"`
			Evidence []json.RawMessage `json:"evidence"`
		} `json:"hosts"`
		Counts struct{ Hosts, Devices int } `json:"counts"`
	}
	if code, body := getJSON(t, srv, "hosts?view=merged", &merged); code != http.StatusOK || len(merged.Hosts) != 1 || merged.Hosts[0].ID != "pve-pve-101" ||
		len(merged.Hosts[0].Evidence) != 3 || merged.Counts.Hosts != 1 || merged.Counts.Devices != 1 {
		t.Errorf("merged hosts: %d %s", code, body)
	}
	var records struct{ Hosts []json.RawMessage }
	if code, _ := getJSON(t, srv, "hosts", &records); code != http.StatusOK || len(records.Hosts) != 2 {
		t.Errorf("host records changed: %d %d", code, len(records.Hosts))
	}
	if code, _ := getJSON(t, srv, "hosts?view=other", nil); code != http.StatusBadRequest {
		t.Errorf("bad view: %d", code)
	}

	var devs struct {
		Devices []struct {
			Address string `json:"address"`
			HostID  string `json:"host_id"`
		} `json:"devices"`
		LastScan *store.ScanRun `json:"last_scan"`
	}
	code, body := getJSON(t, srv, "devices", &devs)
	if code != http.StatusOK || len(devs.Devices) != 2 || devs.LastScan == nil || devs.LastScan.Found != 3 || strings.Contains(body, "192.168.5.5") {
		t.Fatalf("devices: %d %s", code, body)
	}
	for _, d := range devs.Devices {
		if want := map[string]string{"10.10.1.20": "pve-pve-101", "10.10.1.99": ""}[d.Address]; d.HostID != want {
			t.Errorf("device %s host %q, want %q", d.Address, d.HostID, want)
		}
	}

	var ins struct {
		Integrations []struct {
			ID, Health string
			Status     map[string]any
		} `json:"integrations"`
	}
	code, body = getJSON(t, srv, "integrations", &ins)
	if code != http.StatusOK || len(ins.Integrations) != 1 || ins.Integrations[0].Health != "ok" || ins.Integrations[0].Status["version"] != "9.0.3" {
		t.Fatalf("integrations: %d %s", code, body)
	}
	for _, leak := range []string{"sealed-secret", "token_id", "fingerprint", "config", "secret"} {
		if strings.Contains(body, leak) {
			t.Errorf("integrations response contains %q: %s", leak, body)
		}
	}
}
