// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// A system page shows everything Varde knows about one machine: where it
// knows it from, its apps and containers, every installed package, and what
// it cannot see yet with the step that changes that.
func TestSystemPage(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "pve-a-node-pve1", Name: "pve1", Kind: inventory.HostBareMetal, Source: inventory.SourceProxmox, Addresses: []string{"10.0.0.2"}, LastContact: now})
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "pvevm-b-112", Name: "docker", Kind: inventory.HostProxmoxGuest, Source: inventory.SourceNodeInventory, OS: "Ubuntu 24.04", Addresses: []string{"10.0.0.12"}, LastContact: now,
		Detail: "VM 112 on 10.0.0.2, 3 packages and 1 Docker containers read"})
	_, _ = h.store.ApplySnapshot(ctx, "pvevm-b-112", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "aaaaaaaaaaaa", Name: "immich_server",
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"},
	}}, now)
	if err := h.store.SetHostPackages(ctx, store.HostPackages{HostID: "pvevm-b-112", Distro: "ubuntu-24.04", OS: "Ubuntu 24.04", Read: now, Packages: []inventory.Package{
		{Manager: "dpkg", Name: "libssl3t64", Version: "3.0.13-0ubuntu3.5", Source: "openssl"},
		{Manager: "dpkg", Name: "bash", Version: "5.2.21-2ubuntu4"},
		{Manager: "dpkg", Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.5", Source: "openssh"},
	}}); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems", nil, nil)
	m := regexp.MustCompile(`href="(/systems/[^"]+)">docker</a>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("hosts page does not link the system")
	}
	resp, body := h.do(t, "GET", m[1], nil, nil)
	body = html.UnescapeString(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("system page: %d %s", resp.StatusCode, body[:min(len(body), 3000)])
	}
	for _, want := range []string{"Where Varde knows it from", "3 packages and 1 Docker containers read", "immich_server", "ghcr.io/immich-app/immich-server:v1.120.0",
		"libssl3t64", "3.0.13-0ubuntu3.5", "openssl", "openssh-server", "Installed packages"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// The filter narrows the package list.
	_, body = h.do(t, "GET", m[1]+"?q=ssl", nil, nil)
	if !strings.Contains(body, "libssl3t64") || strings.Contains(body, ">bash<") {
		t.Error("filter did not narrow the list")
	}
	// The node: guests seen from the outside only, with the step.
	_, body = h.do(t, "GET", "/systems", nil, nil)
	n := regexp.MustCompile(`href="(/systems/[^"]+)">pve1</a>`).FindStringSubmatch(body)
	if n == nil {
		t.Fatal("node not linked")
	}
	_, body = h.do(t, "GET", n[1], nil, nil)
	if !strings.Contains(body, "Read all guests of this node") || !strings.Contains(body, "/connections/connect/proxmox-lxc?address=10.0.0.2") {
		t.Error("node blind spot missing")
	}
	if resp, _ := h.do(t, "GET", "/systems/nope", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown system: %d", resp.StatusCode)
	}
}
