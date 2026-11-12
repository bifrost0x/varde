// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/settings"
)

func withNginx(t *testing.T) func(*Deps) {
	return func(d *Deps) {
		cat, err := catalog.Load(fstest.MapFS{"nginx.yaml": {Data: []byte(`id: nginx
name: nginx
homepage: https://nginx.org
images: [{match: library/nginx}]
packages: [{manager: dpkg, name: nginx}]
eol: nginx
version: {scheme: semver}
advisories: {coverage: limited, notes: test}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-09
`)}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		d.Catalog = catalog.NewLive(cat)
	}
}

// A distribution package shows its version and release data on the
// inventory, and the next steps suggest the distribution security data
// while osv.dev queries are off.
func TestDistroPackages(t *testing.T) {
	var set *settings.Service
	h := newHarness(t, withNetwork(t), withNginx(t), func(d *Deps) { set = d.Settings })
	csrf := h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "ssh-web", Name: "web", Kind: inventory.HostLinux, Source: inventory.SourceSSHInventory, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "ssh-web", inventory.KindPackage, []inventory.Workload{
		{Kind: inventory.KindPackage, RuntimeID: "dpkg:nginx", Name: "nginx", Package: &inventory.Package{Manager: "dpkg", Name: "nginx", Version: "1.22.1-9+deb12u8", Distro: "debian-12"}},
	}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems/apps", nil, nil)
	if body = html.UnescapeString(body); !strings.Contains(body, "1.22.1-9+deb12u8") || !strings.Contains(body, "checked against the Debian:12 security data") {
		t.Error("distribution package version not shown")
	}
	if resp, _ := h.do(t, "POST", "/connections/scope", url.Values{"csrf": {csrf}, "networks": {"192.168.1.0/24"}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("scope")
	}
	_ = h.store.RecordDevices(ctx, []discovery.Device{{Address: "192.168.1.5", Kind: discovery.KindWeb, Label: "Web"}}, nil, now)
	_, body = h.do(t, "GET", "/connections", nil, nil)
	if !strings.Contains(body, "Check 1 distribution packages against their distribution") || !strings.Contains(body, "/settings#sources") {
		t.Error("distribution data step missing")
	}
	if err := set.Update(ctx, map[string]string{settings.KeyDirectOSV: "true"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	if _, body = h.do(t, "GET", "/connections", nil, nil); strings.Contains(body, "distribution packages against") {
		t.Error("step shown although osv.dev queries are on")
	}
}
