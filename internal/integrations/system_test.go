// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

// One system package per source package, at the highest binary version;
// vendor builds and unsupported releases are left out.
func TestSystemWorkloads(t *testing.T) {
	inv := HostInventory{Distro: "debian-13", Packages: []inventory.Package{
		{Manager: "dpkg", Name: "libssl3t64", Version: "3.5.1-1", Source: "openssl"},
		{Manager: "dpkg", Name: "openssl", Version: "3.5.1-1+b1", Source: "openssl"},
		{Manager: "dpkg", Name: "bash", Version: "5.2.37-2"},
		{Manager: "dpkg", Name: "nginx", Version: "1.28.0-1~trixie", Source: "nginx"},
		{Manager: "rpm", Name: "stray", Version: "1"},
	}}
	ws := SystemWorkloads(nil, inv)
	got := map[string]string{}
	for _, w := range ws {
		if w.Package == nil || !w.Package.System || w.Package.Distro != "debian-13" || w.Kind != inventory.KindPackage {
			t.Fatalf("not a system package: %+v", w)
		}
		got[w.Name] = w.Package.Version
	}
	if len(got) != 2 || got["openssl"] != "3.5.1-1+b1" || got["bash"] != "5.2.37-2" {
		t.Fatalf("system packages %v", got)
	}
	if ws := SystemWorkloads(nil, HostInventory{Distro: "fedora-42", Packages: inv.Packages}); ws != nil {
		t.Fatalf("release without security data: %v", ws)
	}
	// A source package a catalog app covers is not doubled.
	cat := testCatalog(t)
	withApp := HostInventory{Distro: "debian-13", Packages: append(inv.Packages, inventory.Package{Manager: "dpkg", Name: "jellyfin-server", Version: "10.10.3+deb13", Source: "jellyfin"})}
	for _, w := range SystemWorkloads(cat, withApp) {
		if w.Name == "jellyfin" || w.Name == "jellyfin-server" {
			t.Fatal("catalog app also listed as system package")
		}
	}
}
