// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

func TestRebootReason(t *testing.T) {
	deb := func(name, version string) inventory.Package {
		return inventory.Package{Manager: "dpkg", Name: name, Version: version}
	}
	for _, c := range []struct {
		name string
		inv  HostInventory
		want string
	}{
		{"newer kernel installed", HostInventory{Distro: "debian-12", Kernel: "6.1.0-25-amd64", Packages: []inventory.Package{
			deb("linux-image-6.1.0-25-amd64", "6.1.106-3"), deb("linux-image-6.1.0-28-amd64", "6.1.119-1"), deb("linux-image-amd64", "6.1.119-1")}},
			"kernel 6.1.0-28-amd64 is installed, 6.1.0-25-amd64 is running"},
		{"running the newest", HostInventory{Distro: "debian-12", Kernel: "6.1.0-28-amd64", Packages: []inventory.Package{
			deb("linux-image-6.1.0-25-amd64", "6.1.106-3"), deb("linux-image-6.1.0-28-amd64", "6.1.119-1")}}, ""},
		{"running kernel removed", HostInventory{Distro: "ubuntu-24.04", Kernel: "6.8.0-40-generic", Packages: []inventory.Package{
			deb("linux-image-6.8.0-45-generic", "6.8.0-45.45")}}, "is no longer installed"},
		{"proxmox kernel", HostInventory{Distro: "debian-12", Kernel: "6.8.12-4-pve", Packages: []inventory.Package{
			deb("proxmox-kernel-6.8.12-4-pve-signed", "6.8.12-4"), deb("proxmox-kernel-6.8.12-8-pve-signed", "6.8.12-8")}},
			"kernel 6.8.12-8-pve is installed, 6.8.12-4-pve is running"},
		{"container without kernel packages", HostInventory{Distro: "debian-12", Kernel: "6.8.12-4-pve", Packages: []inventory.Package{deb("bash", "5.2.15-2")}}, ""},
		{"restart note", HostInventory{Distro: "ubuntu-24.04", RebootFlag: true, RebootPackages: []string{"libc6", "dbus"}},
			"updated packages wait for a restart: libc6, dbus"},
		{"nothing known", HostInventory{Distro: "alpine-3.22"}, ""},
	} {
		got := RebootReason(c.inv)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// Version 3 adds the running kernel and the restart notes; anything
// unexpected in them is dropped.
func TestParseInventoryV3(t *testing.T) {
	out := "varde-inventory 3\n@@hostname\nweb\n@@os-release\nID=debian\nVERSION_ID=\"12\"\n" +
		"@@kernel\n6.1.0-25-amd64\n@@reboot\nrequired\nlibc6\n$(rm -rf /)\nlibc6\n@@end\n"
	inv, err := ParseInventory([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Kernel != "6.1.0-25-amd64" || !inv.RebootFlag || len(inv.RebootPackages) != 1 || inv.RebootPackages[0] != "libc6" {
		t.Fatalf("inventory %+v", inv)
	}
	bad, err := ParseInventory([]byte("varde-inventory 3\n@@kernel\n6.1 0; reboot\n@@end\n"))
	if err != nil || bad.Kernel != "" {
		t.Fatalf("invalid kernel accepted: %q %v", bad.Kernel, err)
	}
}
