// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"strings"
	"testing"
)

// The current key line reads the RPM epoch; lines set up before keep the
// old format, which is still read.
func TestParseInventoryRPMEpoch(t *testing.T) {
	head := "varde-inventory 1\n@@os-release\nID=\"almalinux\"\nVERSION_ID=\"9.8\"\n@@rpm\n"
	for _, c := range []struct{ rpm, want string }{
		{"nginx=2:1.26.3-2.module_el9.7.0+223+9cd7031b.1;bash=0:5.1.8-9.el9;", "2:1.26.3-2.module_el9.7.0+223+9cd7031b.1"},
		{"nginx=1.26.3-2.module_el9.7.0+223+9cd7031b.1;", "1.26.3-2.module_el9.7.0+223+9cd7031b.1"},
	} {
		inv, err := ParseInventory([]byte(head + c.rpm + "\n@@end\n"))
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		for _, p := range inv.Packages {
			if p.Name == "nginx" {
				got = p.Version
				if p.Distro != "almalinux-9.8" {
					t.Errorf("distro %q", p.Distro)
				}
			}
		}
		if got != c.want {
			t.Errorf("version %q, want %q", got, c.want)
		}
	}
	if !strings.Contains(InventoryCommand, "%{EPOCHNUM}:") {
		t.Error("the inventory command does not read the epoch")
	}
}
