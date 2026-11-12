// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"os"
	"testing"
)

// Version 2 of the inventory command reads the package databases: every
// package of the host is listed, with the source package the
// distribution's security data names. The fixtures are its real output on
// Debian trixie, Fedora 42 and Alpine 3.22.
func TestParseInventoryV2(t *testing.T) {
	for _, c := range []struct {
		file, distro, manager string
		min                   int
		pkg, source           string
	}{
		{"inventory2-debian.txt", "debian-13", "dpkg", 70, "libssl3t64", "openssl"},
		{"inventory2-fedora.txt", "fedora-42", "rpm", 120, "openssl-libs", "openssl"},
		{"inventory2-alpine.txt", "alpine-3.22.", "apk", 14, "libcrypto3", "openssl"},
	} {
		out, err := os.ReadFile("testdata/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		inv, err := ParseInventory(out)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if len(inv.Packages) < c.min || len(inv.Distro) < len(c.distro) || inv.Distro[:len(c.distro)] != c.distro {
			t.Errorf("%s: %d packages, distro %q", c.file, len(inv.Packages), inv.Distro)
		}
		found := false
		for _, p := range inv.Packages {
			if p.Manager != c.manager {
				t.Errorf("%s: manager %q", c.file, p.Manager)
				break
			}
			if p.Name == c.pkg {
				found = p.Source == c.source && p.Version != "" && p.Distro == inv.Distro
			}
		}
		if !found {
			t.Errorf("%s: %s with source %s missing", c.file, c.pkg, c.source)
		}
	}
}
