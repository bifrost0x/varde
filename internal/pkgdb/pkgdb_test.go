// SPDX-License-Identifier: Apache-2.0

package pkgdb

import (
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

func TestParser(t *testing.T) {
	var p Parser
	p.Feed([]byte("Package: curl\r\nStatus: install ok installed\r\nVersion: 8.14.1-2\r\n\r\nPackage: libssl3t64\nStatus: install ok installed\nSource: openssl (3.5.1-1)\nVersion: 3.5.1-1+b1\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: noversion\nStatus: install ok installed\n"))
	p.Feed([]byte("C:Q1abc\nP:libcrypto3\nV:3.5.4-r0\nA:x86_64\no:openssl\n\nP:musl\nV:1.2.5-r10\no:musl\n\nP:orphan\n"))
	got := p.Packages("debian-13")
	want := []inventory.Package{
		{Manager: "dpkg", Name: "curl", Version: "8.14.1-2", Distro: "debian-13"},
		{Manager: "dpkg", Name: "libssl3t64", Version: "3.5.1-1+b1", Distro: "debian-13", Source: "openssl", SourceVersion: "3.5.1-1"},
		{Manager: "apk", Name: "libcrypto3", Version: "3.5.4-r0", Distro: "debian-13", Source: "openssl"},
		{Manager: "apk", Name: "musl", Version: "1.2.5-r10", Distro: "debian-13"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestOSRelease(t *testing.T) {
	o := ParseOSRelease([]byte("PRETTY_NAME=\"Alpine Linux v3.24\"\nNAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.24.4\n"))
	if o.Distro() != "alpine-3.24.4" || o.String() != "Alpine Linux 3.24.4" {
		t.Errorf("%+v %q %q", o, o.Distro(), o.String())
	}
	if (OSRelease{ID: "Bad ID; x"}).Distro() != "" {
		t.Error("invalid ID accepted")
	}
	if (OSRelease{ID: "debian", VersionID: "../x y"}).Distro() != "debian" {
		t.Error("invalid VERSION_ID kept")
	}
}

func TestParseNPMManifest(t *testing.T) {
	m, ok := ParseNPMManifest([]byte(`{"name": " uptime-kuma ", "version": "1.23.17", "scripts": {}}`))
	if !ok || m != (inventory.Package{Manager: "npm", Name: "uptime-kuma", Version: "1.23.17"}) {
		t.Errorf("%+v %v", m, ok)
	}
	for _, bad := range []string{`{"name": "x"}`, `{"version": "1.0.0"}`, `not json`, `{"name": "x", "version": 1}`, `[]`} {
		if _, ok := ParseNPMManifest([]byte(bad)); ok {
			t.Errorf("%s accepted", bad)
		}
	}
}
