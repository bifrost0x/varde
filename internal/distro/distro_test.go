// SPDX-License-Identifier: Apache-2.0

package distro

import (
	"testing"
	"time"
)

func TestEcosystem(t *testing.T) {
	for release, want := range map[string]string{
		"debian-12":                    "Debian:12 dpkg",
		"debian-13":                    "Debian:13 dpkg",
		"ubuntu-24.04":                 "Ubuntu:24.04:LTS dpkg",
		"ubuntu-22.04":                 "Ubuntu:22.04:LTS dpkg",
		"ubuntu-25.04":                 "Ubuntu:25.04 dpkg",
		"ubuntu-24.10":                 "Ubuntu:24.10 dpkg",
		"alpine-3.22.1":                "Alpine:v3.22 apk",
		"alpine-3.24":                  "Alpine:v3.24 apk",
		"debian":                       "",
		"alpine-edge":                  "",
		"fedora-42":                    "",
		"":                             "",
		"debian-12; x":                 "",
		"almalinux-9.8":                "AlmaLinux:9 rpm",
		"rocky-9.3":                    "Rocky Linux:9 rpm",
		"opensuse-leap-15.6":           "openSUSE:Leap 15.6 rpm",
		"rhel-9.4":                     "Red Hat:enterprise_linux:9 rpm",
		"rhel-8":                       "Red Hat:enterprise_linux:8 rpm",
		"wolfi":                        "Wolfi apk",
		"wolfi-20230201":               "Wolfi apk",
		"chainguard":                   "Chainguard apk",
		"opensuse-tumbleweed-20241010": "openSUSE:Tumbleweed rpm",
		"centos-9":                     "",
	} {
		eco, mgr, ok := Ecosystem(release)
		got := ""
		if ok {
			got = eco + " " + mgr
		}
		if got != want {
			t.Errorf("%q: %q, want %q", release, got, want)
		}
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		eco, a, b string
		want      int
		ok        bool
	}{
		{"Debian:12", "1.22.1-9+deb12u3", "1.22.1-9+deb12u4", -1, true},
		{"Debian:12", "1.22.1-9+deb12u4", "1.22.1-9+deb12u4", 0, true},
		{"Ubuntu:24.04:LTS", "1.24.0-2ubuntu7.5", "1.24.0-2ubuntu7.10", -1, true},
		{"Alpine:v3.22", "1.28.3-r2", "1.28.3-r10", -1, true},
		{"Alpine:v3.22", "not-a-version", "1.0-r0", 0, false},
		{"Fedora:42", "1", "2", 0, false},
		{"Debian:12", "", "1", 0, false},
		{"AlmaLinux:9", "1:1.20.1-14.el9_2.1.alma.1", "1:1.20.1-14.el9_2.1.alma.2", -1, true},
		{"AlmaLinux:9", "1.22.1-1.el9", "1:1.20.1-14.el9", 1, true},
		{"Rocky Linux:9", "0:8.7p1-29.el9_2", "8.7p1-30.el9", -1, true},
		{"AlmaLinux:9", "1:1.0-1.el9", "2:0.1-1.el9", -1, true},
	} {
		got, ok := Compare(c.eco, c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("%s %s vs %s: %d %v, want %d %v", c.eco, c.a, c.b, got, ok, c.want, c.ok)
		}
	}
	if !PerCVE("DEBIAN-CVE-2026-1642") || PerCVE("DSA-6131-1") || PerCVE("USN-8955-1") || !PerCVE("ALPINE-CVE-2026-9256") {
		t.Error("PerCVE")
	}
}

func TestForeign(t *testing.T) {
	for v, want := range map[string]bool{
		"1.28.0-1~bookworm":  true,
		"1.26.3-1~noble":     true,
		"9.2p1-2~bpo12+1":    true,
		"1.22.1-9+deb12u8":   false,
		"1.0~rc1-2":          false,
		"2.4.62-1ubuntu1.2":  false,
		"1:9.2p1-2+deb12u7":  false,
		"1.24.0-2ubuntu7.10": false,
	} {
		if got := Foreign("Debian:12", v); got != want {
			t.Errorf("%s: %v, want %v", v, got, want)
		}
	}
	if Foreign("Alpine:v3.22", "1.0-r0~bookworm") {
		t.Error("Alpine versions have no codenames")
	}
}

func TestForeignRPM(t *testing.T) {
	for v, want := range map[string]bool{
		"1:1.20.1-14.el9_2.1.alma.1":                 false,
		"1:1.22.1-3.module+el9.2.0+15280+45c505d6.1": false,
		"0:8.7p1-29.el9_2":                           false,
		"2:1.26.3-2.module_el9.7.0+223+9cd7031b.1":   false,
		"1:1.28.0-1.el9.ngx":                         true,
		"2.4.1-1":                                    true,
	} {
		if got := Foreign("AlmaLinux:9", v); got != want {
			t.Errorf("%s: %v, want %v", v, got, want)
		}
	}
	if !Notices("Rocky Linux:9") || Notices("Debian:12") {
		t.Error("Notices")
	}
}

// Debian 11 in long-term support has notices only on osv.dev: they are kept
// rather than nothing; where per-CVE records exist, the notices are dropped.
func TestKeepRecords(t *testing.T) {
	now := time.Now()
	lts := map[string]time.Time{"DLA-3942-1": now, "DSA-5417-1": now}
	if got := KeepRecords("Debian:11", lts); len(got) != 2 {
		t.Fatalf("notices only: %v", got)
	}
	mixed := map[string]time.Time{"DEBIAN-CVE-2024-1": now, "DSA-5417-1": now}
	if got := KeepRecords("Debian:12", mixed); len(got) != 1 || got["DEBIAN-CVE-2024-1"].IsZero() {
		t.Fatalf("mixed: %v", got)
	}
	if got := KeepRecords("Rocky Linux:9", map[string]time.Time{"RLSA-2024:1": now}); len(got) != 1 {
		t.Fatalf("notice ecosystem: %v", got)
	}
}

// Red Hat keeps its data per repository; a package list does not say which
// repository a package came from, so all of them apply.
func TestRedHatVariants(t *testing.T) {
	now := time.Now()
	got := Variants("Red Hat:enterprise_linux:9", now)
	if len(got) != 3 || got[0] != "Red Hat:enterprise_linux:9::baseos" || got[1] != "Red Hat:enterprise_linux:9::appstream" {
		t.Fatalf("variants %v", got)
	}
	if !SameRelease("Red Hat:enterprise_linux:9::appstream", "Red Hat:enterprise_linux:9", now) || SameRelease("Red Hat:enterprise_linux:8::baseos", "Red Hat:enterprise_linux:9", now) {
		t.Error("repository records not matched to their release")
	}
	if c, ok := Compare("Wolfi", "3.3.2-r0", "3.3.2-r1"); !ok || c >= 0 {
		t.Errorf("Wolfi versions compare %d %v, want apk order", c, ok)
	}
	if c, ok := Compare("Red Hat:enterprise_linux:9::baseos", "1:3.0.7-24.el9", "1:3.0.7-27.el9"); !ok || c >= 0 {
		t.Errorf("Red Hat versions compare %d %v, want rpm order", c, ok)
	}
	if !Supported("Chainguard") || !Supported("Red Hat:enterprise_linux:9") || Supported("Fedora:42") {
		t.Error("supported distributions")
	}
}
