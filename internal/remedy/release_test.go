// SPDX-License-Identifier: Apache-2.0

package remedy

import (
	"slices"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/version"
)

// record is a distribution record (or a language one, which is stored the
// same way) for one package, fixed in fixed.
func record(id, eco, name, fixed string) match.Advisory {
	return match.Advisory{Source: match.SourceDistro, Vuln: advisory.Vulnerability{
		ID: id,
		Affected: []advisory.Affected{{
			Package: advisory.Package{Ecosystem: eco, Name: name},
			Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
		}},
	}}
}

// releaseAdvs are the records of the test packages, by package.
var releaseAdvs = map[string][]match.Advisory{
	"Debian:12/openssl": {record("DEBIAN-CVE-2026-1", "Debian:12", "openssl", "3.0.15-1~deb12u1")},
	"Debian:12/zlib":    {record("DEBIAN-CVE-2026-2", "Debian:12", "zlib", "1:1.2.13.dfsg-2")},
	"Debian:12/libxml2": {record("DEBIAN-CVE-2026-3", "Debian:12", "libxml2", "2.9.14+dfsg-1.4")},
	"npm/lodash":        {record("GHSA-lodash", "npm", "lodash", "4.17.21")},
}

func advsOf(p distro.Package) []match.Advisory { return releaseAdvs[p.Ecosystem+"/"+p.Name] }

// containerFindings are the image findings of a container with pkgs, as
// the analysis makes them: one Match per source package.
func containerFindings(t *testing.T, pkgs []inventory.Package) []match.Finding {
	t.Helper()
	var out []match.Finding
	for _, p := range imagePackages("debian-12", pkgs) {
		pkg := p
		for _, f := range match.Match(match.Input{App: &catalog.App{ID: distro.SystemAppID(p.Ecosystem, p.Name), Name: p.Name}, Distro: &pkg}, advsOf(p), match.Enrichment{}) {
			f.Image = true
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		t.Fatal("no findings")
	}
	return out
}

func deb(name, v string) inventory.Package {
	return inventory.Package{Manager: "dpkg", Name: name, Version: v}
}

func lodash(v string) inventory.Package {
	return inventory.Package{Manager: "npm", Name: "lodash", Version: v, Path: "/app/package-lock.json"}
}

var running = []inventory.Package{
	deb("openssl", "3.0.11-1~deb12u2"),
	deb("zlib", "1:1.2.13.dfsg-1"),
	deb("libxml2", "2.9.14+dfsg-1.3~deb12u1"),
	lodash("4.17.20"),
}

var cyberchef = &catalog.App{ID: "cyberchef", Name: "CyberChef", Version: catalog.VersionSpec{Scheme: version.SemVer}}

func line(arch, variant string, partial bool, pkgs ...inventory.Package) feed.ReleaseLine {
	return feed.ReleaseLine{
		AppID: "cyberchef", Image: "ghcr.io/gchq/cyberchef", Tag: "v10.20.0", Version: "10.20.0",
		IndexDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Platform:    feed.ReleasePlatform{OS: "linux", Arch: arch, Variant: variant},
		Read:        time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC), Distro: "debian-12", Partial: partial, Packages: pkgs,
	}
}

func ids(fs []Flaw) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.AdvisoryID)
	}
	slices.Sort(out)
	return out
}

func amd64() registry.Platform { return registry.Platform{OS: "linux", Arch: "amd64"} }

func TestReleaseFixCounts(t *testing.T) {
	findings := containerFindings(t, running)
	// The release fixes openssl, keeps the flawed zlib, no longer ships
	// libxml2 and brings a fixed lodash.
	rel := line("amd64", "", false,
		deb("openssl", "3.0.15-1~deb12u1"), deb("zlib", "1:1.2.13.dfsg-1"), lodash("4.17.21"))
	fix, ok := ReleaseFixFor(cyberchef, "10.19.0", amd64(), findings, []feed.ReleaseLine{rel}, advsOf)
	if !ok {
		t.Fatalf("no release fix: %+v", fix)
	}
	if got := ids(fix.Fixed); !slices.Equal(got, []string{"DEBIAN-CVE-2026-1", "DEBIAN-CVE-2026-3", "GHSA-lodash"}) {
		t.Errorf("fixed = %v", got)
	}
	if got := ids(fix.Open); !slices.Equal(got, []string{"DEBIAN-CVE-2026-2"}) {
		t.Errorf("open = %v", got)
	}
	if fix.Tag != "v10.20.0" || fix.Newest || !fix.Read.Equal(rel.Read) || fix.Total() != 4 {
		t.Errorf("fix = %+v", fix)
	}
	// Findings that are not of the image are no business of a release
	// of it.
	app := match.Finding{AdvisoryID: "GHSA-app", State: match.Affected, Evidence: match.Evidence{Package: "cyberchef"}}
	if fix2, _ := ReleaseFixFor(cyberchef, "10.19.0", amd64(), append(findings, app), []feed.ReleaseLine{rel}, advsOf); fix2.Total() != 4 {
		t.Errorf("app finding counted: %+v", fix2)
	}
	// No findings of the image: nothing to say.
	if _, ok := ReleaseFixFor(cyberchef, "10.19.0", amd64(), []match.Finding{app}, []feed.ReleaseLine{rel}, advsOf); ok {
		t.Error("release fix without image findings")
	}
}

func TestReleaseNotNewer(t *testing.T) {
	findings := containerFindings(t, running)
	rel := line("amd64", "", false, deb("openssl", "3.0.15-1~deb12u1"))
	for _, tc := range []struct {
		name, running string
		newest        bool
	}{
		{"equal", "10.20.0", true},
		// A re-tagged stream or a downgrade: the newest release is older
		// than what runs, so it fixes nothing the container could get.
		{"older", "10.21.0", true},
		{"unknown", "", false},
		{"unparseable", "not-a-version", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fix, ok := ReleaseFixFor(cyberchef, tc.running, amd64(), findings, []feed.ReleaseLine{rel}, advsOf)
			if ok || len(fix.Fixed) > 0 || len(fix.Open) > 0 {
				t.Fatalf("claims a fix: %+v", fix)
			}
			if fix.Newest != tc.newest || fix.Tag != "v10.20.0" {
				t.Errorf("fix = %+v, want newest %v", fix, tc.newest)
			}
		})
	}
}

func TestAbsentPackagePartialRelease(t *testing.T) {
	findings := containerFindings(t, running)
	pkgs := []inventory.Package{deb("openssl", "3.0.15-1~deb12u1"), deb("zlib", "1:1.2.13.dfsg-2")}
	// A complete read: libxml2 and lodash are not in the release.
	fix, ok := ReleaseFixFor(cyberchef, "10.19.0", amd64(), findings, []feed.ReleaseLine{line("amd64", "", false, pkgs...)}, advsOf)
	if !ok || len(fix.Open) != 0 || len(fix.Fixed) != 4 {
		t.Fatalf("complete read: %+v", fix)
	}
	// A read that stopped at a bound: the missing packages may be there.
	fix, ok = ReleaseFixFor(cyberchef, "10.19.0", amd64(), findings, []feed.ReleaseLine{line("amd64", "", true, pkgs...)}, advsOf)
	if !ok {
		t.Fatal("no release fix")
	}
	if got := ids(fix.Open); !slices.Equal(got, []string{"DEBIAN-CVE-2026-3", "GHSA-lodash"}) {
		t.Errorf("partial read, open = %v", got)
	}
	if got := ids(fix.Fixed); !slices.Equal(got, []string{"DEBIAN-CVE-2026-1", "DEBIAN-CVE-2026-2"}) {
		t.Errorf("partial read, fixed = %v", got)
	}
	// A release on another distribution: a Debian package it lacks is
	// not known to be fixed, its packages are compared with other records.
	alpine := line("amd64", "", false, lodash("4.17.21"))
	alpine.Distro = "alpine-3.20"
	fix, ok = ReleaseFixFor(cyberchef, "10.19.0", amd64(), findings, []feed.ReleaseLine{alpine}, advsOf)
	if !ok || !slices.Equal(ids(fix.Fixed), []string{"GHSA-lodash"}) || len(fix.Open) != 3 {
		t.Errorf("other distribution: %+v", fix)
	}
}

func TestPlatformChoice(t *testing.T) {
	findings := containerFindings(t, running)
	// The amd64 image got the fixed openssl, the arm64 one did not.
	x86 := line("amd64", "", false, deb("openssl", "3.0.15-1~deb12u1"), deb("zlib", "1:1.2.13.dfsg-2"), deb("libxml2", "2.9.14+dfsg-1.4"), lodash("4.17.21"))
	arm := line("arm64", "v8", false, deb("openssl", "3.0.11-1~deb12u2"), deb("zlib", "1:1.2.13.dfsg-2"), deb("libxml2", "2.9.14+dfsg-1.4"), lodash("4.17.21"))
	arm7 := line("arm", "v7", false, deb("openssl", "3.0.11-1~deb12u2"), deb("zlib", "1:1.2.13.dfsg-1"), deb("libxml2", "2.9.14+dfsg-1.4"), lodash("4.17.21"))
	lines := []feed.ReleaseLine{x86, arm, arm7}
	open := func(p registry.Platform, lines []feed.ReleaseLine) ([]string, bool) {
		fix, ok := ReleaseFixFor(cyberchef, "10.19.0", p, findings, lines, advsOf)
		return ids(fix.Open), ok
	}
	if got, ok := open(HostPlatform("aarch64"), lines); !ok || !slices.Equal(got, []string{"DEBIAN-CVE-2026-1"}) {
		t.Errorf("arm64 host: open = %v (%v)", got, ok)
	}
	if got, ok := open(HostPlatform("x86_64"), lines); !ok || len(got) != 0 {
		t.Errorf("amd64 host: open = %v (%v)", got, ok)
	}
	if got, ok := open(HostPlatform("armv7l"), lines); !ok || !slices.Equal(got, []string{"DEBIAN-CVE-2026-1", "DEBIAN-CVE-2026-2"}) {
		t.Errorf("armv7 host: open = %v (%v)", got, ok)
	}
	// Unknown host platform: amd64.
	if got, ok := open(HostPlatform(""), lines); !ok || len(got) != 0 {
		t.Errorf("unknown host: open = %v (%v)", got, ok)
	}
	// An arm64 host with no arm64 image in the release: no other
	// platform's list stands in for it.
	if _, ok := open(HostPlatform("arm64"), []feed.ReleaseLine{x86, arm7}); ok {
		t.Error("arm64 host compared with another platform's packages")
	}
	// A single-platform image is what the tag pulls on every host.
	single := x86
	single.IndexDigest = ""
	if got, ok := open(HostPlatform("arm64"), []feed.ReleaseLine{single}); !ok || len(got) != 0 {
		t.Errorf("single-platform image: open = %v (%v)", got, ok)
	}
	// A 32-bit ARM host of unknown variant cannot choose between v6 and v7.
	arm6 := arm7
	arm6.Platform.Variant = "v6"
	if _, ok := open(HostPlatform("arm"), []feed.ReleaseLine{x86, arm6, arm7}); ok {
		t.Error("arm host of unknown variant chose a line")
	}
	if got, ok := open(HostPlatform("arm"), []feed.ReleaseLine{x86, arm7}); !ok || len(got) != 2 {
		t.Errorf("arm host, one arm line: open = %v (%v)", got, ok)
	}
}

func TestHostPlatform(t *testing.T) {
	for in, want := range map[string]registry.Platform{
		"amd64": {OS: "linux", Arch: "amd64"}, "x86_64": {OS: "linux", Arch: "amd64"},
		"aarch64": {OS: "linux", Arch: "arm64"}, "arm64": {OS: "linux", Arch: "arm64"},
		"armv7l": {OS: "linux", Arch: "arm", Variant: "v7"}, "armv6l": {OS: "linux", Arch: "arm", Variant: "v6"},
		"arm": {OS: "linux", Arch: "arm"}, "i686": {OS: "linux", Arch: "386"}, "ppc64le": {OS: "linux", Arch: "ppc64le"},
		"": {}, "sparc": {},
	} {
		if got := HostPlatform(in); got != want {
			t.Errorf("HostPlatform(%q) = %+v, want %+v", in, got, want)
		}
	}
}

// imagePackages is what the analysis checks of an image: the same reading
// the release's packages get.
func imagePackages(distroName string, pkgs []inventory.Package) []distro.Package {
	return identify.ImageCheckedPackages(&inventory.Container{Distro: distroName, Packages: pkgs})
}
