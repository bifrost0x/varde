// SPDX-License-Identifier: Apache-2.0

package upstream

import (
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
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/version"
)

var opensslRecord = match.Advisory{Source: match.SourceDistro, Vuln: advisory.Vulnerability{
	ID: "DEBIAN-CVE-2099-2",
	Affected: []advisory.Affected{{
		Package: advisory.Package{Ecosystem: "Debian:12", Name: "openssl"},
		Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.0.15-1~deb12u1"}}}},
	}},
}}

func advs(p distro.Package) []match.Advisory {
	if p.Ecosystem == "Debian:12" && p.Name == "openssl" {
		return []match.Advisory{opensslRecord}
	}
	return nil
}

// runningFindings are the image findings of a container with an old
// openssl, as the analysis makes them.
func runningFindings(t *testing.T) []match.Finding {
	t.Helper()
	img := &inventory.Container{Distro: "debian-12", Packages: []inventory.Package{{Manager: "dpkg", Name: "openssl", Version: "3.0.11-1~deb12u2", Source: "openssl"}}}
	var out []match.Finding
	for _, p := range identify.ImageSystemPackages(img) {
		pkg := p
		for _, f := range match.Match(match.Input{App: &catalog.App{ID: distro.SystemAppID(p.Ecosystem, p.Name), Name: p.Name}, Distro: &pkg}, advs(p), match.Enrichment{}) {
			f.Image = true
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("findings %+v", out)
	}
	return out
}

var chefApp = &catalog.App{ID: "cyberchef", Name: "CyberChef", Version: catalog.VersionSpec{Scheme: version.SemVer}}

// releaseLine is the data package's read of v10.20.0 with a fixed openssl.
func releaseLine() feed.ReleaseLine {
	return feed.ReleaseLine{AppID: "cyberchef", Image: "ghcr.io/gchq/cyberchef", Tag: "v10.20.0", Version: "10.20.0",
		IndexDigest: rebuilt, Platform: feed.ReleasePlatform{OS: "linux", Arch: "amd64"}, Read: time.Now(), Distro: "debian-12",
		Packages: []inventory.Package{{Manager: "dpkg", Name: "openssl", Version: "3.0.15-1~deb12u1", Source: "openssl"}}}
}

func dataPackageInput(t *testing.T, imageRef, runningTag string) Input {
	t.Helper()
	return Input{
		Container: &inventory.Container{ImageRef: imageRef, RepoDigests: []string{"ghcr.io/gchq/cyberchef@" + running}},
		Platform:  registry.Platform{OS: "linux", Arch: "amd64"},
		Findings:  runningFindings(t),
		App:       chefApp, Running: remedy.Running{Repository: "ghcr.io/gchq/cyberchef", Tag: runningTag},
		Lines: []feed.ReleaseLine{releaseLine()}, Advisories: advs,
	}
}

func TestEvaluateFromDataPackage(t *testing.T) {
	// An older running release: the newest release fixes openssl.
	st := Evaluate(dataPackageInput(t, "ghcr.io/gchq/cyberchef:v10.19.0", "v10.19.0"))
	if st.Kind != UpdateAvailable || st.TargetTag != "v10.20.0" || st.Rebuilt || st.Source != SourceDataPackage || len(st.Fixed) != 1 {
		t.Errorf("older release: %+v", st)
	}
	// The same release under another digest: a rebuild of the running tag.
	st = Evaluate(dataPackageInput(t, "ghcr.io/gchq/cyberchef:v10.20.0", "v10.20.0"))
	if st.Kind != UpdateAvailable || !st.Rebuilt || st.TargetTag != "v10.20.0" {
		t.Errorf("rebuilt release: %+v", st)
	}
	// A running release newer than the one the data package read: that
	// read says nothing about the running tag.
	st = Evaluate(dataPackageInput(t, "ghcr.io/gchq/cyberchef:v10.21.0", "v10.21.0"))
	if st.Kind != Unknown || st.Actionable() || st.Rebuilt {
		t.Errorf("newer running release: %+v", st)
	}
	// The running digest is the newest release's: nothing newer exists.
	in := dataPackageInput(t, "ghcr.io/gchq/cyberchef:v10.20.0", "v10.20.0")
	in.Container.RepoDigests = []string{"ghcr.io/gchq/cyberchef@" + rebuilt}
	if st = Evaluate(in); st.Kind != NoUpstreamFix {
		t.Errorf("newest release running: %+v", st)
	}
}
