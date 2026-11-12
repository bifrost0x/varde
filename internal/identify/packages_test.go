// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
)

// Packages read from an image are version evidence: an upstream package
// states the release, a distribution package does not.
func TestContainerPackages(t *testing.T) {
	cat, err := catalog.Load(fstest.MapFS{
		"jellyfin.yaml": {Data: []byte(`id: jellyfin
name: Jellyfin
homepage: https://jellyfin.org
images: [{match: jellyfin/jellyfin}, {match: lscr.io/linuxserver/jellyfin, flavor: lsio}]
packages:
  - manager: dpkg
    name: jellyfin-server
    versioning: upstream
    version_pattern: '^(?P<v>\d+\.\d+(?:\.\d+)?)\+'
version: {scheme: semver}` + tail)},
		"nginx.yaml": {Data: []byte(`id: nginx
name: nginx
homepage: https://nginx.org
images: [{match: nginx}]
packages: [{manager: apk, name: nginx}]
version: {scheme: semver}` + tail)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := func(manager, name, version string) inventory.Package {
		return inventory.Package{Manager: manager, Name: name, Version: version, Distro: "ubuntu-24.04"}
	}
	run := func(image string, pkgs ...inventory.Package) Result {
		w := ctr("x", image, nil, nil)
		w.Container.Packages = pkgs
		return Identify(cat, w)
	}

	r := run("lscr.io/linuxserver/jellyfin:latest", pkg("dpkg", "jellyfin-server", "10.10.7+ubu2404"))
	if r.Version != "10.10.7" || r.Trust != Confirmed || !strings.Contains(r.VersionSource, "jellyfin-server in the image") || r.Doubt() != "" {
		t.Errorf("floating tag with upstream package: %+v", r)
	}
	// Without the package the floating tag leaves the version unknown.
	if r := run("lscr.io/linuxserver/jellyfin:latest"); r.Version != "" {
		t.Errorf("version without a source: %+v", r)
	}
	// A tag that agrees stays the source; the package confirms it.
	r = run("jellyfin/jellyfin:10.10.7", pkg("dpkg", "jellyfin-server", "10.10.7+deb13"))
	if r.Version != "10.10.7" || r.Trust != Confirmed || !strings.HasPrefix(r.VersionSource, "tag") || len(r.Evidence) != 2 {
		t.Errorf("tag and package agree: %+v", r)
	}
	// A tag that disagrees with the installed package is a conflict, which
	// cannot produce affected findings.
	r = run("jellyfin/jellyfin:10.10.6", pkg("dpkg", "jellyfin-server", "10.10.7+deb13"))
	if r.Trust != Conflict || r.Doubt() == "" {
		t.Errorf("tag and package disagree: %+v", r)
	}
	// A package version the pattern does not cover is recorded, not used.
	r = run("jellyfin/jellyfin:latest", pkg("dpkg", "jellyfin-server", "unstable"))
	if r.Version != "" || len(r.Evidence) != 1 || r.Evidence[0].Version != "" {
		t.Errorf("unparsable package version: %+v", r)
	}
	// Distribution packages keep the upstream version while carrying
	// backported fixes: no evidence.
	r = run("nginx:latest", pkg("apk", "nginx", "1.26.2-r0"))
	if r.Version != "" || len(r.Evidence) != 0 {
		t.Errorf("distribution package used: %+v", r)
	}
	// Packages of other apps in the image say nothing about this one.
	r = run("lscr.io/linuxserver/jellyfin:latest", pkg("apk", "nginx", "1.26.2-r0"), pkg("dpkg", "jellyfin", "10.10.7+ubu2404"))
	if r.Version != "" {
		t.Errorf("unrelated package used: %+v", r)
	}
}
