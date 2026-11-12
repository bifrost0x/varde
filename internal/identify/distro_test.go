// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/inventory"
)

func TestDistroPackage(t *testing.T) {
	cat, err := catalog.Load(fstest.MapFS{
		"nginx.yaml": {Data: []byte(`id: nginx
name: nginx
homepage: https://nginx.org
images: [{match: library/nginx}]
packages: [{manager: dpkg, name: nginx}, {manager: apk, name: nginx}, {manager: rpm, name: nginx}, {manager: dpkg, name: nginx-core, source: nginx}]
version: {scheme: semver}` + tail)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := func(manager, name, version, release string) inventory.Workload {
		return inventory.Workload{Kind: inventory.KindPackage, Package: &inventory.Package{Manager: manager, Name: name, Version: version, Distro: release}}
	}
	r := Identify(cat, pkg("dpkg", "nginx", "1.22.1-9+deb12u8", "debian-12"))
	want := distro.Package{Ecosystem: "Debian:12", Name: "nginx", Version: "1.22.1-9+deb12u8"}
	if r.DistroPackage == nil || *r.DistroPackage != want || r.Trust != Confirmed || !r.VersionKnown() || r.Version != "" || r.Doubt() != "" {
		t.Errorf("debian package: %+v", r)
	}
	// The binary package names its source package.
	if r := Identify(cat, pkg("dpkg", "nginx-core", "1.22.1-9", "debian-12")); r.DistroPackage == nil || r.DistroPackage.Name != "nginx" {
		t.Errorf("source name: %+v", r.DistroPackage)
	}
	if r := Identify(cat, pkg("apk", "nginx", "1.28.3-r2", "alpine-3.22.1")); r.DistroPackage == nil || r.DistroPackage.Ecosystem != "Alpine:v3.22" {
		t.Errorf("alpine package: %+v", r.DistroPackage)
	}
	// No distribution data: a vendor build, a release without data, a
	// package manager that does not fit the release.
	for _, w := range []inventory.Workload{
		pkg("dpkg", "nginx", "1.28.0-1~bookworm", "debian-12"),
		pkg("rpm", "nginx", "1.26.3-1.fc42", "fedora-42"),
		pkg("apk", "nginx", "1.28.3-r2", "debian-12"),
		pkg("dpkg", "nginx", "1.22.1-9", ""),
	} {
		r := Identify(cat, w)
		if r.DistroPackage != nil || r.VersionKnown() || !strings.Contains(r.Note, "distribution package") {
			t.Errorf("%+v: %+v", w.Package, r)
		}
	}
	got := DistroPackages(cat, []inventory.Workload{
		pkg("dpkg", "nginx", "1.22.1-9+deb12u8", "debian-12"),
		pkg("dpkg", "unknown", "1", "debian-12"),
		{Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "nginx:1.28.0"}},
	})
	if len(got) != 1 || len(got["nginx"]) != 1 {
		t.Errorf("DistroPackages: %+v", got)
	}
}
