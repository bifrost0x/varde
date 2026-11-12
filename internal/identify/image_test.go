// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

// One package per source package of an image, at the highest version;
// vendor builds, manifests and releases without data are left out.
func TestImageSystemPackages(t *testing.T) {
	c := &inventory.Container{Distro: "debian-12", Packages: []inventory.Package{
		{Manager: "dpkg", Name: "libc6", Version: "2.36-9", Source: "glibc"},
		{Manager: "dpkg", Name: "libc-bin", Version: "2.36-9+b1", Source: "glibc"},
		{Manager: "dpkg", Name: "nginx", Version: "1.27.0-1~bookworm"},
		{Manager: "npm", Name: "express", Version: "4.18.2", Path: "/app/package.json"},
	}}
	got := ImageSystemPackages(c)
	if len(got) != 1 || got[0].Name != "glibc" || got[0].Version != "2.36-9+b1" || got[0].Ecosystem != "Debian:12" {
		t.Fatalf("packages %+v", got)
	}
	if ImageSystemPackages(&inventory.Container{Distro: "", Packages: c.Packages}) != nil || ImageSystemPackages(nil) != nil {
		t.Fatal("packages without a release")
	}
}

// Packages of the language ecosystems an image's apps install are checked
// in their OSV ecosystems; a package without the file it came from (not
// read from the image) is not.
func TestImageLanguageEcosystems(t *testing.T) {
	c := &inventory.Container{Packages: []inventory.Package{
		{Manager: "pip", Name: "requests", Version: "2.31.0", Path: "/usr/local/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA"},
		{Manager: "maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Path: "/app/server.jar"},
		{Manager: "cargo", Name: "hyper", Version: "0.14.27", Path: "/usr/local/bin/app"},
		{Manager: "composer", Name: "guzzlehttp/guzzle", Version: "7.4.0", Path: "/var/www/vendor/composer/installed.json"},
		{Manager: "gem", Name: "rack", Version: "2.2.8", Path: "/usr/local/bundle/specifications/rack-2.2.8.gemspec"},
		{Manager: "nuget", Name: "Newtonsoft.Json", Version: "13.0.1", Path: "/app/App.deps.json"},
		{Manager: "pip", Name: "nopath", Version: "1.0"},
	}}
	got := map[string]string{}
	for _, p := range ImageLanguagePackages(c) {
		got[p.Ecosystem+" "+p.Name] = p.Version
	}
	for want, v := range map[string]string{
		"PyPI requests": "2.31.0", "Maven org.apache.logging.log4j:log4j-core": "2.14.1", "crates.io hyper": "0.14.27",
		"Packagist guzzlehttp/guzzle": "7.4.0", "RubyGems rack": "2.2.8", "NuGet Newtonsoft.Json": "13.0.1",
	} {
		if got[want] != v {
			t.Errorf("%s = %q, want %q (all %v)", want, got[want], v, got)
		}
	}
	if _, ok := got["PyPI nopath"]; ok {
		t.Error("package without a source file checked")
	}
}
