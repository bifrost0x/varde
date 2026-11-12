// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
)

// The app's own package.json in the image gives the version of a floating
// tag; on a development branch it is only reported.
func TestContainerManifest(t *testing.T) {
	cat, err := catalog.Load(fstest.MapFS{
		"uptime-kuma.yaml": {Data: []byte(`id: uptime-kuma
name: Uptime Kuma
homepage: https://uptime.kuma.pet
images: [{match: louislam/uptime-kuma}]
version: {scheme: semver}` + tail)},
		"open-webui.yaml": {Data: []byte(`id: open-webui
name: Open WebUI
homepage: https://openwebui.com
images: [{match: ghcr.io/open-webui/open-webui}]
oci_source: [https://github.com/open-webui/open-webui]
version: {scheme: semver}` + tail)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	run := func(image string, pkgs ...inventory.Package) Result {
		w := ctr("x", image, nil, nil)
		w.Container.Packages = pkgs
		return Identify(cat, w)
	}
	npm := func(name, version string) inventory.Package {
		return inventory.Package{Manager: "npm", Name: name, Version: version, Path: "/app/package.json"}
	}

	r := run("louislam/uptime-kuma:latest", npm("uptime-kuma", "1.23.17"))
	if r.Version != "1.23.17" || r.Trust != Confirmed || r.VersionSource != "manifest /app/package.json" || r.Doubt() != "" {
		t.Errorf("release channel: %+v", r)
	}
	r = run("ghcr.io/open-webui/open-webui:main", npm("open-webui", "0.13.3"))
	if r.Version != "0.13.3" || r.Trust != Reported || r.Doubt() == "" || !strings.Contains(r.Note, "development branch") {
		t.Errorf("development branch: %+v", r)
	}
	// Names are matched by app ID, name, alias or source repository.
	if r := run("ghcr.io/open-webui/open-webui:latest", npm("@acme/open-webui", "0.13.3")); r.Version != "0.13.3" {
		t.Errorf("scoped name: %+v", r)
	}
	// A manifest of something else in the image says nothing.
	for _, p := range []inventory.Package{npm("express", "4.21.2"), npm("", "1.0.0"), {Manager: "npm", Name: "uptime-kuma", Version: "1.23.17"}} {
		if r := run("louislam/uptime-kuma:latest", p); r.Version != "" {
			t.Errorf("%+v used: %+v", p, r)
		}
	}
	// A pinned tag that disagrees with the manifest is a conflict.
	if r := run("louislam/uptime-kuma:1.23.16", npm("uptime-kuma", "1.23.17")); r.Trust != Conflict {
		t.Errorf("tag and manifest disagree: %+v", r)
	}
	if r := run("louislam/uptime-kuma:latest", npm("uptime-kuma", "workspace")); r.Version != "" || len(r.Evidence) != 1 {
		t.Errorf("invalid manifest version: %+v", r)
	}
}

// Evidence files changed inside a container do not describe it: the
// image's packages and manifest are recorded, not used.
func TestChangedInside(t *testing.T) {
	cat, err := catalog.Load(fstest.MapFS{
		"uptime-kuma.yaml": {Data: []byte(`id: uptime-kuma
name: Uptime Kuma
homepage: https://uptime.kuma.pet
images: [{match: louislam/uptime-kuma}]
packages: [{manager: dpkg, name: uptime-kuma, versioning: upstream}]
version: {scheme: semver}` + tail)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := ctr("x", "louislam/uptime-kuma:latest", nil, nil)
	w.Container.Packages = []inventory.Package{
		{Manager: "npm", Name: "uptime-kuma", Version: "1.23.17", Path: "/app/package.json"},
		{Manager: "dpkg", Name: "uptime-kuma", Version: "1.23.17-1"},
	}
	if r := Identify(cat, w); r.Version != "1.23.17" {
		t.Fatalf("unchanged: %+v", r)
	}
	w.Container.ChangedFiles = []string{"/app/package.json", "/var/lib/dpkg/status"}
	r := Identify(cat, w)
	if r.Version != "" || len(r.Evidence) != 2 || !strings.Contains(r.Note, "changed inside the container") {
		t.Errorf("changed files used: %+v", r)
	}
	for _, e := range r.Evidence {
		if e.Version != "" || !strings.Contains(e.Method, "changed inside the container") {
			t.Errorf("evidence: %+v", e)
		}
	}
}
