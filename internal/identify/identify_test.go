// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
)

const tail = `
advisories:
  coverage: limited
  notes: test
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`

var testCatalog = fstest.MapFS{
	"immich.yaml": {Data: []byte(`id: immich
name: Immich
homepage: https://immich.app
images: [{match: ghcr.io/immich-app/immich-server}]
oci_source: [https://github.com/immich-app/immich]
version: {scheme: semver}` + tail)},
	"home-assistant.yaml": {Data: []byte(`id: home-assistant
name: Home Assistant
homepage: https://www.home-assistant.io
images: [{match: ghcr.io/home-assistant/home-assistant}, {match: homeassistant/home-assistant}]
version: {scheme: calver}` + tail)},
	"sonarr.yaml": {Data: []byte(`id: sonarr
name: Sonarr
homepage: https://sonarr.tv
images: [{match: lscr.io/linuxserver/sonarr, flavor: lsio}, {match: ghcr.io/hotio/sonarr}]
version: {scheme: semver}` + tail)},
	"homarr.yaml": {Data: []byte(`id: homarr
name: Homarr
homepage: https://homarr.dev
images: [{match: ghcr.io/homarr-labs/homarr}]
version:
  scheme: semver
  sources:
    - tag: '^v(?P<v>\d+\.\d+\.\d+)$'` + tail)},
	"vaultwarden.yaml": {Data: []byte(`id: vaultwarden
name: Vaultwarden
homepage: https://github.com/dani-garcia/vaultwarden
aliases: [bitwarden-rs]
images: [{match: vaultwarden/server}]
version:
  scheme: semver
  normalise: {strip_prefix: "release-"}` + tail)},
}

func loadCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load(testCatalog, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ctr(name, image string, imageLabels, labels map[string]string) inventory.Workload {
	return inventory.Workload{ID: "w-" + name, Kind: inventory.KindContainer, Name: name, Container: &inventory.Container{
		ImageRef: image, ImageLabels: imageLabels, Labels: labels,
	}}
}

func TestIdentifyContainers(t *testing.T) {
	cat := loadCatalog(t)
	cases := []struct {
		name       string
		w          inventory.Workload
		app        string
		conf       Confidence
		version    string
		source     string
		noteSubstr string
	}{
		{
			name: "image and OCI version label",
			w:    ctr("immich", "ghcr.io/immich-app/immich-server:release", map[string]string{LabelOCIVer: "v1.120.0"}, nil),
			app:  "immich", conf: Exact, version: "1.120.0", source: "image label " + LabelOCIVer,
		},
		{
			name: "floating tag without label",
			w:    ctr("immich", "ghcr.io/immich-app/immich-server:release", nil, nil),
			app:  "immich", conf: Exact, noteSubstr: "floating",
		},
		{
			name: "pinned tag",
			w:    ctr("immich", "ghcr.io/immich-app/immich-server:v1.119.1", nil, nil),
			app:  "immich", conf: Exact, version: "1.119.1", source: "tag v1.119.1",
		},
		{
			name: "garbage label falls through to tag",
			w:    ctr("immich", "ghcr.io/immich-app/immich-server:v1.119.1", map[string]string{LabelOCIVer: "main"}, nil),
			app:  "immich", conf: Exact, version: "1.119.1", source: "tag v1.119.1",
		},
		{
			name: "major-only tag is not a version",
			w:    ctr("immich", "ghcr.io/immich-app/immich-server:v1", nil, nil),
			app:  "immich", conf: Exact, noteSubstr: "does not match",
		},
		{
			name: "digest only",
			w:    ctr("immich", "ghcr.io/immich-app/immich-server@sha256:"+strings.Repeat("a", 64), nil, nil),
			app:  "immich", conf: Exact, noteSubstr: "digest",
		},
		{
			name: "varde.version override wins",
			w:    ctr("immich", "ghcr.io/immich-app/immich-server:v1.119.1", map[string]string{LabelOCIVer: "1.0.0"}, map[string]string{LabelVersion: "1.121.0"}),
			app:  "immich", conf: Exact, version: "1.121.0", source: "label " + LabelVersion,
		},
		{
			name: "invalid override ignored with note",
			w:    ctr("immich", "ghcr.io/immich-app/immich-server:v1.119.1", nil, map[string]string{LabelVersion: "newest"}),
			app:  "immich", conf: Exact, version: "1.119.1",
		},
		{
			name: "OCI source label",
			w:    ctr("immich", "registry.example.com/mirror/immich:v1.2.3", map[string]string{LabelOCISource: "https://github.com/immich-app/immich.git"}, nil),
			app:  "immich", conf: Strong, version: "1.2.3",
		},
		{
			name: "varde.app label",
			w:    ctr("photos", "registry.example.com/custom/build:2.0.0", nil, map[string]string{LabelApp: "immich"}),
			app:  "immich", conf: Exact, version: "2.0.0",
		},
		{
			name: "varde.app alias",
			w:    ctr("pw", "example/pw:1.30.0", nil, map[string]string{LabelApp: "bitwarden-rs"}),
			app:  "vaultwarden", conf: Exact, version: "1.30.0",
		},
		{
			name: "varde.app unknown",
			w:    ctr("x", "ghcr.io/immich-app/immich-server:v1.0.0", nil, map[string]string{LabelApp: "nope"}),
			conf: None, noteSubstr: "does not name",
		},
		{
			name: "calver",
			w:    ctr("ha", "ghcr.io/home-assistant/home-assistant:2026.11.1", nil, nil),
			app:  "home-assistant", conf: Exact, version: "2026.11.1",
		},
		{
			name: "calver month tag floats",
			w:    ctr("ha", "homeassistant/home-assistant:2026.11", nil, nil),
			app:  "home-assistant", conf: Exact, noteSubstr: "does not match",
		},
		{
			name: "lsio build label",
			w: ctr("sonarr", "lscr.io/linuxserver/sonarr:latest", map[string]string{
				"build_version": "Linuxserver.io version:- 4.0.11.2680-ls262 Build-date:- 2024-11-02T05:41:35+00:00",
			}, nil),
			app: "sonarr", conf: Exact, version: "4.0.11.2680", source: "image label build_version",
		},
		{
			name: "lsio via ghcr mirror and tag",
			w:    ctr("sonarr", "ghcr.io/linuxserver/sonarr:4.0.11.2680-ls262", nil, nil),
			app:  "sonarr", conf: Exact, version: "4.0.11.2680",
		},
		{
			name: "non-lsio image of same app uses default chain",
			w:    ctr("sonarr", "ghcr.io/hotio/sonarr:release-4.0.11.2680", nil, nil),
			app:  "sonarr", conf: Exact, noteSubstr: "does not match",
		},
		{
			name: "floating channel tag of non-lsio image",
			w:    ctr("sonarr", "ghcr.io/hotio/sonarr:release", nil, nil),
			app:  "sonarr", conf: Exact, noteSubstr: "floating",
		},
		{
			name: "custom tag source ignores garbage OCI label",
			w:    ctr("homarr", "ghcr.io/homarr-labs/homarr:v2.10.1", map[string]string{LabelOCIVer: "main"}, nil),
			app:  "homarr", conf: Exact, version: "2.10.1", source: "tag v2.10.1",
		},
		{
			name: "strip prefix",
			w:    ctr("vw", "vaultwarden/server:1.32.0", map[string]string{LabelOCIVer: "release-1.32.5"}, nil),
			app:  "vaultwarden", conf: Exact, version: "1.32.5",
		},
		{
			name: "weak by compose service",
			w: func() inventory.Workload {
				w := ctr("stack-immich-1", "example/custom:1.0.0", nil, nil)
				w.Container.ComposeService = "immich"
				return w
			}(),
			app: "immich", conf: Weak, noteSubstr: "probably Immich",
		},
		{
			name: "unknown image",
			w:    ctr("random", "docker.io/someone/thing:1.0", nil, nil),
			conf: None, noteSubstr: "not in catalog",
		},
		{
			name: "broken reference",
			w:    ctr("broken", "::", nil, nil),
			conf: None, noteSubstr: "unparsable",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Identify(cat, c.w)
			if r.AppID != c.app || r.Confidence != c.conf || r.Version != c.version {
				t.Fatalf("got app=%q conf=%s version=%q note=%q; want app=%q conf=%s version=%q", r.AppID, r.Confidence, r.Version, r.Note, c.app, c.conf, c.version)
			}
			if c.source != "" && r.VersionSource != c.source {
				t.Errorf("source %q, want %q", r.VersionSource, c.source)
			}
			if c.noteSubstr != "" && !strings.Contains(r.Note, c.noteSubstr) {
				t.Errorf("note %q does not contain %q", r.Note, c.noteSubstr)
			}
			if r.Version == "" && r.AppID != "" && !strings.Contains(r.Note, LabelVersion) {
				t.Errorf("unknown version without remediation hint: %q", r.Note)
			}
			if r.WorkloadID != c.w.ID {
				t.Errorf("workload id %q", r.WorkloadID)
			}
		})
	}
}

func TestIdentifyOtherKinds(t *testing.T) {
	cat := loadCatalog(t)
	r := Identify(cat, inventory.Workload{Kind: inventory.KindManual, Manual: &inventory.Manual{AppID: "home-assistant", Version: "2026.10.4"}})
	if r.AppID != "home-assistant" || r.Confidence != Exact || r.Version != "2026.10.4" {
		t.Errorf("manual: %+v", r)
	}
	r = Identify(cat, inventory.Workload{Kind: inventory.KindManual, Manual: &inventory.Manual{AppID: "home-assistant", Version: "1.0"}})
	if r.Version != "" || !strings.Contains(r.Note, "calver") {
		t.Errorf("manual bad version: %+v", r)
	}
	r = Identify(cat, inventory.Workload{Kind: inventory.KindManual, Manual: &inventory.Manual{AppID: "unknown-app", Version: "1.0"}})
	if r.Confidence != None {
		t.Errorf("manual unknown app: %+v", r)
	}
	if r := Identify(cat, inventory.Workload{Kind: inventory.KindPackage, Package: &inventory.Package{Manager: "dpkg", Name: "x", Version: "1"}}); r.Confidence != None {
		t.Errorf("unknown package: %+v", r)
	}
	if got := distroUpstream("1:2.0.18-1+deb12u1"); got != "2.0.18" {
		t.Errorf("distroUpstream: %q", got)
	}
	if !Exact.Notifiable() || Weak.Notifiable() || None.Notifiable() {
		t.Error("Notifiable")
	}
}

func FuzzIdentify(f *testing.F) {
	f.Add("ghcr.io/immich-app/immich-server:v1.2.3", "v1.2.3", "1.0", "immich")
	f.Add("lscr.io/linuxserver/sonarr:4.0.1-ls1", "Linuxserver.io version:- x", "", "")
	cat, err := catalog.Load(testCatalog, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, image, ociVersion, override, app string) {
		w := ctr("x", image, map[string]string{LabelOCIVer: ociVersion, "build_version": ociVersion},
			map[string]string{LabelVersion: override, LabelApp: app})
		r := Identify(cat, w)
		if r.Version != "" && r.AppID == "" {
			t.Fatalf("version without app: %+v", r)
		}
	})
}
