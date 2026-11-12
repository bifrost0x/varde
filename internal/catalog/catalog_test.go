// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"strings"
	"testing"
	"testing/fstest"
)

const validEntry = `
id: immich
name: Immich
homepage: https://immich.app
tags: [photos]
images:
  - match: ghcr.io/immich-app/immich-server
oci_source:
  - https://github.com/immich-app/immich
version:
  scheme: semver
  sources:
    - label: org.opencontainers.image.version
    - tag: '^v?(?P<v>\d+\.\d+\.\d+)$'
advisories:
  coverage: full
  github_repos: [immich-app/immich]
  cpe: ['cpe:2.3:a:immich:immich']
exposure_hints:
  default_ports: [2283]
  typical: public
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`

func entry(id, image string) string {
	return strings.NewReplacer("id: immich", "id: "+id, "ghcr.io/immich-app/immich-server", image,
		"https://github.com/immich-app/immich", "https://github.com/x/"+id).Replace(validEntry)
}

func TestParseValid(t *testing.T) {
	app, err := Parse("immich.yaml", []byte(validEntry))
	if err != nil {
		t.Fatal(err)
	}
	if app.ID != "immich" || app.Version.Sources[1].TagRegexp() == nil || app.Images[0].repo != "ghcr.io/immich-app/immich-server" {
		t.Fatalf("parsed: %+v", app)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":    validEntry + "\nsecret_field: 1\n",
		"anchor":           strings.Replace(validEntry, "tags: [photos]", "tags: &t [photos]\naliases: *t", 1),
		"merge key":        strings.Replace(validEntry, "exposure_hints:", "base: &b {typical: lan}\nexposure_hints:\n  <<: *b", 1),
		"two documents":    validEntry + "\n---\nid: other\n",
		"bad id":           strings.Replace(validEntry, "id: immich", "id: Immich!", 1),
		"http homepage":    strings.Replace(validEntry, "https://immich.app", "http://immich.app", 1),
		"wildcard image":   strings.Replace(validEntry, "ghcr.io/immich-app/immich-server", "ghcr.io/immich-app/*", 1),
		"tagged image":     strings.Replace(validEntry, "ghcr.io/immich-app/immich-server", "ghcr.io/immich-app/immich-server:v1", 1),
		"bad flavor":       strings.Replace(validEntry, "- match: ghcr.io/immich-app/immich-server", "- match: ghcr.io/immich-app/immich-server\n    flavor: lsio", 1),
		"oci trailing":     strings.Replace(validEntry, "https://github.com/immich-app/immich", "https://github.com/immich-app/immich/", 1),
		"bad scheme":       strings.Replace(validEntry, "scheme: semver", "scheme: pep440", 1),
		"regex no group":   strings.Replace(validEntry, `(?P<v>\d+\.\d+\.\d+)`, `(\d+\.\d+\.\d+)`, 1),
		"regex unanchored": strings.Replace(validEntry, `'^v?(?P<v>\d+\.\d+\.\d+)$'`, `'v?(?P<v>\d+\.\d+\.\d+)'`, 1),
		"regex invalid":    strings.Replace(validEntry, `'^v?(?P<v>\d+\.\d+\.\d+)$'`, `'^(?P<v>(a$'`, 1),
		"regex backref":    strings.Replace(validEntry, `'^v?(?P<v>\d+\.\d+\.\d+)$'`, `'^(?P<v>a)\1$'`, 1),
		"label and tag":    strings.Replace(validEntry, "- label: org.opencontainers.image.version", "- label: x\n      tag: '^(?P<v>.*)$'", 1),
		"bad normaliser":   strings.Replace(validEntry, "- label: org.opencontainers.image.version", "- label: x\n      normaliser: magic", 1),
		"bad coverage":     strings.Replace(validEntry, "coverage: full", "coverage: great", 1),
		"full no sources":  strings.Replace(validEntry, "github_repos: [immich-app/immich]", "github_repos: []", 1),
		"bad repo":         strings.Replace(validEntry, "[immich-app/immich]", "[https://github.com/immich-app/immich]", 1),
		"bad cpe":          strings.Replace(validEntry, "cpe:2.3:a:immich:immich", "immich", 1),
		"bad port":         strings.Replace(validEntry, "[2283]", "[70000]", 1),
		"bad typical":      strings.Replace(validEntry, "typical: public", "typical: world", 1),
		"no maintainer":    strings.Replace(validEntry, "maintainers_of_entry: [bifrost0x]", "maintainers_of_entry: []", 1),
		"bad date":         strings.Replace(validEntry, "verified: 2026-11-08", "verified: yesterday", 1),
		"probe escapes":    validEntry + "\n" + "",
		"too large":        validEntry + "\n# " + strings.Repeat("x", maxEntryBytes),
	}
	cases["probe escapes"] = strings.Replace(validEntry, "  scheme: semver", "  scheme: semver\n  probe:\n    http:\n      path: http://evil/x", 1)
	for name, doc := range cases {
		if _, err := Parse(name, []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadIndexesAndOverrides(t *testing.T) {
	builtin := fstest.MapFS{
		"immich.yaml":    {Data: []byte(validEntry)},
		"sonarr.yaml":    {Data: []byte(entry("sonarr", "lscr.io/linuxserver/sonarr\n    flavor: lsio"))},
		"README.md":      {Data: []byte("ignored")},
		"sub/jelly.yaml": {Data: []byte(strings.Replace(entry("jellyfin", "jellyfin/jellyfin"), "maintainers_of_entry: [bifrost0x]", "aliases: [jelly]\nmaintainers_of_entry: [bifrost0x]", 1))},
	}
	cat, err := Load(builtin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cat.Len() != 3 {
		t.Fatalf("len %d", cat.Len())
	}
	if a, ok := cat.ByImage("ghcr.io/immich-app/immich-server"); !ok || a.ID != "immich" || a.Origin != OriginBuiltin {
		t.Errorf("ByImage immich: %v %v", a, ok)
	}
	if a, ok := cat.ByImage("docker.io/jellyfin/jellyfin"); !ok || a.ID != "jellyfin" {
		t.Errorf("ByImage normalised docker hub: %v", ok)
	}
	if a, ok := cat.ByImage("lscr.io/linuxserver/sonarr"); !ok || a.ImageFlavor("lscr.io/linuxserver/sonarr") != "lsio" {
		t.Errorf("lsio flavor: %v", ok)
	}
	for _, src := range []string{
		"https://github.com/Immich-App/immich.git",
		"https://github.com/immich-app/immich/",
		"https://github.com/immich-app/immich/tree/0f3c1d2",
		"https://github.com/immich-app/immich/commit/0f3c1d2",
	} {
		if a, ok := cat.ByOCISource(src); !ok || a.ID != "immich" {
			t.Errorf("ByOCISource(%q): %v", src, ok)
		}
	}
	if _, ok := cat.ByOCISource("https://github.com/immich-app/immich-other"); ok {
		t.Error("prefix of another repository matched")
	}
	if a, ok := cat.App("jelly"); !ok || a.ID != "jellyfin" {
		t.Errorf("alias: %v", ok)
	}
	if ids := cat.Apps(); ids[0].ID != "immich" || ids[2].ID != "sonarr" {
		t.Errorf("order: %v %v", ids[0].ID, ids[2].ID)
	}

	local := fstest.MapFS{"immich.yaml": {Data: []byte(strings.Replace(validEntry, "name: Immich", "name: Immich (local)", 1))}}
	cat, err = Load(builtin, local)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := cat.App("immich"); a.Name != "Immich (local)" || a.Origin != OriginLocal {
		t.Errorf("override: %+v", a)
	}
}

func TestLoadRejectsConflicts(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"duplicate image": {
			"a.yaml": {Data: []byte(entry("a", "lscr.io/linuxserver/sonarr"))},
			"b.yaml": {Data: []byte(entry("b", "ghcr.io/linuxserver/sonarr"))},
		},
		"duplicate id": {
			"a.yaml": {Data: []byte(entry("a", "x/a"))},
			"b.yaml": {Data: []byte(entry("a", "x/b"))},
		},
		"duplicate oci source": {
			"a.yaml": {Data: []byte(validEntry)},
			"b.yaml": {Data: []byte(strings.Replace(entry("b", "x/b"), "https://github.com/x/b", "https://github.com/immich-app/immich", 1))},
		},
		"alias is id": {
			"a.yaml": {Data: []byte(entry("a", "x/a"))},
			"b.yaml": {Data: []byte(strings.Replace(entry("b", "x/b"), "maintainers_of_entry", "aliases: [a]\nmaintainers_of_entry", 1))},
		},
		"invalid entry": {
			"a.yaml": {Data: []byte("id: [")},
		},
	}
	for name, fsys := range cases {
		if _, err := Load(fsys, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A local entry must not silently steal an image from another builtin app.
	builtin := fstest.MapFS{"a.yaml": {Data: []byte(entry("a", "x/shared"))}}
	local := fstest.MapFS{"b.yaml": {Data: []byte(entry("b", "x/shared"))}}
	if _, err := Load(builtin, local); err == nil {
		t.Error("local image conflict accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(validEntry))
	f.Add([]byte("id: x\nname: [a, *b]\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Parse("fuzz.yaml", data)
	})
}
