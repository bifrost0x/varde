// SPDX-License-Identifier: Apache-2.0

package catalogdata

import (
	"testing"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
)

// TestSeedCatalog validates every built-in entry with the production loader.
func TestSeedCatalog(t *testing.T) {
	cat, err := catalog.Load(FS(), nil)
	if err != nil {
		t.Fatalf("seed catalog invalid:\n%v", err)
	}
	if cat.Len() < 30 {
		t.Fatalf("seed catalog has %d entries, expected at least 30", cat.Len())
	}
	for _, a := range cat.Apps() {
		if a.Origin != catalog.OriginBuiltin {
			t.Errorf("%s: origin %s", a.ID, a.Origin)
		}
	}
}

// TestSeedIdentification pins well-known references to their apps so that
// catalog edits cannot silently break identification.
func TestSeedIdentification(t *testing.T) {
	cat, err := catalog.Load(FS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		image, app, version string
		labels              map[string]string
	}{
		{"ghcr.io/immich-app/immich-server:v1.120.0", "immich", "1.120.0", nil},
		{"vaultwarden/server:1.32.5", "vaultwarden", "1.32.5", nil},
		{"jellyfin/jellyfin:10.10.3", "jellyfin", "10.10.3", nil},
		{"ghcr.io/home-assistant/home-assistant:2026.11.1", "home-assistant", "2026.11.1", nil},
		{"lscr.io/linuxserver/sonarr:4.0.11.2680-ls262", "sonarr", "4.0.11.2680", nil},
		{"ghcr.io/homarr-labs/homarr:v2.10.1", "homarr", "2.10.1", map[string]string{identify.LabelOCIVer: "main"}},
		{"jc21/nginx-proxy-manager:2.12.1", "nginx-proxy-manager", "2.12.1", nil},
		{"eclipse-mosquitto:2.0.20", "mosquitto", "2.0.20", nil},
		{"nextcloud:30.0.2", "nextcloud", "30.0.2", nil},
		{"traefik:v3.2.1", "traefik", "3.2.1", nil},
		{"ghcr.io/immich-app/immich-server:release", "immich", "", nil},
		{"lscr.io/linuxserver/jellyfin:12.4ubu2604-ls58", "jellyfin", "12.4", nil},
		{"jellyfin/jellyfin:unstable", "jellyfin", "", map[string]string{identify.LabelOCIVer: "2026110213"}},
		{"pihole/pihole:2026.04.1", "pi-hole", "2026.4.1", nil},
		{"portainer/portainer-ee:2.45.0", "portainer-ee", "2.45.0", nil},
		// Databases are apps: a full version tag is read, with or without
		// an image variant; a tag that only names a release line is not
		// taken for a version.
		{"postgres:16.4-alpine", "postgresql", "16.4", nil},
		{"docker.io/library/postgres:16.4", "postgresql", "16.4", nil},
		{"postgres:16-alpine", "postgresql", "", nil},
		{"postgres:16", "postgresql", "", nil},
		{"redis:7.4.1-alpine", "redis", "7.4.1", nil},
		{"redis:7-alpine", "redis", "", nil},
		{"docker.io/valkey/valkey:8.0.1-bookworm", "valkey", "8.0.1", nil},
		{"valkey/valkey:8-bookworm", "valkey", "", nil},
		{"mariadb:11.4.3", "mariadb", "11.4.3", nil},
		{"mysql:8.4.3-oraclelinux9", "mysql", "8.4.3", nil},
		{"mongo:8.0.3-noble", "mongodb", "8.0.3", nil},
		{"memcached:1.6.31-alpine", "memcached", "1.6.31", nil},
		{"mpepping/cyberchef:v10.19.4", "cyberchef", "10.19.4", nil},
		{"mpepping/cyberchef:latest", "cyberchef", "", nil},
		// A pre-release is not the release: its suffix is no image variant,
		// so the tag is not taken for the stable version.
		{"mongo:8.0.0-rc1", "mongodb", "", nil},
		{"redis:8.0-m03-alpine", "redis", "", nil},
		{"postgres:17.0-beta1", "postgresql", "", nil},
		{"redis:7.4.1-alpine3.20", "redis", "7.4.1", nil},
		{"mysql:8.4.3-oracle", "mysql", "8.4.3", nil},
	}
	for _, c := range cases {
		w := inventory.Workload{Kind: inventory.KindContainer, Name: c.app, Container: &inventory.Container{ImageRef: c.image, ImageLabels: c.labels}}
		r := identify.Identify(cat, w)
		if r.AppID != c.app || r.Version != c.version || r.Confidence != identify.Exact {
			t.Errorf("%s: app=%q version=%q conf=%s note=%q; want %s %q", c.image, r.AppID, r.Version, r.Confidence, r.Note, c.app, c.version)
		}
	}
}
