// SPDX-License-Identifier: Apache-2.0

package imageref

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	cases := []struct{ in, repo, tag, digest string }{
		{"nginx", "docker.io/library/nginx", "", ""},
		{"nginx:1.27", "docker.io/library/nginx", "1.27", ""},
		{"library/nginx:latest", "docker.io/library/nginx", "latest", ""},
		{"docker.io/jellyfin/jellyfin:10.10.3", "docker.io/jellyfin/jellyfin", "10.10.3", ""},
		{"index.docker.io/vaultwarden/server", "docker.io/vaultwarden/server", "", ""},
		{"Vaultwarden/Server:1.32.0", "docker.io/vaultwarden/server", "1.32.0", ""},
		{"ghcr.io/immich-app/immich-server:v1.120.0@" + d, "ghcr.io/immich-app/immich-server", "v1.120.0", d},
		{"ghcr.io/immich-app/immich-server@" + d, "ghcr.io/immich-app/immich-server", "", d},
		{"registry.local:5000/team/app:2", "registry.local:5000/team/app", "2", ""},
		{"localhost/app", "localhost/app", "", ""},
		{"lscr.io/linuxserver/sonarr:4.0.11.2680-ls262", "lscr.io/linuxserver/sonarr", "4.0.11.2680-ls262", ""},
		{"ghcr.io/linuxserver/sonarr:latest", "lscr.io/linuxserver/sonarr", "latest", ""},
		{"linuxserver/sonarr", "lscr.io/linuxserver/sonarr", "", ""},
	}
	for _, c := range cases {
		r, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if r.Repository != c.repo || r.Tag != c.tag || r.Digest != c.digest {
			t.Errorf("Parse(%q) = %+v", c.in, r)
		}
	}
	if !IsLSIO("lscr.io/linuxserver/radarr") || IsLSIO("docker.io/library/nginx") {
		t.Error("IsLSIO")
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{
		"", ":tag", "app:", "app@sha256:xyz", "app@" + strings.Repeat("a", 64), "a//b", "-app", "app_",
		"ghcr.io/", "app:-x", "app:ta g", "app name", strings.Repeat("a", 600), "../etc/passwd", "a/../b",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"nginx", "ghcr.io/a/b:c@sha256:" + strings.Repeat("0", 64), "host:5000/x", "linuxserver/x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Parse(s)
		if err != nil {
			return
		}
		// A normalised repository is a fixed point.
		again, err := NormaliseRepository(r.Repository)
		if err != nil || again != r.Repository {
			t.Fatalf("normalisation of %q not idempotent: %q -> %q (%v)", s, r.Repository, again, err)
		}
	})
}
