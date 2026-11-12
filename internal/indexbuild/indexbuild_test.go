// SPDX-License-Identifier: Apache-2.0

package indexbuild

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/applists"
)

func TestImagesIn(t *testing.T) {
	readme := "# Tandoor\n\nA recipe manager. It needs a database such as postgres; nginx is optional.\n" +
		"Some people prefer mealie/mealie instead.\n\n" +
		"```bash\ndocker pull vabene1111/recipes:latest\n" +
		"docker run -d --name recipes -p 8080:8080 -v ./data:/data -e SECRET_KEY=x --restart=unless-stopped \\\n  vabene1111/recipes:1.5\n```\n\n" +
		"```yaml\nservices:\n  db:\n    image: postgres:16-alpine\n  cache:\n    image: \"redis:7\"\n  web:\n    image: ghcr.io/TandoorRecipes/recipes:latest@sha256:" + strings.Repeat("a", 64) + "\n" +
		"  proxy:\n    image: nginx\n  builder:\n    build: .\n```\n\n" +
		"FROM python:3.12\n\n    podman run --rm -it quay.io/someorg/tool:2 --help\n\n" +
		"docker run <your-image>\ndocker pull ${REGISTRY}/thing\ndocker run -it\n"
	got := ImagesIn(readme)
	want := []string{"docker.io/vabene1111/recipes", "ghcr.io/tandoorrecipes/recipes", "quay.io/someorg/tool"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("images = %v, want %v", got, want)
	}
	// Bounded.
	var many strings.Builder
	for i := range 50 {
		fmt.Fprintf(&many, "docker pull o/app%d\n", i)
	}
	if n := len(ImagesIn(many.String())); n != maxImagesPerText {
		t.Errorf("%d images from one text, want %d", n, maxImagesPerText)
	}
	if got := ImagesIn(""); len(got) != 0 {
		t.Errorf("empty text: %v", got)
	}
}

func TestLinksRepo(t *testing.T) {
	desc := "Source: https://github.com/TandoorRecipes/recipes.git and docs at http://GitHub.com/tandoorrecipes/recipes/wiki. Also see https://github.com/other/thing/."
	for repo, want := range map[string]bool{
		"github.com/tandoorrecipes/recipes":     true,
		"github.com/other/thing":                true,
		"github.com/tandoorrecipes/recipes-old": false,
		"github.com/tandoorrecipes/other":       false,
		"github.com/someone/recipes":            false,
	} {
		if got := LinksRepo(desc, repo); got != want {
			t.Errorf("LinksRepo(%s) = %v, want %v", repo, got, want)
		}
	}
	if LinksRepo("", "github.com/a/b") {
		t.Error("empty description links a repository")
	}
}

func TestBuild(t *testing.T) {
	ev := []Evidence{
		// Project names the image and the image's page links the project.
		{"docker.io/vabene1111/recipes", "github.com/tandoorrecipes/recipes", KindReadme},
		{"docker.io/vabene1111/recipes", "github.com/tandoorrecipes/recipes", KindHub},
		{"docker.io/vabene1111/recipes", "github.com/tandoorrecipes/recipes", KindHub},
		// Only the project says so.
		{"docker.io/o/reported", "github.com/o/reported", KindReadme},
		// Same owner on GitHub's registry alone is not evidence of the name.
		{"ghcr.io/o/guess", "github.com/o/guess", KindGHCR},
		// With the README it is.
		{"ghcr.io/o/app", "github.com/o/app", KindGHCR},
		{"ghcr.io/o/app", "github.com/o/app", KindReadme},
		// A fork copied the README; the Hub page links the original.
		{"docker.io/orig/tool", "github.com/orig/tool", KindReadme},
		{"docker.io/orig/tool", "github.com/orig/tool", KindHub},
		{"docker.io/orig/tool", "github.com/fork/tool", KindReadme},
		// Two projects name the image and nothing settles it.
		{"docker.io/shared/thing", "github.com/a/thing", KindHub},
		{"docker.io/shared/thing", "github.com/b/thing", KindHub},
		// Never: official and helper images.
		{"docker.io/library/postgres", "github.com/o/app", KindReadme},
		{"docker.io/bitnami/redis", "github.com/o/app", KindReadme},
	}
	tab, dropped := Build(ev)
	type row struct {
		repo      string
		kinds     string
		confirmed bool
	}
	want := map[string]row{
		"docker.io/vabene1111/recipes": {"github.com/tandoorrecipes/recipes", "[hub readme]", true},
		"docker.io/o/reported":         {"github.com/o/reported", "[readme]", false},
		"ghcr.io/o/app":                {"github.com/o/app", "[ghcr readme]", true},
		"docker.io/orig/tool":          {"github.com/orig/tool", "[hub readme]", true},
	}
	if tab.Len() != len(want) {
		t.Errorf("table has %d rows, want %d:\n%s", tab.Len(), len(want), tab.Marshal())
	}
	for image, w := range want {
		e, ok := tab.Lookup(image)
		if !ok || e.Repo != w.repo || fmt.Sprint(e.Lists) != w.kinds || e.Confirmed() != w.confirmed {
			t.Errorf("%s: %+v %v, want %+v", image, e, ok, w)
		}
	}
	for image, reason := range map[string]string{
		"ghcr.io/o/guess":            "registry namespace alone",
		"docker.io/shared/thing":     "several repositories, equal evidence",
		"docker.io/library/postgres": "base or helper image",
		"docker.io/bitnami/redis":    "base or helper image",
	} {
		if dropped[image] != reason {
			t.Errorf("dropped[%s] = %q, want %q", image, dropped[image], reason)
		}
	}

	// Deterministic and readable by the table parser.
	out := tab.Marshal()
	for range 5 {
		shuffled := append([]Evidence{}, ev...)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		again, _ := Build(shuffled)
		if !bytes.Equal(again.Marshal(), out) {
			t.Fatal("not deterministic")
		}
	}
	if _, err := applists.Unmarshal(out); err != nil {
		t.Fatal(err)
	}
}

// What a project's README or Compose file says counts alone only for an
// image in the project's own namespace. Compose files name what a project
// runs beside itself, companion projects name the image they extend, and a
// fork copies the original's README: with a foreign owner the image's own
// page has to link the project.
func TestBuildReadmeAlone(t *testing.T) {
	tab, dropped := Build([]Evidence{
		// Other projects' images in a Compose file.
		{"lscr.io/linuxserver/sabnzbd", "github.com/tristenlammi/arrmada", KindReadme},
		{"docker.io/grafana/tempo", "github.com/rustfs/rustfs", KindReadme},
		// A companion project names the image it extends.
		{"docker.io/headscale/headscale", "github.com/goodieshq/headscale-admin", KindReadme},
		{"docker.io/jc21/nginx-proxy-manager", "github.com/b3nw/nginx-proxy-manager-mcp", KindReadme},
		// A fork with a copied README; the original was not visited.
		{"docker.io/orig/tool", "github.com/fork/tool", KindReadme},
		// The project's own image under another account: only with the Hub link.
		{"docker.io/vabene1111/recipes", "github.com/tandoorrecipes/recipes", KindReadme},
		{"docker.io/deluan/navidrome", "github.com/navidrome/navidrome", KindReadme},
		{"docker.io/deluan/navidrome", "github.com/navidrome/navidrome", KindHub},
		// The same owner: the project's word is enough for a report.
		{"docker.io/gitea/act_runner", "github.com/gitea/runner-images", KindReadme},
		{"docker.io/josh-gaby/relay", "github.com/joshgaby/tor-server", KindReadme},
	})
	for _, image := range []string{"lscr.io/linuxserver/sabnzbd", "docker.io/grafana/tempo", "docker.io/headscale/headscale",
		"docker.io/jc21/nginx-proxy-manager", "docker.io/orig/tool", "docker.io/vabene1111/recipes"} {
		if _, ok := tab.Lookup(image); ok || dropped[image] != "named by another project only" {
			t.Errorf("%s kept (dropped: %q)", image, dropped[image])
		}
	}
	for image, confirmed := range map[string]bool{"docker.io/deluan/navidrome": true, "docker.io/gitea/act_runner": false, "docker.io/josh-gaby/relay": false} {
		if e, ok := tab.Lookup(image); !ok || e.Confirmed() != confirmed {
			t.Errorf("%s: %+v %v (dropped: %q)", image, e, ok, dropped[image])
		}
	}
}

// The owner's namespace on GitHub's registry and the README are one fact,
// not two, for an image that is not named like the repository: a sidecar
// in a Compose file must not alert as the project.
func TestBuildNamespaceConfirmsOnlyTheNamedImage(t *testing.T) {
	tab, _ := Build([]Evidence{
		{"ghcr.io/appwrite/exiftool", "github.com/appwrite/appwrite", KindGHCR},
		{"ghcr.io/appwrite/exiftool", "github.com/appwrite/appwrite", KindReadme},
		{"ghcr.io/matrix-org/synapse-service", "github.com/matrix-org/sliding-sync", KindGHCR},
		{"ghcr.io/matrix-org/synapse-service", "github.com/matrix-org/sliding-sync", KindReadme},
		{"ghcr.io/immich-app/immich-server", "github.com/immich-app/immich", KindGHCR},
		{"ghcr.io/immich-app/immich-server", "github.com/immich-app/immich", KindReadme},
		{"ghcr.io/o/app", "github.com/o/app", KindGHCR},
		{"ghcr.io/o/app", "github.com/o/app", KindReadme},
	})
	for image, want := range map[string]string{
		"ghcr.io/appwrite/exiftool":          "[readme]",
		"ghcr.io/matrix-org/synapse-service": "[readme]",
		"ghcr.io/immich-app/immich-server":   "[ghcr readme]",
		"ghcr.io/o/app":                      "[ghcr readme]",
	} {
		e, ok := tab.Lookup(image)
		if !ok || fmt.Sprint(e.Lists) != want || e.Confirmed() != (want == "[ghcr readme]") {
			t.Errorf("%s: %+v %v, want %s", image, e, ok, want)
		}
	}
}

func TestImagesInLeavesOutPlaceholders(t *testing.T) {
	text := "docker pull ghcr.io/owner/ratatoskr\ndocker pull my/claudeclaw-plus\ndocker pull ghcr.io/yourusername/gift\n" +
		"docker pull example/app\ndocker pull localhost:5000/app\ndocker pull username/app\ndocker pull o/real\r\n" +
		"docker run -d \\\r\n  --name x \\\r\n  o/crlf:1\r\n"
	if got := ImagesIn(text); fmt.Sprint(got) != "[docker.io/o/real docker.io/o/crlf]" {
		t.Errorf("images = %v", got)
	}
}

// The guard stops a partial run from replacing a good table.
func TestGuard(t *testing.T) {
	ok := Stats{Requests: 1000, Failed: 10, RateLimited: 20}
	if err := Guard(ok, 2000, 1950); err != nil {
		t.Errorf("healthy run refused: %v", err)
	}
	if err := Guard(Stats{Requests: 1000, Failed: 40, RateLimited: 40}, 2000, 2000); err == nil {
		t.Error("a run with 8 % failed requests accepted")
	}
	if err := Guard(ok, 2000, 1700); err == nil {
		t.Error("a table that lost 15 % of its rows accepted")
	}
	if err := Guard(ok, 0, 10); err != nil {
		t.Errorf("first table refused: %v", err)
	}
	if err := Guard(Stats{}, 2000, 2000); err == nil {
		t.Error("a run without any request accepted")
	}
}
