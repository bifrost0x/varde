// SPDX-License-Identifier: Apache-2.0

package applists

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func TestNormaliseImage(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                     "docker.io/library/nginx",
		"linuxserver/sonarr:latest": "lscr.io/linuxserver/sonarr",
		"docker.io/library/redis:7": "docker.io/library/redis",
		"index.docker.io/foo/bar":   "docker.io/foo/bar",
		"ghcr.io/Immich-App/immich-server@sha256:" + strings.Repeat("a", 64):    "ghcr.io/immich-app/immich-server",
		"ghcr.io/immich-app/immich-server:v3@sha256:" + strings.Repeat("a", 64): "ghcr.io/immich-app/immich-server",
		"registry.lan:5000/immich":   "registry.lan:5000/immich",
		"registry.lan:5000/immich:1": "registry.lan:5000/immich",
	} {
		if got, ok := NormaliseImage(in); !ok || got != want {
			t.Errorf("NormaliseImage(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	// Surrounding whitespace is trimmed.
	if got, ok := NormaliseImage(" lscr.io/linuxserver/plex\n"); !ok || got != "lscr.io/linuxserver/plex" {
		t.Errorf("padded reference: %q, %v", got, ok)
	}
	for _, in := range []string{"", "  ", "a b", "${IMAGE}", "https://raw.githubusercontent.com/x/y/z.plg", "foo/", "/foo", "a//b", strings.Repeat("a", 300)} {
		if got, ok := NormaliseImage(in); ok {
			t.Errorf("NormaliseImage(%q) accepted as %q", in, got)
		}
	}
}

func TestParseUnraid(t *testing.T) {
	f, err := os.Open("testdata/unraid.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	pairs, err := ParseUnraid(f)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pairs {
		if p.List != "unraid" {
			t.Errorf("list = %q", p.List)
		}
		got[p.Image] = p.Repo
	}
	want := map[string]string{
		"docker.io/vabene1111/recipes": "github.com/tandoorrecipes/recipes",
		"ghcr.io/homarr-labs/homarr":   "github.com/homarr-labs/homarr",
		"docker.io/library/postgres":   "github.com/drytrix/timetracker",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("pairs = %v, want %v", got, want)
	}

	if _, err := ParseUnraid(strings.NewReader(`{"applist":[{"Repository":"a/b","Project":"https://github.com/a/b"}`)); err == nil {
		t.Error("truncated list accepted")
	}
	if _, err := ParseUnraid(strings.NewReader(`<html>not found</html>`)); err == nil {
		t.Error("HTML accepted")
	}
	if _, err := ParseUnraid(strings.NewReader(`{"apps":1}`)); err == nil {
		t.Error("list without applist accepted")
	}
	var big strings.Builder
	big.WriteString(`{"applist":[`)
	for i := range maxApps + 1 {
		if i > 0 {
			big.WriteByte(',')
		}
		fmt.Fprintf(&big, `{"Repository":"o/i%d","Project":"https://github.com/o/i%d"}`, i, i)
	}
	big.WriteString(`]}`)
	if _, err := ParseUnraid(strings.NewReader(big.String())); err == nil {
		t.Error("list with too many apps accepted")
	}
}

// umbrelArchive builds a gzip tar like GitHub's archive of the repository.
func umbrelArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "umbrel-apps-master/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseUmbrel(t *testing.T) {
	data := umbrelArchive(t, map[string]string{
		"README.md":                      "apps",
		"immich/umbrel-app.yml":          "manifestVersion: 1\nid: immich\nrepo: https://github.com/immich-app/immich\nsupport: https://x\n",
		"immich/docker-compose.yml":      "services:\n  app_proxy:\n    environment:\n      APP_HOST: x\n  server:\n    image: ghcr.io/immich-app/immich-server:v3.3.6@sha256:" + strings.Repeat("b", 64) + "\n  redis:\n    image: redis:7\n  db:\n    image: \"postgres:16\"\n",
		"two/umbrel-app.yml":             "id: two\nrepo: https://github.com/o/two\n",
		"two/docker-compose.yml":         "services:\n  a:\n    image: o/two-web:1\n  b:\n    image: o/two-worker:1\n",
		"norepo/umbrel-app.yml":          "id: norepo\nrepo: \"\"\n",
		"norepo/docker-compose.yml":      "services:\n  a:\n    image: o/norepo:1\n",
		"deep/sub/umbrel-app.yml":        "id: deep\nrepo: https://github.com/o/deep\n",
		"deep/sub/docker-compose.yml":    "services:\n  a:\n    image: o/deep:1\n",
		"recipes/umbrel-app.yml":         "id: recipes\nrepo: https://github.com/TandoorRecipes/recipes.git\n",
		"recipes/docker-compose.yml":     "services:\n  web:\n    image: vabene1111/recipes:1.5\n",
		"composeonly/docker-compose.yml": "services:\n  a:\n    image: o/composeonly:1\n",
	})
	pairs, err := ParseUmbrel(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pairs {
		if p.List != "umbrel" {
			t.Errorf("list = %q", p.List)
		}
		got[p.Image] = p.Repo
	}
	want := map[string]string{
		"ghcr.io/immich-app/immich-server": "github.com/immich-app/immich",
		"docker.io/vabene1111/recipes":     "github.com/tandoorrecipes/recipes",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("pairs = %v, want %v", got, want)
	}

	if _, err := ParseUmbrel(strings.NewReader("<html>")); err == nil {
		t.Error("HTML accepted as archive")
	}
	if _, err := ParseUmbrel(bytes.NewReader(data[:len(data)/2])); err == nil {
		t.Error("truncated archive accepted")
	}
	huge := umbrelArchive(t, map[string]string{"big/umbrel-app.yml": "repo: https://github.com/o/big\n" + strings.Repeat("#", maxMember+1)})
	if _, err := ParseUmbrel(bytes.NewReader(huge)); err == nil {
		t.Error("oversized member accepted")
	}
}

func TestBuild(t *testing.T) {
	pairs := []Pair{
		// A shared base image listed beside three projects.
		{"docker.io/library/postgres", "github.com/drytrix/timetracker", "unraid"},
		{"docker.io/library/postgres", "github.com/nightscout/nocturne", "unraid"},
		{"docker.io/library/postgres", "github.com/docker-library/postgres", "unraid"},
		// An official image with one project is still a base image.
		{"docker.io/library/caddy", "github.com/someone/caddy-template", "unraid"},
		// Ambiguous inside one list, although another list is clear.
		{"docker.io/o/shared", "github.com/a/one", "unraid"},
		{"docker.io/o/shared", "github.com/b/two", "unraid"},
		{"docker.io/o/shared", "github.com/a/one", "umbrel"},
		// Lists disagree and neither repository matches the image path.
		{"docker.io/vabene1111/recipes", "github.com/vabene1111/recipes-old", "unraid"},
		{"docker.io/vabene1111/recipes", "github.com/tandoorrecipes/recipes", "umbrel"},
		// Lists disagree on GitHub's registry; one repository is the image
		// path (a renamed project).
		{"ghcr.io/oauth2-proxy/oauth2-proxy", "github.com/pusher/oauth2_proxy", "unraid"},
		{"ghcr.io/oauth2-proxy/oauth2-proxy", "github.com/oauth2-proxy/oauth2-proxy", "umbrel"},
		// Agreement.
		{"ghcr.io/immich-app/immich-server", "github.com/immich-app/immich", "umbrel"},
		{"ghcr.io/immich-app/immich-server", "github.com/immich-app/immich", "unraid"},
		{"ghcr.io/immich-app/immich-server", "github.com/immich-app/immich", "unraid"},
		// One list.
		{"lscr.io/linuxserver/sonarr", "github.com/sonarr/sonarr", "unraid"},
	}
	tab, dropped := Build(pairs)
	if tab.Len() != 3 {
		t.Fatalf("table has %d entries: %s", tab.Len(), tab.Marshal())
	}
	for img, reason := range map[string]string{
		"docker.io/library/postgres":   "base image",
		"docker.io/library/caddy":      "base image",
		"docker.io/o/shared":           "ambiguous in unraid",
		"docker.io/vabene1111/recipes": "lists disagree",
	} {
		if dropped[img] != reason {
			t.Errorf("dropped[%s] = %q, want %q", img, dropped[img], reason)
		}
		if _, ok := tab.Lookup(img); ok {
			t.Errorf("%s is in the table", img)
		}
	}
	e, ok := tab.Lookup("ghcr.io/oauth2-proxy/oauth2-proxy")
	if !ok || e.Repo != "github.com/oauth2-proxy/oauth2-proxy" || fmt.Sprint(e.Lists) != "[umbrel]" || e.Confirmed() {
		t.Errorf("renamed project: %+v %v", e, ok)
	}
	e, ok = tab.Lookup("ghcr.io/immich-app/immich-server")
	if !ok || e.Repo != "github.com/immich-app/immich" || fmt.Sprint(e.Lists) != "[umbrel unraid]" || !e.Confirmed() {
		t.Errorf("agreement: %+v %v", e, ok)
	}
	e, ok = tab.Lookup("lscr.io/linuxserver/sonarr")
	if !ok || e.Confirmed() || fmt.Sprint(e.Lists) != "[unraid]" {
		t.Errorf("one list: %+v %v", e, ok)
	}
	// The registry host is part of the key.
	for _, miss := range []string{"registry.lan/immich-app/immich-server", "immich-app/immich-server", "docker.io/immich-app/immich-server", "ghcr.io/immich-app/immich"} {
		if _, ok := tab.Lookup(miss); ok {
			t.Errorf("%s matched", miss)
		}
	}
	var none *Table
	if _, ok := none.Lookup("ghcr.io/immich-app/immich-server"); ok || none.Len() != 0 {
		t.Error("nil table matched")
	}

	// Deterministic, and it round-trips.
	want := tab.Marshal()
	for range 5 {
		shuffled := append([]Pair{}, pairs...)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		again, _ := Build(shuffled)
		if !bytes.Equal(again.Marshal(), want) {
			t.Fatalf("not deterministic:\n%s\nvs\n%s", again.Marshal(), want)
		}
	}
	back, err := Unmarshal(want)
	if err != nil || !bytes.Equal(back.Marshal(), want) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestUnmarshalRejects(t *testing.T) {
	good := "docker.io/a/b\tgithub.com/a/b\tunraid\ndocker.io/c/d\tgithub.com/c/d\tumbrel,unraid\n"
	if tab, err := Unmarshal([]byte(good)); err != nil || tab.Len() != 2 {
		t.Fatalf("good table: %v", err)
	}
	if tab, err := Unmarshal(nil); err != nil || tab.Len() != 0 {
		t.Fatalf("empty table: %v", err)
	}
	for name, bad := range map[string]string{
		"unsorted":      "docker.io/c/d\tgithub.com/c/d\tunraid\ndocker.io/a/b\tgithub.com/a/b\tunraid\n",
		"duplicate":     "docker.io/a/b\tgithub.com/a/b\tunraid\ndocker.io/a/b\tgithub.com/a/b\tunraid\n",
		"two fields":    "docker.io/a/b\tgithub.com/a/b\n",
		"bad repo":      "docker.io/a/b\thttps://evil.example/a/b\tunraid\n",
		"bad image":     "A B\tgithub.com/a/b\tunraid\n",
		"empty list":    "docker.io/a/b\tgithub.com/a/b\t\n",
		"unsorted list": "docker.io/a/b\tgithub.com/a/b\tunraid,umbrel\n",
		"no newline":    "docker.io/a/b\tgithub.com/a/b\tunraid",
	} {
		if _, err := Unmarshal([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Review findings on what a list may state.
func TestListsDoNotNameTemplateRepositories(t *testing.T) {
	// "GitHub" is often the template's own repository: it counts only when
	// it is named like the image.
	pairs, err := ParseUnraid(strings.NewReader(`{"applist":[
		{"Repository":"apache/nifi","GitHub":"https://github.com/DanRegalia/NIFI-Unraid"},
		{"Repository":"ghcr.io/o/tool","GitHub":"https://github.com/o/tool"},
		{"Repository":"o/thing","Project":"https://github.com/o/thing.git.git"},
		{"Repository":"o/org","Project":"https://github.com/orgs/someone"},
		{"Repository":"o/dots","Project":"https://github.com/o/.."}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 || pairs[0].Image != "ghcr.io/o/tool" || pairs[0].Repo != "github.com/o/tool" {
		t.Errorf("pairs = %+v", pairs)
	}
}

func TestBuildDropsHelpersAndGuardsTiebreak(t *testing.T) {
	tab, dropped := Build([]Pair{
		// A database beside a project, outside docker.io/library.
		{"ghcr.io/immich-app/postgres", "github.com/postgres/postgres", "unraid"},
		{"docker.io/bitnami/redis", "github.com/o/app", "unraid"},
		// Docker Hub namespaces are not GitHub owners: no tiebreak there.
		{"docker.io/foo/app", "github.com/foo/app", "unraid"},
		{"docker.io/foo/app", "github.com/bar/app", "umbrel"},
		// On GitHub's registry the namespace is the owner's.
		{"ghcr.io/foo/app", "github.com/foo/app", "unraid"},
		{"ghcr.io/foo/app", "github.com/bar/app", "umbrel"},
	})
	for _, img := range []string{"ghcr.io/immich-app/postgres", "docker.io/bitnami/redis", "docker.io/foo/app"} {
		if _, ok := tab.Lookup(img); ok || dropped[img] == "" {
			t.Errorf("%s kept (dropped: %q)", img, dropped[img])
		}
	}
	if e, ok := tab.Lookup("ghcr.io/foo/app"); !ok || e.Repo != "github.com/foo/app" || e.Confirmed() {
		t.Errorf("ghcr tiebreak: %+v %v", e, ok)
	}
}

// The archive is bounded as a whole, not only per file.
func TestParseUmbrelTotalSize(t *testing.T) {
	files := map[string]string{}
	filler := strings.Repeat("#", maxMember-64)
	for i := range maxArchive/maxMember + 2 {
		files[fmt.Sprintf("app%d/docker-compose.yml", i)] = "services:\n  a:\n    image: o/app" + fmt.Sprint(i) + ":1\n" + filler
	}
	if _, err := ParseUmbrel(bytes.NewReader(umbrelArchive(t, files))); err == nil {
		t.Error("archive over the total size limit accepted")
	}
}
