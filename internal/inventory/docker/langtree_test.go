// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

func tarOf(t *testing.T, files map[string][]byte) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return tar.NewReader(&buf)
}

func jarWith(t *testing.T, pom string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(pom))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The language roots yield the packages apps install, with the file each
// came from; metadata outside site-packages (a source tree) is not an
// installed package.
func TestReadLanguageTree(t *testing.T) {
	tr := tarOf(t, map[string][]byte{
		"lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA": []byte("Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nbody"),
		"lib/python3.12/site-packages/old.egg-info/PKG-INFO":              []byte("Name: PyYAML\nVersion: 5.3\n"),
		"lib/src/project/build/x.dist-info/METADATA":                      []byte("Name: notinstalled\nVersion: 1.0\n"),
		"lib/www/vendor/composer/installed.json":                          []byte(`{"packages":[{"name":"guzzlehttp/guzzle","version":"v7.4.0"}]}`),
		"lib/ruby/gems/3.2.0/specifications/rack-2.2.8.gemspec":           []byte("ignored"),
		"lib/app/App.deps.json":                                           []byte(`{"libraries":{"Newtonsoft.Json/13.0.1":{"type":"package"},"App/1.0.0":{"type":"project"}}}`),
		"lib/app/server.jar":                                              jarWith(t, "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"),
		"lib/app/README.md":                                               []byte("nothing"),
	})
	var got []inventory.Package
	files := 0
	if err := readLanguageTree(tr, "/usr/local", &countingLimit{left: 1 << 30}, &files, &got); err != nil {
		t.Fatal(err)
	}
	have := map[string]string{}
	for _, p := range got {
		have[p.Manager+" "+p.Name+" "+p.Version] = p.Path
	}
	for want, path := range map[string]string{
		"pip requests 2.31.0":                              "/usr/local/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA",
		"pip pyyaml 5.3":                                   "/usr/local/lib/python3.12/site-packages/old.egg-info/PKG-INFO",
		"composer guzzlehttp/guzzle 7.4.0":                 "/usr/local/lib/www/vendor/composer/installed.json",
		"gem rack 2.2.8":                                   "/usr/local/lib/ruby/gems/3.2.0/specifications/rack-2.2.8.gemspec",
		"nuget Newtonsoft.Json 13.0.1":                     "/usr/local/lib/app/App.deps.json",
		"maven org.apache.logging.log4j:log4j-core 2.14.1": "/usr/local/lib/app/server.jar",
	} {
		if have[want] != path {
			t.Errorf("%s from %q, want %q (all: %v)", want, have[want], path, have)
		}
	}
	for k := range have {
		if strings.Contains(k, "notinstalled") {
			t.Error("metadata of a source tree read as an installed package")
		}
	}
}

// A root larger than the byte budget stops the walk; the caller marks the
// read partial instead of treating missing packages as removed.
func TestReadLanguageTreeBound(t *testing.T) {
	tr := tarOf(t, map[string][]byte{
		"lib/big.bin": bytes.Repeat([]byte{0}, 8192),
		"lib/python3.12/site-packages/z-1.0.dist-info/METADATA": []byte("Name: z\nVersion: 1.0\n"),
	})
	var got []inventory.Package
	files := 0
	err := readLanguageTree(tr, "/usr/local", &countingLimit{left: 4096}, &files, &got)
	if !errors.Is(err, errLanguageBound) {
		t.Fatalf("err %v, want the bound", err)
	}
}

func TestLanguageRootsWorkDir(t *testing.T) {
	if !under("/app/server", LanguageRoots) || under("/data", LanguageRoots) || under("/applications", LanguageRoots) {
		t.Error("work directory inside the roots")
	}
}

// A package file too large to read leaves its packages unknown, so the
// read counts as incomplete.
func TestReadLanguageTreeSkipsLarge(t *testing.T) {
	tr := tarOf(t, map[string][]byte{"lib/app/huge.jar": bytes.Repeat([]byte{1}, languageArchiveMax+1)})
	var got []inventory.Package
	files := 0
	limit := &countingLimit{left: 1 << 30}
	if err := readLanguageTree(tr, "/usr/local", limit, &files, &got); err != nil {
		t.Fatal(err)
	}
	if !limit.skipped || len(got) != 0 {
		t.Errorf("skipped %v, packages %v", limit.skipped, got)
	}
}
