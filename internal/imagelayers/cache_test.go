// SPDX-License-Identifier: Apache-2.0

package imagelayers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/registry"
)

// memCache keeps records as JSON, as a store would.
type memCache struct {
	recs map[string][]byte
	puts int
}

func (m *memCache) Layer(_ context.Context, key string) (*LayerRecord, error) {
	b, ok := m.recs[key]
	if !ok {
		return nil, nil
	}
	var rec LayerRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (m *memCache) PutLayer(_ context.Context, key string, rec *LayerRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	m.recs[key] = b
	m.puts++
	return nil
}

// snapshot describes everything a view holds.
func snapshot(v *View) string {
	var lines []string
	for p, n := range v.files {
		perr := ""
		if n.progErr != nil {
			perr = n.progErr.Error()
		}
		prog, _ := json.Marshal(n.prog)
		lines = append(lines, fmt.Sprintf("%s use=%d link=%v:%q size=%d large=%v data=%q prog=%s err=%q layer=%d",
			p, n.use, n.isLink, n.link, n.size, n.tooLarge, n.data, prog, perr, n.layer))
	}
	sort.Strings(lines)
	return fmt.Sprintf("partial=%v kept=%d inserts=%d\n%s", v.Partial(), v.kept, v.inserts, strings.Join(lines, "\n"))
}

// A view rebuilt from layer records is the view read from the blobs, and
// the rebuild opens no blob.
func TestCacheReplaysLayers(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	bin, err := os.ReadFile(exe) //nolint:gosec // the running test binary
	if err != nil {
		t.Skip(err)
	}
	status2 := statusFile + "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u4\n\n"
	cases := map[string]struct {
		cfg    docker.ImageConfig
		lim    Limits
		layers [][]entry
	}{
		"whiteouts": {layers: [][]entry{
			{dir("var/"), dir("var/lib/dpkg/"), file("var/lib/dpkg/status", statusFile), file("lib/apk/db/installed", "P:musl\nV:1\n"), file("usr/share/doc/x", "unread")},
			{file("var/lib/dpkg/.wh.status", ""), file("lib/apk/.wh.db", "")},
			{file("var/lib/dpkg/status", status2)},
		}},
		"opaque and replaced dir": {layers: [][]entry{
			{file("var/lib/dpkg/status.d/bash", statusFile), file("var/lib/dpkg/status.d/libc", statusFile)},
			{dir("var/lib/dpkg/status.d/"), file("var/lib/dpkg/status.d/.wh..wh..opq", ""), file("var/lib/dpkg/status.d/zlib", statusFile)},
			{file("etc/os-release", "ID=debian\n"), dir("etc/os-release")},
		}},
		"symlinks and hard links": {layers: [][]entry{
			{symlink("lib", "usr/lib"), file("usr/lib/apk/db/installed", "P:old\n"), symlink("etc/os-release", "../usr/lib/os-release"), file("usr/lib/os-release", "ID=alpine\n")},
			{file("lib/apk/db/installed", "P:musl\n"), hardlink("etc/alt-release", "usr/lib/os-release"), hardlink("usr/lib/os-release2", "etc/os-release")},
		}},
		"programs": {cfg: docker.ImageConfig{Entrypoint: []string{"/bin/app"}, WorkingDir: "/app"}, layers: [][]entry{
			{file("usr/local/bin/gosu", string(bin)), file("usr/local/bin/docker-entrypoint.sh", strings.Repeat("#", 2048)), file("usr/bin/app", string(bin))},
			{symlink("bin", "usr/bin"), file("app/package.json", `{"name":"web","version":"1.2.3"}`)},
		}},
		"kept bytes": {lim: Limits{KeptBytes: 100}, layers: [][]entry{
			{file("var/lib/dpkg/status", statusFile), file("etc/os-release", strings.Repeat("y", 90))},
		}},
		"files": {lim: Limits{Files: 2}, layers: [][]entry{
			{file("var/lib/dpkg/status", statusFile), file("etc/os-release", "ID=debian\n"), file("lib/apk/db/installed", "P:musl\n")},
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			img := newImage(t, gzipType, tc.layers...)
			want := snapshot(build(t, img, tc.cfg, tc.lim))
			cache := &memCache{recs: map[string][]byte{}}
			v, err := BuildCached(t.Context(), img.layers, img.open, tc.cfg, tc.lim, cache)
			if err != nil {
				t.Fatal(err)
			}
			if got := snapshot(v); got != want {
				t.Fatalf("recording build:\n%s\nwant\n%s", got, want)
			}
			if cache.puts != len(img.layers) {
				t.Fatalf("%d records for %d layers", cache.puts, len(img.layers))
			}
			noBlob := func(context.Context, registry.Layer) (io.ReadCloser, error) {
				return nil, errors.New("blob opened")
			}
			v, err = BuildCached(t.Context(), img.layers, noBlob, tc.cfg, tc.lim, cache)
			if err != nil {
				t.Fatal(err)
			}
			if got := snapshot(v); got != want {
				t.Fatalf("replayed:\n%s\nwant\n%s", got, want)
			}
			a, errA := docker.ReadPackages(t.Context(), build(t, img, tc.cfg, tc.lim).Source(), tc.cfg)
			b, errB := docker.ReadPackages(t.Context(), v.Source(), tc.cfg)
			ja, _ := json.Marshal(a)
			jb, _ := json.Marshal(b)
			if string(ja) != string(jb) || fmt.Sprint(errA) != fmt.Sprint(errB) {
				t.Fatalf("packages from the replayed view:\n%s %v\nwant\n%s %v", jb, errB, ja, errA)
			}
		})
	}
}

// A layer cut by the layer byte limit is not recorded: its record would
// claim a read the next build can complete.
func TestCacheSkipsCutLayer(t *testing.T) {
	img := newImage(t, gzipType,
		[]entry{file("etc/os-release", "ID=debian\n")},
		[]entry{file("usr/share/doc/big", strings.Repeat("x", 64<<10))},
	)
	cache := &memCache{recs: map[string][]byte{}}
	lim := Limits{LayerBytes: 32 << 10}
	v, err := BuildCached(t.Context(), img.layers, img.open, docker.ImageConfig{}, lim, cache)
	if err != nil || !v.Partial() {
		t.Fatalf("partial %v, %v", v != nil && v.Partial(), err)
	}
	if cache.puts != 1 {
		t.Fatalf("%d records, want the first layer's only", cache.puts)
	}
	var opened []string
	open := func(ctx context.Context, l registry.Layer) (io.ReadCloser, error) {
		opened = append(opened, l.Digest)
		return img.open(ctx, l)
	}
	v, err = BuildCached(t.Context(), img.layers, open, docker.ImageConfig{}, lim, cache)
	if err != nil || !v.Partial() || len(opened) != 1 || opened[0] != img.layers[1].Digest {
		t.Fatalf("second build: partial %v opened %v, %v", v != nil && v.Partial(), opened, err)
	}
	if got, err := readFile(t, v, "/etc/os-release"); err != nil || got != "ID=debian\n" {
		t.Fatalf("os-release = %q, %v", got, err)
	}
}

// The key of a layer changes with the layers below it, the configuration
// and the limits: a record is replayed only onto the view it was made on.
func TestLayerKeys(t *testing.T) {
	a := registry.Layer{Digest: "sha256:" + strings.Repeat("a", 64), MediaType: gzipType}
	b := registry.Layer{Digest: "sha256:" + strings.Repeat("b", 64), MediaType: gzipType}
	c := registry.Layer{Digest: "sha256:" + strings.Repeat("c", 64), MediaType: gzipType}
	base := LayerKeys([]registry.Layer{a, b}, docker.ImageConfig{}, Limits{})
	if base[0] == base[1] {
		t.Fatal("two layers share a key")
	}
	if again := LayerKeys([]registry.Layer{a, b, c}, docker.ImageConfig{}, Limits{}); again[0] != base[0] || again[1] != base[1] {
		t.Fatal("a layer above changed the keys below it")
	}
	if other := LayerKeys([]registry.Layer{c, b}, docker.ImageConfig{}, Limits{}); other[1] == base[1] {
		t.Fatal("a layer on another base kept its key")
	}
	if other := LayerKeys([]registry.Layer{a, b}, docker.ImageConfig{Entrypoint: []string{"/app"}}, Limits{}); other[0] == base[0] {
		t.Fatal("another configuration kept the key")
	}
	if other := LayerKeys([]registry.Layer{a, b}, docker.ImageConfig{Labels: map[string]string{"x": "y"}}, Limits{}); other[0] != base[0] {
		t.Fatal("a label the reader does not use changed the key")
	}
	if other := LayerKeys([]registry.Layer{a, b}, docker.ImageConfig{}, Limits{Files: 3}); other[0] == base[0] {
		t.Fatal("other limits kept the key")
	}
}
