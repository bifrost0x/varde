// SPDX-License-Identifier: Apache-2.0

package imagelayers

import (
	"bytes"
	"compress/gzip"
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
		"names that are not UTF-8": {layers: [][]entry{
			{file("var/lib/dpkg/status.d/\xff\xfe", statusFile), symlink("etc/os-release", "../usr/lib/os-\xffrelease"), file("usr/lib/os-\xffrelease", "ID=debian\n")},
			{file("var/lib/dpkg/status.d/.wh.\xff\xfe", "")},
		}},
		// Under the config of the case nothing reads /app, so the file
		// that replaces the directory is kept by name only; a config
		// that reads /app must still see the directory go.
		"file replaces a directory another config reads": {layers: [][]entry{
			{dir("app/"), file("app/package.json", `{"name":"web","version":"1.2.3"}`), file("app/README", "x")},
			{file("app", "now a file")},
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
			// Under every other config the records give the view read
			// from the blobs, reading a layer again only for content
			// they lack.
			for _, other := range otherConfigs {
				want := snapshot(build(t, img, other, tc.lim))
				v, err := BuildCached(t.Context(), img.layers, img.open, other, tc.lim, cache)
				if err != nil {
					t.Fatal(err)
				}
				if got := snapshot(v); got != want {
					t.Fatalf("config %+v from records:\n%s\nwant\n%s", other, got, want)
				}
			}
		})
	}
}

// otherConfigs read other programs and working directories.
var otherConfigs = []docker.ImageConfig{
	{},
	{Entrypoint: []string{"/bin/app"}, WorkingDir: "/app"},
	{Cmd: []string{"gosu"}, WorkingDir: "/srv/web"},
	{WorkingDir: "/var/lib"},
}

// Records are shared by images on the same base whatever their config: a
// config that reads nothing more of a layer replays it without its blob;
// one that reads a file the record lacks reads the layer once and adds
// the file, after which neither config needs the blob.
func TestCacheSharedAcrossConfigs(t *testing.T) {
	img := newImage(t, gzipType,
		[]entry{file("etc/os-release", "ID=debian\n"), file("var/lib/dpkg/status", statusFile)},
		[]entry{file("app/package.json", `{"name":"web","version":"1.2.3"}`)},
	)
	a := docker.ImageConfig{Cmd: []string{"nginx"}}
	b := docker.ImageConfig{Cmd: []string{"node"}, WorkingDir: "/srv"}
	c := docker.ImageConfig{WorkingDir: "/app"}
	cache := &memCache{recs: map[string][]byte{}}
	var opened []string
	open := func(ctx context.Context, l registry.Layer) (io.ReadCloser, error) {
		opened = append(opened, l.Digest)
		return img.open(ctx, l)
	}
	for _, step := range []struct {
		cfg  docker.ImageConfig
		want int
	}{{a, 2}, {b, 0}, {c, 1}, {c, 0}, {a, 0}, {b, 0}} {
		opened = nil
		v, err := BuildCached(t.Context(), img.layers, open, step.cfg, Limits{}, cache)
		if err != nil {
			t.Fatal(err)
		}
		if len(opened) != step.want {
			t.Fatalf("config %+v opened %d layers, want %d", step.cfg, len(opened), step.want)
		}
		if got, want := snapshot(v), snapshot(build(t, img, step.cfg, Limits{})); got != want {
			t.Fatalf("config %+v:\n%s\nwant\n%s", step.cfg, got, want)
		}
	}
	if len(cache.recs) != 2 {
		t.Fatalf("%d records for 2 layers", len(cache.recs))
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

// The key of a layer changes with the layers below it and the limits,
// not with the config. Fields are hashed unambiguously: a media type that
// smuggles a second layer in cannot reproduce another chain's key, and
// such a layer is refused.
func TestLayerKeys(t *testing.T) {
	d := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	a := registry.Layer{Digest: d("a"), MediaType: gzipType}
	b := registry.Layer{Digest: d("b"), MediaType: gzipType}
	c := registry.Layer{Digest: d("c"), MediaType: gzipType}
	keys := func(ls ...registry.Layer) []string {
		t.Helper()
		k, err := LayerKeys(ls, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	base := keys(a, b)
	if base[0] == base[1] {
		t.Fatal("two layers share a key")
	}
	if again := keys(a, b, c); again[0] != base[0] || again[1] != base[1] {
		t.Fatal("a layer above changed the keys below it")
	}
	if other := keys(c, b); other[1] == base[1] {
		t.Fatal("a layer on another base kept its key")
	}
	if other, _ := LayerKeys([]registry.Layer{a, b}, Limits{Files: 3}); other[0] == base[0] {
		t.Fatal("other limits kept the key")
	}
	for _, bad := range []registry.Layer{
		{Digest: d("a"), MediaType: gzipType + "\x01" + d("b") + "\x00" + gzipType},
		{Digest: d("a"), MediaType: "x+gzip"},
		{Digest: "sha256:" + strings.Repeat("A", 64), MediaType: gzipType},
		{Digest: d("a") + "\x01", MediaType: gzipType},
	} {
		if _, err := LayerKeys([]registry.Layer{bad}, Limits{}); err == nil {
			t.Errorf("layer %+v accepted", bad)
		}
		img := newImage(t, gzipType, []entry{file("etc/os-release", "ID=x\n")})
		img.layers[0] = bad
		if _, err := BuildCached(t.Context(), img.layers, img.open, docker.ImageConfig{}, Limits{}, &memCache{recs: map[string][]byte{}}); err == nil {
			t.Errorf("build with layer %+v accepted", bad)
		}
	}
	// The crafted pair (digest a, media type carrying b) against the chain
	// (a, b): different keys even if it were accepted.
	crafted := hashJSON([]any{"imagelayers record", recordFormat, docker.ReaderFormat, LimitsKey(Limits{}),
		[]string{d("a"), gzipType + "\x01" + d("b") + "\x00" + gzipType}})
	if crafted == base[1] || crafted == base[0] {
		t.Fatal("crafted media type reproduced a chain key")
	}
}

// A layer with more members than a record holds is read correctly and
// not recorded, and its members are not kept while it is read.
func TestCacheMemberCap(t *testing.T) {
	var many []entry
	for i := range 40 {
		many = append(many, file(fmt.Sprintf("usr/share/doc/f%d", i), ""))
	}
	many = append(many, file("var/lib/dpkg/status", statusFile))
	img := newImage(t, gzipType, []entry{file("etc/os-release", "ID=debian\n")}, many)
	lim := Limits{Files: 2} // records hold at most 8 members
	cache := &memCache{recs: map[string][]byte{}}
	v, err := BuildCached(t.Context(), img.layers, img.open, docker.ImageConfig{}, lim, cache)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := snapshot(v), snapshot(build(t, img, docker.ImageConfig{}, lim)); got != want {
		t.Fatalf("view:\n%s\nwant\n%s", got, want)
	}
	keys, err := LayerKeys(img.layers, lim)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.recs[keys[0]]; !ok || cache.puts != 1 {
		t.Fatalf("small layer recorded %v, %d records", ok, cache.puts)
	}
	if _, ok := cache.recs[keys[1]]; ok {
		t.Fatal("layer over the member cap recorded")
	}
	rec := &LayerRecord{}
	w := &View{cfg: docker.ImageConfig{}, lim: lim.withDefaults(), files: map[string]*node{}, below: map[string]int{}}
	if _, err := w.readLayer(t.Context(), img.layers[1], img.open, 1<<30, rec); err != nil {
		t.Fatal(err)
	}
	if !rec.over || rec.Entries != nil {
		t.Fatalf("over %v with %d members kept", rec.over, len(rec.Entries))
	}
	// A second build reads the layer again.
	var opened int
	open := func(ctx context.Context, l registry.Layer) (io.ReadCloser, error) {
		opened++
		return img.open(ctx, l)
	}
	if _, err := BuildCached(t.Context(), img.layers, open, docker.ImageConfig{}, lim, cache); err != nil || opened != 1 {
		t.Fatalf("second build opened %d layers, %v", opened, err)
	}
}

// A record keeps the latest config keys only.
func TestRecordConfigsBounded(t *testing.T) {
	rec := &LayerRecord{}
	for i := range maxRecordConfigs + 5 {
		rec.addConfig(fmt.Sprint(i))
	}
	rec.addConfig("7")
	if len(rec.Configs) != maxRecordConfigs || rec.Configs[len(rec.Configs)-1] != "7" || rec.Configs[0] != "5" {
		t.Fatalf("configs %v", rec.Configs)
	}
}

// A record keeps the members no reader reads by name only, and the files
// a reader reads with their content as text: a layer of thousands of
// unread files records in a few bytes per file.
func TestRecordIsSlim(t *testing.T) {
	var members []entry
	for i := range 3000 {
		if i%10 == 0 {
			members = append(members, dir(fmt.Sprintf("usr/share/doc/pkg%d/", i)))
		}
		members = append(members, file(fmt.Sprintf("usr/share/doc/pkg%d/copyright-%d", i/10, i), strings.Repeat("c", 200)))
	}
	members = append(members, file("var/lib/dpkg/status", strings.Repeat(statusFile, 200)))
	img := newImage(t, gzipType, members)
	cache := &memCache{recs: map[string][]byte{}}
	if _, err := BuildCached(t.Context(), img.layers, img.open, docker.ImageConfig{}, Limits{}, cache); err != nil {
		t.Fatal(err)
	}
	var rec *LayerRecord
	for _, b := range cache.recs {
		rec = &LayerRecord{}
		if err := json.Unmarshal(b, rec); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.Entries) != 1 || rec.Entries[0].Path != "var/lib/dpkg/status" || rec.Entries[0].Text == "" || rec.Entries[0].Index != len(members)-1 {
		t.Fatalf("entries: %+v", rec.Entries)
	}
	if n := strings.Count(rec.Bare, "\x00") + 1; n != len(members)-1 {
		t.Fatalf("%d bare members, want %d", n, len(members)-1)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_ = json.NewEncoder(zw).Encode(rec)
	_ = zw.Close()
	// About 40 bytes of names per member before compression.
	if buf.Len() > 16<<10 {
		t.Fatalf("record of %d members compresses to %d bytes", len(members), buf.Len())
	}
}

// A record whose members do not add up is read again, not replayed.
func TestBadRecordReadAgain(t *testing.T) {
	img := newImage(t, gzipType, []entry{dir("etc/"), file("etc/os-release", "ID=debian\n"), file("usr/x", "y")})
	cache := &memCache{recs: map[string][]byte{}}
	want := snapshot(build(t, img, docker.ImageConfig{}, Limits{}))
	if _, err := BuildCached(t.Context(), img.layers, img.open, docker.ImageConfig{}, Limits{}, cache); err != nil {
		t.Fatal(err)
	}
	for k, b := range cache.recs {
		var rec LayerRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatal(err)
		}
		rec.Entries[0].Index = 7 // past the end of the bare members
		cache.recs[k], _ = json.Marshal(&rec)
	}
	var opened int
	open := func(ctx context.Context, l registry.Layer) (io.ReadCloser, error) {
		opened++
		return img.open(ctx, l)
	}
	v, err := BuildCached(t.Context(), img.layers, open, docker.ImageConfig{}, Limits{}, cache)
	if err != nil || opened != 1 {
		t.Fatalf("opened %d, %v", opened, err)
	}
	if got := snapshot(v); got != want {
		t.Fatalf("view:\n%s\nwant\n%s", got, want)
	}
}
