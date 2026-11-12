// SPDX-License-Identifier: Apache-2.0

package imagelayers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/registry"
)

const (
	gzipType = "application/vnd.oci.image.layer.v1.tar+gzip"
	zstdType = "application/vnd.oci.image.layer.v1.tar+zstd"
	tarType  = "application/vnd.oci.image.layer.v1.tar"
)

// entry is one member of a test layer: a regular file unless typ says
// otherwise.
type entry struct {
	name, body, link string
	typ              byte
}

func file(name, body string) entry   { return entry{name: name, body: body} }
func symlink(name, to string) entry  { return entry{name: name, link: to, typ: tar.TypeSymlink} }
func hardlink(name, to string) entry { return entry{name: name, link: to, typ: tar.TypeLink} }
func dir(name string) entry          { return entry{name: name, typ: tar.TypeDir} }

func tarOf(t *testing.T, es []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Linkname: e.link, Mode: 0o644}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func compress(t *testing.T, mediaType string, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	switch mediaType {
	case gzipType:
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(raw)
		_ = zw.Close()
	case zstdType:
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = zw.Write(raw)
		_ = zw.Close()
	default:
		buf.Write(raw)
	}
	return buf.Bytes()
}

// image holds test layers and opens them by digest.
type image struct {
	layers []registry.Layer
	blobs  map[string][]byte
}

func newImage(t *testing.T, mediaType string, layers ...[]entry) *image {
	t.Helper()
	img := &image{blobs: map[string][]byte{}}
	for i, es := range layers {
		b := compress(t, mediaType, tarOf(t, es))
		d := fmt.Sprintf("sha256:%064d", i)
		img.blobs[d] = b
		img.layers = append(img.layers, registry.Layer{Digest: d, MediaType: mediaType, Size: int64(len(b))})
	}
	return img
}

func (img *image) open(_ context.Context, l registry.Layer) (io.ReadCloser, error) {
	b, ok := img.blobs[l.Digest]
	if !ok {
		return nil, errors.New("no such blob")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func build(t *testing.T, img *image, cfg docker.ImageConfig, lim Limits) *View {
	t.Helper()
	v, err := Build(t.Context(), img.layers, img.open, cfg, lim)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func readFile(t *testing.T, v *View, file string) (string, error) {
	t.Helper()
	b, err := v.Source().ReadFile(t.Context(), file)
	return string(b), err
}

const statusFile = "Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b2\n\n"

// A package database deleted through a whiteout in an upper layer must not
// show the lower layer's file (Review Focus).
func TestWhiteoutRemovesLowerFile(t *testing.T) {
	img := newImage(t, gzipType,
		[]entry{dir("var/"), dir("var/lib/"), dir("var/lib/dpkg/"), file("var/lib/dpkg/status", statusFile), file("lib/apk/db/installed", "P:musl\nV:1\n")},
		[]entry{file("var/lib/dpkg/.wh.status", ""), file("lib/apk/.wh.db", "")},
	)
	v := build(t, img, docker.ImageConfig{}, Limits{})
	for _, f := range []string{"/var/lib/dpkg/status", "/lib/apk/db/installed"} {
		if _, err := readFile(t, v, f); !errors.Is(err, docker.ErrNoFile) {
			t.Fatalf("%s after its whiteout: err %v, want ErrNoFile", f, err)
		}
	}
	if v.Partial() {
		t.Fatal("complete view marked partial")
	}
	// A file added again above the whiteout counts.
	img = newImage(t, gzipType,
		[]entry{file("var/lib/dpkg/status", "old")},
		[]entry{file("var/lib/dpkg/.wh.status", "")},
		[]entry{file("var/lib/dpkg/status", statusFile)},
	)
	if got, err := readFile(t, build(t, img, docker.ImageConfig{}, Limits{}), "/var/lib/dpkg/status"); err != nil || got != statusFile {
		t.Fatalf("re-added status = %q, %v", got, err)
	}
}

func TestOpaqueDirClearsLower(t *testing.T) {
	img := newImage(t, gzipType,
		[]entry{file("var/lib/dpkg/status.d/a", "Package: a\nVersion: 1\n"), file("var/lib/dpkg/status.d/b", "Package: b\nVersion: 1\n"), file("var/lib/dpkg/status", statusFile)},
		// The marker may come after the layer's own files of the directory.
		[]entry{file("var/lib/dpkg/status.d/c", "Package: c\nVersion: 1\n"), file("var/lib/dpkg/status.d/.wh..wh..opq", "")},
		[]entry{file("var/lib/.wh..wh..opq", ""), dir("var/lib/dpkg/"), file("var/lib/dpkg/status.d/d", "Package: d\nVersion: 1\n")},
	)
	v := build(t, img, docker.ImageConfig{}, Limits{})
	files, err := v.Source().ReadStatusDir(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !strings.Contains(string(files[0]), "Package: d") {
		t.Fatalf("status.d after opaque dirs = %q", files)
	}
	if _, err := readFile(t, v, "/var/lib/dpkg/status"); !errors.Is(err, docker.ErrNoFile) {
		t.Fatalf("status under an opaque parent: err %v", err)
	}
	img = newImage(t, gzipType,
		[]entry{file("var/lib/dpkg/status.d/a", "Package: a\n"), file("var/lib/dpkg/status.d/b", "Package: b\n")},
		[]entry{file("var/lib/dpkg/status.d/c", "Package: c\n"), file("var/lib/dpkg/status.d/.wh..wh..opq", "")},
	)
	files, err = build(t, img, docker.ImageConfig{}, Limits{}).Source().ReadStatusDir(t.Context())
	if err != nil || len(files) != 1 || string(files[0]) != "Package: c\n" {
		t.Fatalf("status.d = %q, %v; want only the opaque layer's own file", files, err)
	}
}

func TestUpperLayerOverrides(t *testing.T) {
	img := newImage(t, gzipType,
		[]entry{file("etc/os-release", "ID=debian\nVERSION_ID=\"11\"\n"), file("var/lib/dpkg/status", "old")},
		[]entry{file("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")},
		// A directory replacing a file, and a file replacing a directory.
		[]entry{dir("var/lib/dpkg/status/"), file("var/lib/dpkg/status/x", "")},
	)
	v := build(t, img, docker.ImageConfig{}, Limits{})
	if got, err := readFile(t, v, "/etc/os-release"); err != nil || !strings.Contains(got, `"12"`) {
		t.Fatalf("os-release = %q, %v", got, err)
	}
	if _, err := readFile(t, v, "/var/lib/dpkg/status"); !errors.Is(err, docker.ErrNoFile) {
		t.Fatalf("status replaced by a directory: err %v", err)
	}
	img = newImage(t, gzipType,
		[]entry{file("var/lib/dpkg/status.d/a", "Package: a\n")},
		[]entry{file("var/lib/dpkg/status.d", "not a directory")},
	)
	if files, err := build(t, img, docker.ImageConfig{}, Limits{}).Source().ReadStatusDir(t.Context()); len(files) != 0 || !errors.Is(err, docker.ErrNoFile) {
		t.Fatalf("status.d replaced by a file = %q, %v", files, err)
	}
}

func TestSymlinkOSRelease(t *testing.T) {
	img := newImage(t, gzipType,
		[]entry{symlink("etc/os-release", "../usr/lib/os-release"), file("usr/lib/os-release", "ID=debian\nVERSION_ID=\"12\"\n")},
	)
	v := build(t, img, docker.ImageConfig{}, Limits{})
	if got, err := readFile(t, v, "/etc/os-release"); err != nil || !strings.Contains(got, "ID=debian") {
		t.Fatalf("os-release through its symlink = %q, %v", got, err)
	}
	// The absolute form, a symlinked parent (merged /usr) and a hard link.
	img = newImage(t, gzipType,
		[]entry{symlink("lib", "usr/lib"), file("usr/lib/os-release", "ID=alpine\n"), file("usr/lib/apk/db/installed", "P:musl\n")},
		[]entry{symlink("etc/os-release", "/lib/os-release"), hardlink("usr/lib/apk/db/x", "usr/lib/apk/db/installed")},
	)
	v = build(t, img, docker.ImageConfig{}, Limits{})
	if got, err := readFile(t, v, "/etc/os-release"); err != nil || got != "ID=alpine\n" {
		t.Fatalf("absolute symlink through a symlinked parent = %q, %v", got, err)
	}
	if got, err := readFile(t, v, "/lib/apk/db/installed"); err != nil || got != "P:musl\n" {
		t.Fatalf("file under a symlinked parent = %q, %v", got, err)
	}
	if v.Partial() {
		t.Fatal("view marked partial")
	}
}

// Names and links that climb out of the root stay inside the view, a loop
// ends, and a link to a file the view does not keep marks it partial.
func TestSymlinkSafety(t *testing.T) {
	img := newImage(t, gzipType,
		[]entry{
			file("../../../etc/os-release", "ID=debian\n"),
			symlink("var/lib/dpkg/status", "../../../../../../../../etc/shadow"),
			symlink("lib/apk/db/installed", "/lib/apk/db/installed"),
		},
	)
	v := build(t, img, docker.ImageConfig{}, Limits{})
	if got, err := readFile(t, v, "/etc/os-release"); err != nil || got != "ID=debian\n" {
		t.Fatalf("climbing name = %q, %v", got, err)
	}
	if _, err := readFile(t, v, "/lib/apk/db/installed"); err == nil {
		t.Fatal("symlink loop read")
	}
	if _, err := readFile(t, v, "/var/lib/dpkg/status"); !errors.Is(err, docker.ErrNoFile) {
		t.Fatalf("link out of the view: err %v", err)
	}
	if !v.Partial() {
		t.Fatal("a link to a file outside the view must mark it partial")
	}
	if _, err := v.Source().ReadFile(t.Context(), "/etc/shadow"); err == nil || errors.Is(err, docker.ErrNoFile) {
		t.Fatalf("a path the reader never reads must be refused: %v", err)
	}
}

func TestLimitMarksPartial(t *testing.T) {
	layers := [][]entry{
		{file("etc/os-release", "ID=debian\n"), file("var/lib/dpkg/status", statusFile)},
		{file("usr/share/doc/big", strings.Repeat("x", 64<<10))},
		{file("var/lib/dpkg/.wh.status", "")},
	}
	v := build(t, newImage(t, gzipType, layers...), docker.ImageConfig{}, Limits{LayerBytes: 32 << 10})
	if !v.Partial() {
		t.Fatal("layer byte limit not marked partial")
	}
	if got, err := readFile(t, v, "/etc/os-release"); err != nil || got != "ID=debian\n" {
		t.Fatalf("what was read before the limit = %q, %v", got, err)
	}
	if v := build(t, newImage(t, gzipType, layers...), docker.ImageConfig{}, Limits{KeptBytes: 16}); !v.Partial() {
		t.Fatal("kept byte limit not marked partial")
	}
	if v := build(t, newImage(t, gzipType, layers...), docker.ImageConfig{}, Limits{Files: 1}); !v.Partial() {
		t.Fatal("file limit not marked partial")
	}
	if v := build(t, newImage(t, gzipType, layers...), docker.ImageConfig{}, Limits{}); v.Partial() {
		t.Fatal("default limits marked partial")
	}
	// A package file over the reader's own limit fails like in a container.
	big := newImage(t, tarType, []entry{file("var/lib/dpkg/status", strings.Repeat("x", 16<<20+1))})
	if _, err := readFile(t, build(t, big, docker.ImageConfig{}, Limits{}), "/var/lib/dpkg/status"); err == nil || errors.Is(err, docker.ErrNoFile) {
		t.Fatalf("oversized status: err %v", err)
	}
}

func TestZstdLayer(t *testing.T) {
	img := newImage(t, zstdType, []entry{file("etc/os-release", "ID=debian\n")})
	if got, err := readFile(t, build(t, img, docker.ImageConfig{}, Limits{}), "/etc/os-release"); err != nil || got != "ID=debian\n" {
		t.Fatalf("os-release from zstd = %q, %v", got, err)
	}
	img = newImage(t, tarType, []entry{file("etc/os-release", "ID=alpine\n")})
	if got, err := readFile(t, build(t, img, docker.ImageConfig{}, Limits{}), "/etc/os-release"); err != nil || got != "ID=alpine\n" {
		t.Fatalf("os-release from a plain tar = %q, %v", got, err)
	}
	img.layers[0].MediaType = "application/vnd.oci.image.layer.v1.tar+bzip2"
	if _, err := Build(t.Context(), img.layers, img.open, docker.ImageConfig{}, Limits{}); err == nil {
		t.Fatal("unknown layer media type accepted")
	}
	// A broken layer fails the build instead of yielding an empty view.
	img = newImage(t, gzipType, []entry{file("etc/os-release", "ID=debian\n")})
	img.blobs[img.layers[0].Digest] = img.blobs[img.layers[0].Digest][:20]
	if _, err := Build(t.Context(), img.layers, img.open, docker.ImageConfig{}, Limits{}); err == nil {
		t.Fatal("truncated layer accepted")
	}
}

func TestReadPackagesOnView(t *testing.T) {
	img := newImage(t, gzipType,
		[]entry{
			symlink("etc/os-release", "../usr/lib/os-release"),
			file("usr/lib/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n"),
			file("var/lib/dpkg/status", statusFile+"Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u4\n\n"),
		},
		[]entry{
			file("app/package.json", `{"name":"web","version":"1.2.3"}`),
			file("usr/local/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n"),
			file("usr/local/lib/python3.11/site-packages/requests/api.py", "print()"),
		},
	)
	v := build(t, img, docker.ImageConfig{WorkingDir: "/app"}, Limits{})
	got, err := docker.ReadPackages(t.Context(), v.Source(), docker.ImageConfig{WorkingDir: "/app"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Distro != "debian-12" || got.Partial {
		t.Fatalf("distro %q partial %v", got.Distro, got.Partial)
	}
	want := map[string]bool{"dpkg bash 5.2.15-2+b2": false, "dpkg libc6 2.36-9+deb12u4": false, "npm web 1.2.3": false, "pip requests 2.31.0": false}
	for _, p := range got.Packages {
		k := p.Manager + " " + p.Name + " " + p.Version
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("%s not read: %+v", k, got.Packages)
		}
	}
}

func TestGoProgramsOnView(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	bin, err := os.ReadFile(exe) //nolint:gosec // the running test binary
	if err != nil {
		t.Skip(err)
	}
	img := newImage(t, tarType,
		[]entry{file("usr/local/bin/gosu", string(bin)), file("usr/local/bin/docker-entrypoint.sh", strings.Repeat("#", 2048)), file("usr/bin/app", string(bin))},
		[]entry{symlink("bin", "usr/bin")},
	)
	cfg := docker.ImageConfig{Entrypoint: []string{"/bin/app"}}
	v := build(t, img, cfg, Limits{})
	progs, err := v.Source().ReadGoPrograms(t.Context())
	if err != nil || len(progs) != 1 || progs[0].Path != "/usr/local/bin/gosu" || len(progs[0].Info.Packages) == 0 {
		t.Fatalf("programs = %+v, %v", progs, err)
	}
	bi, err := v.Source().ReadGoBuildInfo(t.Context(), "/bin/app")
	if err != nil || len(bi.Packages) == 0 {
		t.Fatalf("entrypoint through merged /usr = %+v, %v", bi, err)
	}
	if _, err := v.Source().ReadGoBuildInfo(t.Context(), "/usr/local/bin/docker-entrypoint.sh"); err == nil {
		t.Fatal("a script read as a Go program")
	}
}
