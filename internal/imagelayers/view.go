// SPDX-License-Identifier: Apache-2.0

// Package imagelayers squashes the layers of an image into a view of the
// few files the package reader reads, so a release that runs nowhere is read
// exactly like a running container. Layers come from registries Varde does
// not control: every read is bounded, names and links never leave the view,
// and nothing touches the local filesystem.
package imagelayers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/klauspost/compress/zstd"

	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/pkgdb"
	"github.com/bifrost0x/varde/internal/registry"
)

// Opener opens the blob of one layer, compressed as its media type says.
// The registry checks the digest at the end of the blob, so Build reads
// every layer to its end.
type Opener func(ctx context.Context, l registry.Layer) (io.ReadCloser, error)

// Limits bound the work and memory of one view. LayerBytes bounds the
// uncompressed bytes streamed from all layers together (a decompression
// bomb ends there), KeptBytes the file contents held in memory, Files the
// entries put into the view. A zero field takes its DefaultLimits value.
type Limits struct {
	LayerBytes, KeptBytes int64
	Files                 int
}

// DefaultLimits suit the largest images in common use.
var DefaultLimits = Limits{LayerBytes: 2 << 30, KeptBytes: 256 << 20, Files: 20000}

func (l Limits) withDefaults() Limits {
	if l.LayerBytes <= 0 {
		l.LayerBytes = DefaultLimits.LayerBytes
	}
	if l.KeptBytes <= 0 {
		l.KeptBytes = DefaultLimits.KeptBytes
	}
	if l.Files <= 0 {
		l.Files = DefaultLimits.Files
	}
	return l
}

const (
	// maxLinkHops ends a chain of symlinks, as the kernel's limit does.
	maxLinkHops = 40
	// maxLinkTarget bounds the target of a kept symlink.
	maxLinkTarget = 4096
	// zstdWindow bounds the memory of a zstd stream (long mode uses up
	// to 128 MiB).
	zstdWindow = 128 << 20
)

// errBound stops a build at LayerBytes.
var errBound = errors.New("imagelayers: layer byte limit reached")

// node is one kept file or symlink.
type node struct {
	use   docker.FileUse
	layer int
	size  int64
	// link is the target of a symlink; isLink marks one.
	link   string
	isLink bool
	data   []byte
	// tooLarge marks a file over the reader's limit: reading it fails as
	// it does in a container.
	tooLarge bool
	// prog and progErr are a Program's build information, taken while the
	// layer streamed by; its bytes are not kept.
	prog    docker.GoProgram
	progErr error
}

// View is the squashed result of an image's layers, restricted to the
// files docker.Use names for its configuration.
type View struct {
	cfg     docker.ImageConfig
	lim     Limits
	anchors []string
	files   map[string]*node
	// below counts the kept nodes under each directory, so whiteouts of
	// paths without kept nodes cost nothing.
	below   map[string]int
	kept    int64
	inserts int
	partial atomic.Bool

	// The layer being read and what it hides of the lower layers, applied
	// when it ends: a whiteout hides a path and everything under it, an
	// opaque directory or a file replacing a directory what is under it.
	layer     int
	hide      map[string]bool
	hideBelow map[string]bool

	// For layer records (cache.go): made is the file node the archive
	// member being read put, plain says that what the member did depends
	// on its name and type alone (a directory, a file the reader does not
	// read), replay is the recorded member being replayed.
	made   *node
	plain  bool
	replay *RecordEntry
}

// Build streams layers bottom to top and returns the view of the files the
// package reader reads of an image with cfg. A broken or unreadable layer
// is an error; a limit reached ends the build early with a Partial view.
func Build(ctx context.Context, layers []registry.Layer, open Opener, cfg docker.ImageConfig, lim Limits) (*View, error) {
	return BuildCached(ctx, layers, open, cfg, lim, nil)
}

// BuildCached is Build that replays layers from cache where its records
// suffice and records every layer it reads to the end (cache.go). A nil
// cache is Build.
func BuildCached(ctx context.Context, layers []registry.Layer, open Opener, cfg docker.ImageConfig, lim Limits, cache Cache) (*View, error) {
	v := &View{
		cfg:   cfg,
		lim:   lim.withDefaults(),
		files: map[string]*node{},
		below: map[string]int{},
	}
	for _, a := range docker.ReadLocations(cfg) {
		v.anchors = append(v.anchors, a)
		if t := twin(a); t != "" {
			v.anchors = append(v.anchors, t)
		}
	}
	var keys []string
	if cache != nil {
		var err error
		if keys, err = LayerKeys(layers, v.lim); err != nil {
			return nil, err
		}
	}
	left := v.lim.LayerBytes
	for i, l := range layers {
		v.layer, v.hide, v.hideBelow = i, map[string]bool{}, map[string]bool{}
		var used int64
		var err error
		if cache == nil {
			used, err = v.readLayer(ctx, l, open, left, nil)
		} else {
			used, err = v.cachedLayer(ctx, l, open, left, cache, keys[i])
		}
		left -= used
		// What the layer hid applies even when it was cut short.
		v.endLayer()
		if errors.Is(err, errBound) {
			v.partial.Store(true)
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Partial reports whether the view misses files the reader would read: a
// limit was reached while building, a kept file was too large to keep, or
// a read since then needed a file the view does not hold (a symlink to an
// unkept path). A read of a Partial view is incomplete.
func (v *View) Partial() bool { return v.partial.Load() }

// Source returns the view as a file source for docker.ReadPackages.
func (v *View) Source() docker.FileSource { return source{v} }

// boundedReader ends a stream with errBound after left bytes.
type boundedReader struct {
	r    io.Reader
	left int64
	used int64
	hit  bool
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		b.hit = true
		return 0, errBound
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	b.used += int64(n)
	return n, err
}

// ctxReader ends a layer stream, the drain at its end included, once ctx
// is done.
type ctxReader struct {
	ctx context.Context
	io.ReadCloser
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.ReadCloser.Read(p)
}

// trackReader remembers the error of the stream under a parser, which may
// turn a read error into a verdict about the content.
type trackReader struct {
	r   io.Reader
	err error
}

func (t *trackReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		t.err = err
	}
	return n, err
}

// readLayer streams one layer into the view and returns the uncompressed
// bytes it took. With rec, every archive member is recorded into it, with
// the content of the files the view kept.
func (v *View) readLayer(ctx context.Context, l registry.Layer, open Opener, left int64, rec *LayerRecord) (int64, error) {
	rc, err := open(ctx, l)
	if err != nil {
		return 0, fmt.Errorf("imagelayers: layer %s: %w", l.Digest, err)
	}
	defer func() { _ = rc.Close() }()
	rc = ctxReader{ctx: ctx, ReadCloser: rc}
	dec, err := decompress(l.MediaType, rc)
	if err != nil {
		return 0, fmt.Errorf("imagelayers: layer %s: %w", l.Digest, err)
	}
	defer func() { _ = dec.Close() }()
	br := &boundedReader{r: dec, left: left}
	fail := func(err error) (int64, error) {
		if br.hit {
			// The files read before the cut stay in the view, so the rest
			// of the compressed blob is read as well: the registry checks
			// the digest only at its end, and unchecked content must not
			// enter a release line. The blob is bounded by the layer's size
			// and its time bound; a layer that does not match fails.
			if _, err := io.Copy(io.Discard, rc); err != nil {
				return br.used, fmt.Errorf("imagelayers: layer %s: %w", l.Digest, err)
			}
			return br.used, errBound
		}
		return br.used, fmt.Errorf("imagelayers: layer %s: %w", l.Digest, err)
	}
	tr := tar.NewReader(br)
	for {
		if err := ctx.Err(); err != nil {
			return br.used, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(err)
		}
		v.made, v.plain = nil, false
		if err := v.add(hdr, tr); err != nil {
			return fail(err)
		}
		if rec != nil {
			rec.add(hdr, v.made, v.plain, recordMembersPerFile*v.lim.Files)
		}
	}
	// The rest of the layer (tar padding, the compressed stream's end) is
	// read too: the registry checks the digest only at the end of the blob.
	if _, err := io.Copy(io.Discard, br); err != nil {
		return fail(err)
	}
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fail(err)
	}
	if rec != nil {
		rec.finish(br.used)
	}
	return br.used, nil
}

// decompress opens a layer by its media type: gzip, zstd or a plain tar.
func decompress(mediaType string, r io.Reader) (io.ReadCloser, error) {
	switch {
	case strings.HasSuffix(mediaType, "+gzip") || strings.HasSuffix(mediaType, ".tar.gzip"):
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		return zr, nil
	case strings.HasSuffix(mediaType, "+zstd"):
		zr, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(zstdWindow))
		if err != nil {
			return nil, err
		}
		return zr.IOReadCloser(), nil
	case strings.HasSuffix(mediaType, ".tar"):
		return io.NopCloser(r), nil
	}
	return nil, fmt.Errorf("unsupported layer media type %q", mediaType)
}

// use is docker.Use, also for the twin of a path in an image with a merged
// /usr, where /bin/app is stored as /usr/bin/app.
func (v *View) use(p string) (docker.FileUse, int64) {
	u, limit := docker.Use(v.cfg, p)
	if u == docker.Unread {
		if t := twin(p); t != "" {
			return docker.Use(v.cfg, t)
		}
	}
	return u, limit
}

// twin maps a path under /bin, /sbin and /lib* to /usr and back: one of
// the two is a symlink to the other's directory in a merged /usr.
func twin(p string) string {
	for _, d := range []string{"/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"} {
		if strings.HasPrefix(p, d) {
			return "/usr" + p
		}
		if strings.HasPrefix(p, "/usr"+d) {
			return strings.TrimPrefix(p, "/usr")
		}
	}
	return ""
}

// anchorOrAbove reports whether p is a path the reader reads or a
// directory above one, where a symlink changes what is read.
func (v *View) anchorOrAbove(p string) bool {
	for _, a := range v.anchors {
		if a == p || strings.HasPrefix(a, p+"/") {
			return true
		}
	}
	return false
}

// add puts one archive member into the view.
func (v *View) add(hdr *tar.Header, r io.Reader) error {
	// Names are rooted at the image's root: "../" cannot climb above it.
	p := path.Clean("/" + hdr.Name)
	base, parent := path.Base(p), path.Dir(p)
	// A directory above the entry may be a kept symlink (lib -> usr/lib):
	// the entry belongs where the link leads, as when the layer is
	// unpacked.
	dir, crossed, ok := v.resolveDir(parent)
	if !ok {
		// A link loop above the entry: where it belongs is unknown.
		v.partial.Store(true)
		return nil
	}
	if crossed {
		parent, p = dir, path.Join(dir, base)
	}
	switch {
	case base == ".wh..wh..opq":
		if v.below[parent] > 0 {
			v.hideBelow[parent] = true
		}
		return nil
	case strings.HasPrefix(base, ".wh..wh."):
		// Other markers of the aufs format carry nothing for a reader.
		return nil
	case strings.HasPrefix(base, ".wh."):
		gone := path.Join(parent, strings.TrimPrefix(base, ".wh."))
		if v.files[gone] != nil || v.below[gone] > 0 {
			v.hide[gone] = true
		}
		return nil
	}
	if hdr.Typeflag == tar.TypeDir {
		// A directory replaces a file or link of a lower layer.
		v.remove(p)
		v.plain = true
		return nil
	}
	if v.below[p] > 0 {
		// A file replaces a lower layer's directory and all under it.
		v.hideBelow[p] = true
	}
	use, limit := v.use(p)
	switch hdr.Typeflag {
	case tar.TypeSymlink:
		if (use == docker.Unread && !v.anchorOrAbove(p)) || len(hdr.Linkname) > maxLinkTarget {
			v.remove(p)
			return nil
		}
		v.put(p, &node{isLink: true, link: hdr.Linkname})
	case tar.TypeLink:
		if use == docker.Unread {
			v.remove(p)
			return nil
		}
		src := v.files[path.Clean("/"+hdr.Linkname)]
		if src == nil || src.isLink || src.use != use {
			// A hard link to a file the view did not keep for this use.
			v.remove(p)
			v.partial.Store(true)
			return nil
		}
		n := *src
		v.put(p, &n)
	case tar.TypeReg:
		if use == docker.Unread {
			v.remove(p)
			v.plain = true
			return nil
		}
		if v.replay != nil && v.replay.bare {
			// Recorded by name for a config that does not read it.
			return errNoContent
		}
		return v.addFile(p, hdr.Size, use, limit, r)
	default:
		v.remove(p)
	}
	return nil
}

// addFile keeps a regular file the reader reads, within its limit.
func (v *View) addFile(p string, size int64, use docker.FileUse, limit int64, r io.Reader) error {
	n := &node{use: use, size: size}
	switch {
	case size > limit && use == docker.WholeFile:
		n.tooLarge = true
	case size > limit && use == docker.StatusFile:
		// The container reader skips such a file as well.
		v.remove(p)
		return nil
	case size > limit:
		v.remove(p)
		v.partial.Store(true)
		return nil
	case use == docker.Program && v.replay != nil:
		// A program's bytes are never recorded, its build information is.
		if !v.replay.program(n) {
			return errNoContent
		}
	case use == docker.Program:
		tr := &trackReader{r: r}
		n.prog, n.progErr = docker.ScanProgram(tr, size)
		if tr.err != nil {
			return tr.err
		}
	case v.kept-v.keptAt(p)+size > v.lim.KeptBytes:
		v.remove(p)
		v.partial.Store(true)
		return nil
	case v.replay != nil && (!v.replay.HasData || int64(len(v.replay.content())) != size):
		// Kept for this configuration, not when the layer was read.
		return errNoContent
	default:
		b, err := io.ReadAll(io.LimitReader(r, size))
		if err != nil {
			return err
		}
		if int64(len(b)) != size {
			return io.ErrUnexpectedEOF
		}
		n.data = b
	}
	v.put(p, n)
	v.made = n
	return nil
}

// keptAt returns the bytes held at p, which a new file at p replaces.
func (v *View) keptAt(p string) int64 {
	if n := v.files[p]; n != nil {
		return int64(len(n.data))
	}
	return 0
}

// put stores n at p for the current layer, within Files.
func (v *View) put(p string, n *node) {
	if v.inserts >= v.lim.Files {
		v.remove(p)
		v.partial.Store(true)
		return
	}
	v.inserts++
	v.remove(p)
	n.layer = v.layer
	v.files[p] = n
	v.kept += int64(len(n.data))
	for d := path.Dir(p); ; d = path.Dir(d) {
		v.below[d]++
		if d == "/" {
			break
		}
	}
}

// remove drops whatever is stored at p.
func (v *View) remove(p string) {
	n := v.files[p]
	if n == nil {
		return
	}
	delete(v.files, p)
	v.kept -= int64(len(n.data))
	for d := path.Dir(p); ; d = path.Dir(d) {
		if v.below[d]--; v.below[d] <= 0 {
			delete(v.below, d)
		}
		if d == "/" {
			break
		}
	}
}

// endLayer removes what the current layer hides of the lower ones. Nodes
// of the layer itself stay: an opaque marker may follow the layer's own
// files in the same directory.
func (v *View) endLayer() {
	if len(v.hide) == 0 && len(v.hideBelow) == 0 {
		return
	}
	for p, n := range v.files {
		if n.layer >= v.layer {
			continue
		}
		gone := v.hide[p]
		for d := path.Dir(p); !gone; d = path.Dir(d) {
			gone = v.hide[d] || v.hideBelow[d]
			if d == "/" {
				break
			}
		}
		if gone {
			v.remove(p)
		}
	}
}

// resolve follows symlinks in p within the view. Absolute targets start at
// the image's root and ".." stops there, so no link leads out of the view.
// crossed says whether a link was followed; a loop is ErrNoFile.
func (v *View) resolve(p string) (real string, crossed bool, err error) {
	cur := "/"
	rest := strings.Split(p, "/")
	for hops := 0; len(rest) > 0; {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, c)
		n := v.files[next]
		if n == nil || !n.isLink {
			cur = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return "", true, docker.ErrNoFile
		}
		crossed = true
		if strings.HasPrefix(n.link, "/") {
			cur = "/"
		}
		rest = append(strings.Split(n.link, "/"), rest...)
	}
	return cur, crossed, nil
}

// resolveDir is resolve for the directory of an archive entry; ok is
// false for a link loop.
func (v *View) resolveDir(dir string) (real string, crossed, ok bool) {
	real, crossed, err := v.resolve(dir)
	return real, crossed, err == nil
}

// lookup returns the node a read of file for want reaches through links.
func (v *View) lookup(file string, want docker.FileUse) (*node, error) {
	var real string
	var crossed bool
	var err error
	if want == docker.Program {
		// As in a container: links in the directories above a program
		// are followed (a merged /usr), a link at the program itself is
		// not read. /usr/bin/python3 -> python3.11 is no program read.
		var dir string
		dir, crossed, err = v.resolve(path.Dir(file))
		real = path.Join(dir, path.Base(file))
		if n := v.files[real]; err == nil && n != nil && n.isLink {
			return nil, docker.ErrNoFile
		}
	} else {
		real, crossed, err = v.resolve(file)
	}
	if err != nil {
		return nil, err
	}
	n := v.files[real]
	if n == nil {
		if u, _ := v.use(real); crossed && u != want {
			// A link to a file the view never kept: a container may well
			// have it.
			v.partial.Store(true)
		}
		return nil, docker.ErrNoFile
	}
	if (want == docker.Program) != (n.use == docker.Program) {
		v.partial.Store(true)
		return nil, docker.ErrNoFile
	}
	return n, nil
}

// checkParents marks the view partial when a directory above dir is a
// symlink: a container follows it, but the view kept files by the paths
// in the layers.
func (v *View) checkParents(dir string) {
	if _, crossed, err := v.resolve(path.Dir(dir)); crossed || err != nil {
		v.partial.Store(true)
	}
}

// under returns the kept files directly in dir (or anywhere below it with
// deep), of use, in name order.
func (v *View) under(dir string, use docker.FileUse, deep bool) []string {
	var out []string
	for p, n := range v.files {
		if n.isLink || n.use != use || !strings.HasPrefix(p, dir+"/") || (!deep && path.Dir(p) != dir) {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// streamTar writes the files at paths as an archive named relative to
// parent, after a directory entry for dir, and hands it to read.
func (v *View) streamTar(dir, parent string, paths []string, read func(*tar.Reader) error) error {
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		rel := func(p string) string { return strings.TrimPrefix(strings.TrimPrefix(p, parent), "/") }
		err := tw.WriteHeader(&tar.Header{Name: rel(dir) + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		for _, p := range paths {
			if err != nil {
				break
			}
			n := v.files[p]
			if err = tw.WriteHeader(&tar.Header{Name: rel(p), Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(n.data))}); err == nil {
				_, err = tw.Write(n.data)
			}
		}
		if err == nil {
			err = tw.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	err := read(tar.NewReader(pr))
	// Ends the writer when read stopped early.
	_ = pr.Close()
	return err
}

// source serves a View as a docker.FileSource. Its methods read what the
// container source's methods of the same name read.
type source struct{ v *View }

func (s source) ReadFile(_ context.Context, file string) ([]byte, error) {
	use, limit := docker.Use(s.v.cfg, file)
	if use != docker.WholeFile {
		return nil, fmt.Errorf("imagelayers: refusing to read %q", file)
	}
	n, err := s.v.lookup(file, docker.WholeFile)
	if err != nil {
		return nil, err
	}
	if n.tooLarge || int64(len(n.data)) > limit {
		return nil, fmt.Errorf("imagelayers: %s is larger than %d bytes", file, limit)
	}
	// A copy: the reader may append to what it gets.
	return bytes.Clone(n.data), nil
}

func (s source) ReadStatusDir(_ context.Context) ([][]byte, error) {
	s.v.checkParents(docker.StatusDir)
	paths := s.v.under(docker.StatusDir, docker.StatusFile, false)
	if len(paths) == 0 {
		return nil, docker.ErrNoFile
	}
	var out [][]byte
	err := s.v.streamTar(docker.StatusDir, path.Dir(docker.StatusDir), paths, func(tr *tar.Reader) error {
		var err error
		out, err = docker.ReadStatusTar(tr)
		return err
	})
	return out, err
}

func (s source) ReadGoBuildInfo(_ context.Context, file string) (pkgdb.GoBinary, error) {
	if use, _ := docker.Use(s.v.cfg, file); use != docker.Program {
		return pkgdb.GoBinary{}, fmt.Errorf("imagelayers: refusing to read %q", file)
	}
	n, err := s.v.lookup(file, docker.Program)
	switch {
	case err != nil:
		return pkgdb.GoBinary{}, err
	case n.progErr != nil:
		return pkgdb.GoBinary{}, n.progErr
	case n.prog.Crates != nil:
		return pkgdb.GoBinary{}, pkgdb.ErrNotGo
	}
	return n.prog.Info, nil
}

func (s source) ReadGoPrograms(_ context.Context) ([]docker.GoProgram, error) {
	s.v.checkParents(docker.ProgramDir)
	var out []docker.GoProgram
	files := 0
	for _, p := range s.v.under(docker.ProgramDir, docker.Program, false) {
		n := s.v.files[p]
		if n.size < docker.MinProgramSize {
			continue
		}
		if files++; files > docker.MaxPrograms {
			// The reader stops here as in a container, but the programs
			// past the cut are in the image: without them the read is
			// incomplete, and their dependencies must not count as gone.
			s.v.partial.Store(true)
			break
		}
		switch {
		case errors.Is(n.progErr, pkgdb.ErrNotGo):
		case n.progErr != nil:
			return out, n.progErr
		default:
			prog := n.prog
			prog.Path = p
			out = append(out, prog)
		}
	}
	if files == 0 {
		return nil, docker.ErrNoFile
	}
	return out, nil
}

func (s source) ReadLanguagePackages(ctx context.Context, workDir string) (docker.LanguageRead, error) {
	if workDir != s.v.cfg.WorkingDir {
		return docker.LanguageRead{}, fmt.Errorf("imagelayers: the view holds the files of working directory %q, not %q", s.v.cfg.WorkingDir, workDir)
	}
	return docker.WalkLanguageRoots(ctx, workDir, func(root string, _ int64, read func(*tar.Reader) error) error {
		// The budget is counted by the shared walk as the archive streams;
		// the view only holds the metadata files, far below it.
		s.v.checkParents(root)
		paths := s.v.under(root, docker.LanguageMeta, true)
		if len(paths) == 0 {
			return docker.ErrNoFile
		}
		return s.v.streamTar(root, path.Dir(root), paths, read)
	})
}
