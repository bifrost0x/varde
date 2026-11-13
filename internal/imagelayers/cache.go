// SPDX-License-Identifier: Apache-2.0

package imagelayers

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/pkgdb"
	"github.com/bifrost0x/varde/internal/registry"
)

// recordFormat is the version of LayerRecord. Raise it when add, addFile
// or the meaning of a record changes: every older record is then missed
// and its layer read again.
const recordFormat = 4

// Cache keeps layer records between builds. Layer returns nil for a key it
// does not hold.
type Cache interface {
	Layer(ctx context.Context, key string) (*LayerRecord, error)
	PutLayer(ctx context.Context, key string, rec *LayerRecord) error
}

// LayerRecord is a layer as a view reads it, without its blob: every
// archive member in archive order (whiteouts and opaque markers
// included), with the bytes of the files a view kept and the build
// information of the programs one scanned. Members and sizes do not depend
// on the image config, so the record of a base layer serves every image
// built on it; the content it holds is that of the configs it was read or
// replayed for (Configs). A replay that needs content the record lacks
// (a program or manifest only another config reads) reads the layer again
// and adds it.
//
// Most members of a layer are files and directories no reader reads, and
// replaying one needs nothing but its name: a directory replaces what
// was kept at its path, a file the reader does not read does the same
// and hides a kept directory it replaces. Those members are kept as bare
// names (Bare), in a few bytes each; the others in full (Entries). A bare
// file that another config reads is content the record lacks: replaying
// it for that config reads the layer again, as any missing content does.
// So a record replays exactly for every config while it holds little more
// than the names of a layer and the files a reader reads.
type LayerRecord struct {
	// Entries are the members recorded in full, by archive position.
	Entries []RecordEntry `json:"e,omitempty"`
	// Bare are the other members in archive order, each its type flag
	// byte and its name, separated by NUL (which no member name holds).
	// They fill the archive positions Entries leaves.
	Bare string `json:"b,omitempty"`
	// Used is the uncompressed size of the layer, counted against
	// Limits.LayerBytes as when the layer is read.
	Used int64 `json:"u"`
	// Configs are the ConfigKeys the record holds all content for, the
	// latest maxRecordConfigs.
	Configs []string `json:"c,omitempty"`

	// count is the number of members recorded; size the estimated
	// encoded size of the record; over says the layer had more members
	// or content than a record holds, which is then neither kept nor
	// stored. bare collects Bare while the layer is read.
	count int
	size  int64
	over  bool
	bare  []byte
}

// The bounds of one record. A layer beyond them is read every time, like a
// layer cut at LayerBytes: a hostile layer of millions of empty files must
// not become a huge record in memory or in the store.
const (
	// recordMembersPerFile times Limits.Files is the most archive members.
	recordMembersPerFile = 4
	// MaxRecordBytes bounds the estimated encoded size of a record.
	MaxRecordBytes = 128 << 20
	// maxRecordConfigs bounds Configs; older config keys are dropped,
	// which costs at most a conservative byte estimate.
	maxRecordConfigs = 16
)

// errBadRecord ends a replay of a record whose members do not add up; the
// layer is read again.
var errBadRecord = errors.New("imagelayers: inconsistent layer record")

// add records one archive member: bare when its name is all a replay
// needs, else in full. Nothing is kept once the record is over its bounds.
func (rec *LayerRecord) add(hdr *tar.Header, made *node, plain bool, maxMembers int) {
	if rec.over {
		return
	}
	if plain && bareName(hdr.Name) {
		rec.size += int64(len(hdr.Name)) + 2
		rec.bare = append(rec.bare, hdr.Typeflag)
		rec.bare = append(rec.bare, hdr.Name...)
		rec.bare = append(rec.bare, 0)
	} else {
		e := recordOf(hdr, made)
		e.Index = rec.count
		rec.size += e.size()
		rec.Entries = append(rec.Entries, e)
	}
	rec.count++
	if rec.count > maxMembers || rec.size > MaxRecordBytes {
		rec.over, rec.Entries, rec.bare = true, nil, nil
	}
}

// finish ends the recording of a layer read to its end.
func (rec *LayerRecord) finish(used int64) {
	rec.Used = used
	rec.Bare = strings.TrimSuffix(string(rec.bare), "\x00")
	rec.bare = nil
}

// bareName reports whether a member name can be kept bare: a JSON string
// carries it unchanged, and NUL separates it from the next.
func bareName(name string) bool {
	return name != "" && utf8.ValidString(name) && !strings.ContainsRune(name, 0)
}

// size estimates the encoded size of e: base64 grows bytes by a third,
// and every member carries field names and punctuation.
func (e *RecordEntry) size() int64 {
	n := int64(len(e.Name)+len(e.Link)+len(e.Data))*4/3 + int64(len(e.Path)+len(e.Target)+len(e.Text)+len(e.ProgramErr)) + 48
	if e.Program != nil {
		n += int64(len(e.Program.Info.GoVersion)) + 16
		for _, p := range append(e.Program.Info.Packages, e.Program.Crates...) {
			n += int64(len(p.Manager)+len(p.Name)+len(p.Version)+len(p.Distro)+len(p.Source)+len(p.SourceVersion)+len(p.Path)) + 96
		}
	}
	return n
}

// addConfig records cfgKey as covered, keeping the latest
// maxRecordConfigs keys.
func (rec *LayerRecord) addConfig(cfgKey string) {
	rec.Configs = slices.DeleteFunc(rec.Configs, func(c string) bool { return c == cfgKey })
	rec.Configs = append(rec.Configs, cfgKey)
	if n := len(rec.Configs); n > maxRecordConfigs {
		rec.Configs = rec.Configs[n-maxRecordConfigs:]
	}
}

// Covers reports whether the record holds all content a view of an image
// with cfg reads of the layer.
func (rec *LayerRecord) Covers(cfg docker.ImageConfig) bool {
	return slices.Contains(rec.Configs, ConfigKey(cfg))
}

// members calls fn with every member of the record in archive order, bare
// ones as entries that carry their name and type only.
func (rec *LayerRecord) members(fn func(e *RecordEntry) error) error {
	var bare []string
	if rec.Bare != "" {
		bare = strings.Split(rec.Bare, "\x00")
	}
	ei, bi := 0, 0
	for i := 0; ei < len(rec.Entries) || bi < len(bare); i++ {
		if ei < len(rec.Entries) && rec.Entries[ei].Index == i {
			if err := fn(&rec.Entries[ei]); err != nil {
				return err
			}
			ei++
			continue
		}
		if bi >= len(bare) || len(bare[bi]) < 2 || (ei < len(rec.Entries) && rec.Entries[ei].Index < i) {
			return errBadRecord
		}
		e := RecordEntry{Index: i, Type: bare[bi][0], Path: bare[bi][1:], bare: true}
		bi++
		if err := fn(&e); err != nil {
			return err
		}
	}
	return nil
}

// RecordEntry is one archive member of a LayerRecord, at archive position
// Index. A name or link that is UTF-8 is kept as text (Path, Target),
// another as bytes (Name, Link), so every name replays exactly; content
// likewise (Text, or Data).
type RecordEntry struct {
	Index  int    `json:"i"`
	Name   []byte `json:"n,omitempty"`
	Path   string `json:"m,omitempty"`
	Type   byte   `json:"t"`
	Link   []byte `json:"l,omitempty"`
	Target string `json:"k,omitempty"`
	Size   int64  `json:"s,omitempty"`
	// HasData says that Text or Data is the member's content.
	HasData bool   `json:"h,omitempty"`
	Data    []byte `json:"d,omitempty"`
	Text    string `json:"dt,omitempty"`
	// Program is the build information of a program; NotGo and
	// ProgramErr what scanning it reported instead.
	Program    *docker.GoProgram `json:"p,omitempty"`
	NotGo      bool              `json:"g,omitempty"`
	ProgramErr string            `json:"x,omitempty"`

	// bare marks a member replayed from its name alone.
	bare bool
}

func (e *RecordEntry) name() string {
	if e.Path != "" {
		return e.Path
	}
	return string(e.Name)
}

func (e *RecordEntry) link() string {
	if e.Target != "" {
		return e.Target
	}
	return string(e.Link)
}

func (e *RecordEntry) content() []byte {
	if e.Text != "" {
		return []byte(e.Text)
	}
	return e.Data
}

// errNoContent ends a replay that needs content the record does not hold.
var errNoContent = errors.New("imagelayers: layer record lacks content")

func recordOf(hdr *tar.Header, made *node) RecordEntry {
	e := RecordEntry{Type: hdr.Typeflag, Size: hdr.Size}
	if utf8.ValidString(hdr.Name) {
		e.Path = hdr.Name
	} else {
		e.Name = []byte(hdr.Name)
	}
	if utf8.ValidString(hdr.Linkname) {
		e.Target = hdr.Linkname
	} else {
		e.Link = []byte(hdr.Linkname)
	}
	switch {
	case made == nil || made.tooLarge:
	case made.use != docker.Program:
		e.HasData = true
		if utf8.Valid(made.data) {
			e.Text = string(made.data)
		} else {
			e.Data = made.data
		}
	case errors.Is(made.progErr, pkgdb.ErrNotGo):
		e.NotGo = true
	case made.progErr != nil:
		e.ProgramErr = made.progErr.Error()
	default:
		prog := made.prog
		e.Program = &prog
	}
	return e
}

func (e *RecordEntry) hasProgram() bool { return e.Program != nil || e.NotGo || e.ProgramErr != "" }

// program puts what scanning the recorded program gave into n; false
// when the record holds no scan of it.
func (e *RecordEntry) program(n *node) bool {
	switch {
	case e.NotGo:
		n.progErr = pkgdb.ErrNotGo
	case e.ProgramErr != "":
		n.progErr = errors.New(e.ProgramErr)
	case e.Program != nil:
		n.prog = *e.Program
	default:
		return false
	}
	return true
}

// merged returns rec with the content old holds and rec lacks; rec itself
// when both do not record the same members or the merge would not fit a
// record. A member recorded in full by either is recorded in full.
func (rec *LayerRecord) merged(old *LayerRecord) *LayerRecord {
	if old.Used != rec.Used {
		return rec
	}
	all := func(r *LayerRecord) []RecordEntry {
		var out []RecordEntry
		if r.members(func(e *RecordEntry) error { out = append(out, *e); return nil }) != nil {
			return nil
		}
		return out
	}
	news, olds := all(rec), all(old)
	if news == nil || len(news) != len(olds) {
		return rec
	}
	out := &LayerRecord{Used: rec.Used}
	for i := range news {
		n, o := &news[i], &olds[i]
		if n.name() != o.name() || n.Type != o.Type {
			return rec
		}
		switch {
		case n.bare && o.bare:
			out.bare = append(out.bare, n.Type)
			out.bare = append(out.bare, n.Path...)
			out.bare = append(out.bare, 0)
			out.size += int64(len(n.Path)) + 2
			continue
		case n.bare:
			*n = *o
		case !o.bare:
			if n.Size != o.Size || n.link() != o.link() {
				return rec
			}
			if !n.HasData && o.HasData && int64(len(o.content())) == n.Size {
				n.HasData, n.Data, n.Text = true, o.Data, o.Text
			}
			if !n.hasProgram() && o.hasProgram() {
				n.Program, n.NotGo, n.ProgramErr = o.Program, o.NotGo, o.ProgramErr
			}
		}
		n.Index = i
		out.Entries = append(out.Entries, *n)
		out.size += n.size()
	}
	if out.size > MaxRecordBytes {
		return rec
	}
	out.count = len(news)
	out.finish(rec.Used)
	for _, c := range old.Configs {
		out.addConfig(c)
	}
	for _, c := range rec.Configs {
		out.addConfig(c)
	}
	return out
}

// ConfigKey identifies what a view of an image with cfg reads:
// docker.Use depends on cfg only through docker.ReadLocations.
func ConfigKey(cfg docker.ImageConfig) string {
	return hashJSON(docker.ReadLocations(cfg))
}

// LimitsKey identifies lim with its defaults applied.
func LimitsKey(lim Limits) string {
	lim = lim.withDefaults()
	return hashJSON([]int64{lim.LayerBytes, lim.KeptBytes, int64(lim.Files)})
}

func hashJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Slices of strings and numbers always encode.
		panic(err)
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// layerTypes are the layer media types a view reads.
var layerTypes = []string{
	"application/vnd.oci.image.layer.v1.tar",
	"application/vnd.oci.image.layer.v1.tar+gzip",
	"application/vnd.oci.image.layer.v1.tar+zstd",
	"application/vnd.oci.image.layer.nondistributable.v1.tar",
	"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
	"application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
	"application/vnd.docker.image.rootfs.diff.tar.gzip",
	"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
}

// LayerKeys returns the cache key of each layer read with lim. What a
// layer adds to a view depends on the layers below it (the symlinked
// directories its members are put through, the files its whiteouts and
// hard links name) and on the limits all layers share, so the key is the
// digest of the layer, every layer below and the limits, as Docker's
// chain ID is: a record is replayed only onto the layers it was read on,
// and an image on the same base shares the base's records. The fields are
// hashed as a JSON array, so no crafted media type can make two chains
// hash alike; a layer with an invalid digest or an unknown media type is
// refused.
func LayerKeys(layers []registry.Layer, lim Limits) ([]string, error) {
	chain := []any{"imagelayers record", recordFormat, docker.ReaderFormat, LimitsKey(lim)}
	keys := make([]string, len(layers))
	for i, l := range layers {
		if !digestRe.MatchString(l.Digest) {
			return nil, fmt.Errorf("imagelayers: invalid layer digest %q", l.Digest)
		}
		if !slices.Contains(layerTypes, l.MediaType) {
			return nil, fmt.Errorf("imagelayers: layer %s: unsupported media type %q", l.Digest, strings.ToValidUTF8(l.MediaType, "?"))
		}
		chain = append(chain, []string{l.Digest, l.MediaType})
		keys[i] = hashJSON(chain)
	}
	return keys, nil
}

// cachedLayer adds layer l to the view: replayed from cache when its
// record holds all the view needs, else read, and the record stored.
func (v *View) cachedLayer(ctx context.Context, l registry.Layer, open Opener, left int64, cache Cache, key string) (int64, error) {
	old, err := cache.Layer(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("imagelayers: layer %s: cache: %w", l.Digest, err)
	}
	cfgKey := ConfigKey(v.cfg)
	if old != nil {
		saved := v.save()
		used, err := v.replayLayer(ctx, old, left)
		switch {
		case errors.Is(err, errNoContent):
			// Back to the view below the layer, which is read instead.
			v.restore(saved)
		case err != nil:
			return used, err
		default:
			if !slices.Contains(old.Configs, cfgKey) {
				old.addConfig(cfgKey)
				if err := cache.PutLayer(ctx, key, old); err != nil {
					return used, fmt.Errorf("imagelayers: layer %s: cache: %w", l.Digest, err)
				}
			}
			return used, nil
		}
	}
	rec := &LayerRecord{Configs: []string{cfgKey}}
	used, err := v.readLayer(ctx, l, open, left, rec)
	if err != nil {
		// A layer cut at the limit is not recorded: the next build may
		// read it in full.
		return used, err
	}
	if rec.over {
		// Too large to record: read again by every build.
		return used, nil
	}
	if old != nil {
		rec = rec.merged(old)
	}
	if err := cache.PutLayer(ctx, key, rec); err != nil {
		return used, fmt.Errorf("imagelayers: layer %s: cache: %w", l.Digest, err)
	}
	return used, nil
}

// replayLayer adds a recorded layer to the view.
func (v *View) replayLayer(ctx context.Context, rec *LayerRecord, left int64) (int64, error) {
	if rec.Used > left {
		// Reading the layer would reach the limit: read it, so the cut is
		// where reading puts it.
		return 0, errNoContent
	}
	defer func() { v.replay = nil }()
	err := rec.members(func(e *RecordEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		v.replay = e
		hdr := &tar.Header{Name: e.name(), Typeflag: e.Type, Linkname: e.link(), Size: e.Size}
		if err := v.add(hdr, bytes.NewReader(e.content())); err != nil {
			if errors.Is(err, errNoContent) {
				return err
			}
			return fmt.Errorf("imagelayers: replaying %q: %w", e.name(), err)
		}
		return nil
	})
	if errors.Is(err, errBadRecord) {
		// Read the layer instead, and replace the record.
		return 0, errNoContent
	}
	if err != nil {
		return 0, err
	}
	return rec.Used, nil
}

// checkpoint is the state of a view between layers.
type checkpoint struct {
	files   map[string]*node
	below   map[string]int
	kept    int64
	inserts int
	partial bool
}

// save returns the state of the view; nodes are never changed once put,
// so a shallow copy holds it.
func (v *View) save() checkpoint {
	return checkpoint{files: maps.Clone(v.files), below: maps.Clone(v.below), kept: v.kept, inserts: v.inserts, partial: v.partial.Load()}
}

func (v *View) restore(c checkpoint) {
	v.files, v.below, v.kept, v.inserts = c.files, c.below, c.kept, c.inserts
	v.partial.Store(c.partial)
	v.hide, v.hideBelow = map[string]bool{}, map[string]bool{}
}
