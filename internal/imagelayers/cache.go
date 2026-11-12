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

	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/pkgdb"
	"github.com/bifrost0x/varde/internal/registry"
)

// recordFormat is the version of LayerRecord. Raise it when add, addFile
// or the meaning of a record changes: every older record is then missed
// and its layer read again.
const recordFormat = 2

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
type LayerRecord struct {
	Entries []RecordEntry `json:"e"`
	// Used is the uncompressed size of the layer, counted against
	// Limits.LayerBytes as when the layer is read.
	Used int64 `json:"u"`
	// Configs are the ConfigKeys the record holds all content for.
	Configs []string `json:"c,omitempty"`
}

// Covers reports whether the record holds all content a view of an image
// with cfg reads of the layer.
func (rec *LayerRecord) Covers(cfg docker.ImageConfig) bool {
	return slices.Contains(rec.Configs, ConfigKey(cfg))
}

// RecordEntry is one archive member of a LayerRecord.
type RecordEntry struct {
	Name string `json:"n"`
	Type byte   `json:"t"`
	Link string `json:"l,omitempty"`
	Size int64  `json:"s,omitempty"`
	// HasData says that Data is the member's content.
	HasData bool   `json:"h,omitempty"`
	Data    []byte `json:"d,omitempty"`
	// Program is the build information of a program; NotGo and
	// ProgramErr what scanning it reported instead.
	Program    *docker.GoProgram `json:"p,omitempty"`
	NotGo      bool              `json:"g,omitempty"`
	ProgramErr string            `json:"x,omitempty"`
}

// errNoContent ends a replay that needs content the record does not hold.
var errNoContent = errors.New("imagelayers: layer record lacks content")

func recordOf(hdr *tar.Header, made *node) RecordEntry {
	e := RecordEntry{Name: hdr.Name, Type: hdr.Typeflag, Link: hdr.Linkname, Size: hdr.Size}
	switch {
	case made == nil || made.tooLarge:
	case made.use != docker.Program:
		e.HasData, e.Data = true, made.data
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

// merge adds the content old holds and rec lacks; both must record the
// same members.
func (rec *LayerRecord) merge(old *LayerRecord) {
	if len(old.Entries) != len(rec.Entries) || old.Used != rec.Used {
		return
	}
	for i := range rec.Entries {
		n, o := &rec.Entries[i], &old.Entries[i]
		if n.Name != o.Name || n.Type != o.Type || n.Size != o.Size || n.Link != o.Link {
			return
		}
	}
	for i := range rec.Entries {
		n, o := &rec.Entries[i], &old.Entries[i]
		if !n.HasData && o.HasData && int64(len(o.Data)) == n.Size {
			n.HasData, n.Data = true, o.Data
		}
		if !n.hasProgram() && o.hasProgram() {
			n.Program, n.NotGo, n.ProgramErr = o.Program, o.NotGo, o.ProgramErr
		}
	}
	for _, c := range old.Configs {
		if !slices.Contains(rec.Configs, c) {
			rec.Configs = append(rec.Configs, c)
		}
	}
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
				old.Configs = append(old.Configs, cfgKey)
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
	if old != nil {
		rec.merge(old)
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
	for i := range rec.Entries {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		e := &rec.Entries[i]
		v.replay = e
		hdr := &tar.Header{Name: e.Name, Typeflag: e.Type, Linkname: e.Link, Size: e.Size}
		if err := v.add(hdr, bytes.NewReader(e.Data)); err != nil {
			if errors.Is(err, errNoContent) {
				return 0, err
			}
			return 0, fmt.Errorf("imagelayers: replaying %s: %w", e.Name, err)
		}
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
