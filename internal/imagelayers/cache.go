// SPDX-License-Identifier: Apache-2.0

package imagelayers

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/pkgdb"
	"github.com/bifrost0x/varde/internal/registry"
)

// recordFormat is the version of LayerRecord and of what a layer keeps.
// Raise it when add, addFile or docker.Use change what a layer puts into a
// view: every record of an older format is then missed and read again.
const recordFormat = 1

// Cache keeps layer records between builds. Layer returns nil for a key it
// does not hold.
type Cache interface {
	Layer(ctx context.Context, key string) (*LayerRecord, error)
	PutLayer(ctx context.Context, key string, rec *LayerRecord) error
}

// LayerRecord is what one layer did to a view: the archive members that
// changed it (whiteouts and opaque markers included), in archive order,
// with the bytes of the files kept and the build information of the
// programs read. Replaying it on the same view gives the same view as
// reading the layer, without its blob.
type LayerRecord struct {
	Entries []RecordEntry `json:"entries"`
	// Used is the uncompressed size of the layer, counted against
	// Limits.LayerBytes as when the layer is read.
	Used int64 `json:"used"`
	// Partial says that the layer made the view Partial.
	Partial bool `json:"partial,omitempty"`
}

// RecordEntry is one archive member of a LayerRecord.
type RecordEntry struct {
	Name string `json:"name"`
	Type byte   `json:"type"`
	Link string `json:"link,omitempty"`
	Size int64  `json:"size,omitempty"`
	Data []byte `json:"data,omitempty"`
	// Program is the build information of a program; NotGo and
	// ProgramErr what scanning it reported instead.
	Program    *docker.GoProgram `json:"program,omitempty"`
	NotGo      bool              `json:"not_go,omitempty"`
	ProgramErr string            `json:"program_err,omitempty"`
}

func recordOf(hdr *tar.Header, made *node) RecordEntry {
	e := RecordEntry{Name: hdr.Name, Type: hdr.Typeflag, Link: hdr.Linkname, Size: hdr.Size}
	if made == nil {
		return e
	}
	if made.use != docker.Program {
		e.Data = made.data
		return e
	}
	switch {
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

// program is what scanning the recorded program gave.
func (e *RecordEntry) program() (docker.GoProgram, error) {
	switch {
	case e.NotGo:
		return docker.GoProgram{}, pkgdb.ErrNotGo
	case e.ProgramErr != "":
		return docker.GoProgram{}, errors.New(e.ProgramErr)
	case e.Program != nil:
		return *e.Program, nil
	}
	return docker.GoProgram{}, errors.New("imagelayers: recorded program without build information")
}

// LayerKeys returns the cache key of each layer of an image read with cfg
// and lim. What a layer adds to a view depends on more than its own bytes:
// the configuration says which files are kept, the layers below hold the
// symlinked directories its members are put through and the files its
// whiteouts and hard links name, and the limits are shared by all layers.
// The key is therefore the digest of all of them up to the layer (as
// Docker's chain ID is), so a record is replayed only onto the view it was
// recorded on. The next release of an image usually shares its lower
// layers, whose records it reuses.
func LayerKeys(layers []registry.Layer, cfg docker.ImageConfig, lim Limits) []string {
	lim = lim.withDefaults()
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "imagelayers record %d reader %d\x00%d %d %d\x00", recordFormat, docker.ReaderFormat, lim.LayerBytes, lim.KeptBytes, lim.Files)
	// docker.Use depends on cfg only through the locations it reads.
	_, _ = io.WriteString(h, strings.Join(docker.ReadLocations(cfg), "\x00"))
	keys := make([]string, len(layers))
	for i, l := range layers {
		_, _ = fmt.Fprintf(h, "\x01%s\x00%s", l.Digest, l.MediaType)
		// Each key covers every layer below: the hash goes on from here.
		keys[i] = "sha256:" + hex.EncodeToString(h.Sum(nil))
	}
	return keys
}

// layerFrom adds layer l to the view: replayed from cache when it holds
// the layer's record, else read, and its record stored when it was read
// to the end.
func (v *View) layerFrom(ctx context.Context, l registry.Layer, open Opener, left int64, cache Cache, keys []string) (int64, error) {
	if cache == nil {
		return v.readLayer(ctx, l, open, left, nil)
	}
	key := keys[v.layer]
	rec, err := cache.Layer(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("imagelayers: layer %s: cache: %w", l.Digest, err)
	}
	if rec != nil {
		return v.replayLayer(ctx, rec, left)
	}
	rec = &LayerRecord{}
	v.layerPartial = false
	used, err := v.readLayer(ctx, l, open, left, rec)
	if err != nil {
		return used, err
	}
	if err := cache.PutLayer(ctx, key, rec); err != nil {
		return used, fmt.Errorf("imagelayers: layer %s: cache: %w", l.Digest, err)
	}
	return used, nil
}

// replayLayer adds a recorded layer to the view.
func (v *View) replayLayer(ctx context.Context, rec *LayerRecord, left int64) (int64, error) {
	if rec.Used > left {
		// Not the view the record was made on (the key covers the
		// limits); the layer would have been cut.
		return 0, errBound
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
			return 0, fmt.Errorf("imagelayers: replaying %s: %w", e.Name, err)
		}
	}
	return rec.Used, nil
}
