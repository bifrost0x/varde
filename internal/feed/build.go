// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/fsutil"
)

// This file writes feeds. The client never calls it; it serves the tests and
// cmd/feedbuilder (development only). The production pipeline is a separate
// project and holds its keys offline.

// RootSpec describes a root to sign.
type RootSpec struct {
	Version     int64
	Expires     time.Time
	Environment string
	RootKeys    []ed25519.PublicKey
	FeedKeys    []ed25519.PublicKey
	// LicenseKeys sign uplink licenses (role "license").
	LicenseKeys []ed25519.PublicKey
	// LicenseNotBefore and LicenseNotAfter optionally limit their validity.
	LicenseNotBefore, LicenseNotAfter *time.Time
	RootThreshold                     int
	FeedThreshold                     int
	// FeedKeyWindow optionally limits feed key validity.
	FeedNotBefore, FeedNotAfter *time.Time
}

// SignRoot returns a root envelope signed by signers.
func SignRoot(spec RootSpec, signers ...ed25519.PrivateKey) ([]byte, error) {
	r := Root{Type: "root", SpecVersion: SpecVersion, Version: spec.Version, Expires: spec.Expires.UTC(),
		Environment: spec.Environment, Keys: map[string]Key{}}
	r.Thresholds.Root, r.Thresholds.Feed = spec.RootThreshold, spec.FeedThreshold
	for _, k := range spec.RootKeys {
		r.Keys[KeyID(k)] = Key{Public: base64.StdEncoding.EncodeToString(k), Role: RoleRoot}
	}
	for _, k := range spec.FeedKeys {
		r.Keys[KeyID(k)] = Key{Public: base64.StdEncoding.EncodeToString(k), Role: RoleFeed,
			NotBefore: spec.FeedNotBefore, NotAfter: spec.FeedNotAfter}
	}
	for _, k := range spec.LicenseKeys {
		r.Keys[KeyID(k)] = Key{Public: base64.StdEncoding.EncodeToString(k), Role: RoleLicense,
			NotBefore: spec.LicenseNotBefore, NotAfter: spec.LicenseNotAfter}
	}
	signed, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	// Not indented: MarshalIndent would reformat the signed bytes.
	return json.Marshal(envelope{Signed: signed, Signatures: sign(signed, signers)})
}

// IssueLicense signs a license with a license key; the key ID is set from
// the key.
func IssueLicense(l License, key ed25519.PrivateKey) ([]byte, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	l.KeyID = KeyID(pub)
	l.NotBefore, l.ExpiresAt = l.NotBefore.UTC(), l.ExpiresAt.UTC()
	signed, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	return json.Marshal(licenseEnvelope{Signed: signed, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, signed))})
}

func sign(msg []byte, signers []ed25519.PrivateKey) []Signature {
	sigs := make([]Signature, 0, len(signers))
	for _, k := range signers {
		pub, _ := k.Public().(ed25519.PublicKey)
		sigs = append(sigs, Signature{KeyID: KeyID(pub), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(k, msg))})
	}
	return sigs
}

// NewKey returns a fresh Ed25519 key.
func NewKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// WriteRoot publishes a root as the latest root and in the version history.
func WriteRoot(dir string, version int64, data []byte) error {
	if err := os.MkdirAll(filepath.Join(dir, "v1", "root"), 0o755); err != nil { //nolint:gosec // published, world-readable layout
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "v1", "root", fmt.Sprintf("%d.json", version)), data, 0o644); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, "v1", "root.json"), data, 0o644)
}

// maxCatalogBlobEntries is the limit every installation, also one released
// before the generated blob, puts on the catalog blob (catalog.Build).
const maxCatalogBlobEntries = 2000

// Snapshot is the content of one manifest to publish.
type Snapshot struct {
	// Channel is the channel the snapshot is published on
	// (ChannelPackage, ChannelUplink); empty for a static feed.
	Channel        string
	Sequence       int64
	CreatedAt      time.Time
	ExpiresAt      time.Time
	CatalogVersion string
	// Catalog are the reviewed entries; at most 2000, the limit of the
	// installations released before the generated blob.
	Catalog []catalog.Entry
	// Generated are the generated entries, written to a blob of their own;
	// nil leaves the blob out.
	Generated  []catalog.Entry
	Advisories []AdvisoryLine
	KEV        []KEVLine
	EPSS       []EPSSLine
	// Releases are the package lists of the newest releases; nil leaves
	// the blob out.
	Releases []ReleaseLine
	// Index is the first-party index table (applists.Table.Marshal);
	// empty leaves the blob out.
	Index []byte
	// Shards splits advisories by app ID (default 64).
	Shards int
}

// WriteSnapshot writes the blobs, the manifest and its signature file.
func WriteSnapshot(dir string, s Snapshot, signers ...ed25519.PrivateKey) ([]byte, error) {
	if s.Shards <= 0 {
		s.Shards = 64
	}
	blobs := map[string]struct {
		media string
		data  []byte
	}{}
	if len(s.Catalog) > maxCatalogBlobEntries {
		return nil, fmt.Errorf("catalog blob: %d entries, installations read at most %d", len(s.Catalog), maxCatalogBlobEntries)
	}
	cat, err := json.Marshal(catalogDoc{SchemaVersion: SpecVersion, Entries: s.Catalog})
	if err != nil {
		return nil, err
	}
	blobs["catalog"] = struct {
		media string
		data  []byte
	}{MediaCatalog, cat}
	if s.Generated != nil {
		data, err := json.Marshal(catalogDoc{SchemaVersion: SpecVersion, Entries: s.Generated})
		if err != nil {
			return nil, err
		}
		blobs["generated"] = struct {
			media string
			data  []byte
		}{MediaGenerated, data}
	}
	if s.Releases != nil {
		data, err := marshalReleases(s.Releases)
		if err != nil {
			return nil, err
		}
		blobs["releases"] = struct {
			media string
			data  []byte
		}{MediaReleases, data}
	}
	shards := map[int][]AdvisoryLine{}
	for _, a := range s.Advisories {
		h := fnv.New32a()
		_, _ = h.Write([]byte(a.AppID))
		shards[int(h.Sum32())%s.Shards] = append(shards[int(h.Sum32())%s.Shards], a)
	}
	for n, lines := range shards {
		sort.Slice(lines, func(i, j int) bool { return lines[i].AppID+lines[i].OSV.ID < lines[j].AppID+lines[j].OSV.ID })
		data, err := marshalLines(lines)
		if err != nil {
			return nil, err
		}
		blobs[fmt.Sprintf("advisories/shard-%02d", n)] = struct {
			media string
			data  []byte
		}{MediaAdvisories, data}
	}
	if len(s.Index) > 0 {
		blobs["index"] = struct {
			media string
			data  []byte
		}{MediaIndex, s.Index}
	}
	if s.KEV != nil {
		data, err := json.Marshal(s.KEV)
		if err != nil {
			return nil, err
		}
		blobs["enrichment/kev"] = struct {
			media string
			data  []byte
		}{MediaKEV, data}
	}
	if s.EPSS != nil {
		data, err := json.Marshal(s.EPSS)
		if err != nil {
			return nil, err
		}
		blobs["enrichment/epss"] = struct {
			media string
			data  []byte
		}{MediaEPSS, data}
	}

	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return nil, err
	}
	defer func() { _ = enc.Close() }()
	if err := os.MkdirAll(filepath.Join(dir, "v1", "blobs", "sha256"), 0o755); err != nil { //nolint:gosec // published, world-readable layout
		return nil, err
	}
	m := Manifest{Type: "manifest", SchemaVersion: SpecVersion, Channel: s.Channel, Sequence: s.Sequence, CreatedAt: s.CreatedAt.UTC(),
		ExpiresAt: s.ExpiresAt.UTC(), CatalogVersion: s.CatalogVersion}
	names := make([]string, 0, len(blobs))
	for n := range blobs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := blobs[n]
		packed := enc.EncodeAll(b.data, nil)
		sum := sha256.Sum256(packed)
		h := hex.EncodeToString(sum[:])
		if err := fsutil.WriteFileAtomic(filepath.Join(dir, "v1", "blobs", "sha256", h), packed, 0o644); err != nil {
			return nil, err
		}
		m.Blobs = append(m.Blobs, Blob{Name: n, MediaType: b.media, Compression: "zstd", SHA256: h,
			Size: int64(len(packed)), UncompressedSize: int64(len(b.data))})
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	sig, err := json.MarshalIndent(struct {
		Signatures []Signature `json:"signatures"`
	}{sign(data, signers)}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "v1", "manifest.json.sig"), sig, 0o644); err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, "v1", "manifest.json"), data, 0o644); err != nil {
		return nil, err
	}
	return data, nil
}
