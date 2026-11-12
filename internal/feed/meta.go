// SPDX-License-Identifier: Apache-2.0

// Package feed is the client of the signed central feed (ADR 0005,
// docs/feed-trust.md): trust root handling, manifest verification,
// content-addressed blob download, staged installation and rollback and
// freeze protection.
package feed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// SpecVersion is the metadata format this client understands.
const SpecVersion = 1

// Environments a root can declare. Development roots come from
// cmd/feedbuilder and are never embedded in release builds.
const (
	EnvProduction  = "production"
	EnvDevelopment = "development"
)

// Key roles. A root may list keys with roles this client does not know;
// they are kept but never counted for anything (docs/feed-architecture.md
// 4.4), so a later role does not strand clients released before it.
const (
	RoleRoot = "root"
	RoleFeed = "feed"
	// RoleLicense signs uplink license documents.
	RoleLicense = "license"
	// RoleOverride signs acknowledgements of legitimate drops.
	RoleOverride = "override"
)

var roleName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Errors that callers and tests distinguish.
var (
	ErrSignature = errors.New("signature threshold not met")
	ErrExpired   = errors.New("metadata expired")
	ErrRollback  = errors.New("rollback")
	ErrMismatch  = errors.New("content does not match")
	// ErrTooOld reports metadata in a newer format than this version
	// reads: Varde has to be updated before it can use the data.
	ErrTooOld = errors.New("this Varde version is too old for the current data package")
)

// Signature is one Ed25519 signature over the signed bytes.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Key is a public key listed in the root.
type Key struct {
	Public    string     `json:"public"` // base64 Ed25519 public key
	Role      string     `json:"role"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`

	pub ed25519.PublicKey
}

func (k Key) validAt(t time.Time) bool {
	return (k.NotBefore == nil || !t.Before(*k.NotBefore)) && (k.NotAfter == nil || t.Before(*k.NotAfter))
}

// Root is the trust root: it names the keys allowed to sign roots and
// manifests and the number of signatures required.
type Root struct {
	Type        string         `json:"type"`
	SpecVersion int            `json:"spec_version"`
	Version     int64          `json:"version"`
	Expires     time.Time      `json:"expires"`
	Environment string         `json:"environment"`
	Keys        map[string]Key `json:"keys"`
	Thresholds  struct {
		Root int `json:"root"`
		Feed int `json:"feed"`
	} `json:"thresholds"`

	raw []byte // the signed bytes as received
}

// envelope wraps signed metadata: the signature covers the exact bytes of
// "signed", so no canonical JSON form is needed.
type envelope struct {
	Signed     json.RawMessage `json:"signed"`
	Signatures []Signature     `json:"signatures"`
}

// KeyID is the hex SHA-256 of the raw public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// decodeStrict decodes one JSON value, rejecting unknown fields and
// trailing data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// ParseRoot decodes and checks the structure of a root envelope. It does not
// verify signatures; see VerifyRootUpdate and verifySelf.
func ParseRoot(data []byte) (*Root, []Signature, error) {
	if len(data) > maxMetadataBytes {
		return nil, nil, errors.New("root larger than allowed")
	}
	var env envelope
	if err := decodeStrict(data, &env); err != nil {
		return nil, nil, fmt.Errorf("root: %w", err)
	}
	var r Root
	if err := decodeStrict(env.Signed, &r); err != nil {
		return nil, nil, fmt.Errorf("root: %w", err)
	}
	r.raw = env.Signed
	if r.Type != "root" || r.SpecVersion != SpecVersion || r.Version < 1 {
		return nil, nil, fmt.Errorf("root: unsupported type %q, spec %d or version %d", r.Type, r.SpecVersion, r.Version)
	}
	if r.Environment != EnvProduction && r.Environment != EnvDevelopment {
		return nil, nil, fmt.Errorf("root: unknown environment %q", r.Environment)
	}
	if r.Thresholds.Root < 1 || r.Thresholds.Feed < 1 {
		return nil, nil, errors.New("root: thresholds must be at least 1")
	}
	counts := map[string]int{}
	for id, k := range r.Keys {
		raw, err := base64.StdEncoding.DecodeString(k.Public)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("root: key %s is not an Ed25519 public key", id)
		}
		if KeyID(raw) != id {
			return nil, nil, fmt.Errorf("root: key id %s does not match its key", id)
		}
		if !roleName.MatchString(k.Role) {
			return nil, nil, fmt.Errorf("root: key %s has a malformed role %q", id, k.Role)
		}
		k.pub = raw
		r.Keys[id] = k
		counts[k.Role]++
	}
	if counts[RoleRoot] < r.Thresholds.Root || counts[RoleFeed] < r.Thresholds.Feed {
		return nil, nil, errors.New("root: fewer keys than the thresholds require")
	}
	return &r, env.Signatures, nil
}

// keysOf lists the keys of role that are valid at t.
func (r *Root) keysOf(role string, t time.Time) []Key {
	var out []Key
	for _, k := range r.Keys {
		if k.Role == role && k.validAt(t) {
			out = append(out, k)
		}
	}
	return out
}

// countValid counts distinct keys of role (valid at t) whose signature over
// msg verifies.
func (r *Root) countValid(role string, msg []byte, sigs []Signature, t time.Time) int {
	seen := map[string]bool{}
	n := 0
	for _, s := range sigs {
		k, ok := r.Keys[s.KeyID]
		if !ok || k.Role != role || seen[s.KeyID] || !k.validAt(t) {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(k.pub, msg, sig) {
			seen[s.KeyID] = true
			n++
		}
	}
	return n
}

// SignedByFeedKey reports whether sig is a signature over msg by a feed
// key of the root that is valid at t.
func (r *Root) SignedByFeedKey(msg, sig []byte, t time.Time) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, k := range r.keysOf(RoleFeed, t) {
		if ed25519.Verify(k.pub, msg, sig) {
			return true
		}
	}
	return false
}

// VerifyRoot parses a root and checks what does not need an older root:
// its own signatures and that it has not expired. It is the check for a
// root about to be embedded or published, not the one a client makes when
// it follows a rotation (VerifyRootUpdate).
func VerifyRoot(data []byte, now time.Time) (*Root, error) {
	r, sigs, err := ParseRoot(data)
	if err != nil {
		return nil, err
	}
	if err := r.verifySelf(sigs, now); err != nil {
		return nil, err
	}
	if !now.Before(r.Expires) {
		return nil, fmt.Errorf("root version %d: %w", r.Version, ErrExpired)
	}
	return r, nil
}

// KeyCount returns how many keys of role are valid at t.
func (r *Root) KeyCount(role string, t time.Time) int { return len(r.keysOf(role, t)) }

// HasFeedKey reports whether pub is a feed key of the root that is valid
// at t: a manifest signed with its private half would count.
func (r *Root) HasFeedKey(pub ed25519.PublicKey, t time.Time) bool {
	for _, k := range r.keysOf(RoleFeed, t) {
		if k.pub.Equal(pub) {
			return true
		}
	}
	return false
}

// verifySelf checks that a root is signed by the threshold of its own root
// keys.
func (r *Root) verifySelf(sigs []Signature, now time.Time) error {
	if r.countValid(RoleRoot, r.raw, sigs, now) < r.Thresholds.Root {
		return fmt.Errorf("root version %d: %w", r.Version, ErrSignature)
	}
	return nil
}

// VerifyRootUpdate accepts next only as the direct successor of trusted,
// signed by the root threshold of both (so a new root key set must be
// endorsed by the old one), and not expired.
func VerifyRootUpdate(trusted, next *Root, sigs []Signature, now time.Time) error {
	if next.Version != trusted.Version+1 {
		return fmt.Errorf("root version %d does not follow %d", next.Version, trusted.Version)
	}
	if trusted.countValid(RoleRoot, next.raw, sigs, now) < trusted.Thresholds.Root {
		return fmt.Errorf("root version %d not endorsed by version %d: %w", next.Version, trusted.Version, ErrSignature)
	}
	if err := next.verifySelf(sigs, now); err != nil {
		return err
	}
	if !now.Before(next.Expires) {
		return fmt.Errorf("root version %d: %w", next.Version, ErrExpired)
	}
	return nil
}

// Blob describes one content-addressed file of a manifest.
type Blob struct {
	Name             string `json:"name"`
	MediaType        string `json:"media_type"`
	Compression      string `json:"compression"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
	UncompressedSize int64  `json:"uncompressed_size"`
}

// Manifest is one feed snapshot.
type Manifest struct {
	Type          string `json:"type"`
	SchemaVersion int    `json:"schema_version"`
	// Channel names the channel the manifest was built for (the data
	// package, the uplink). All channels are signed by the same feed
	// keys; the name keeps a mirror of one from serving another's
	// manifest. Empty in the feed of the static modes.
	Channel        string    `json:"channel,omitempty"`
	Sequence       int64     `json:"sequence"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	CatalogVersion string    `json:"catalog_version"`
	Blobs          []Blob    `json:"blobs"`
}

// Media types of blobs.
const (
	MediaCatalog    = "application/vnd.varde.catalog.v1+json"
	MediaAdvisories = "application/vnd.varde.osv.v1+jsonl"
	MediaKEV        = "application/vnd.varde.kev.v1+json"
	MediaEPSS       = "application/vnd.varde.epss.v1+json"
	MediaIndex      = "application/vnd.varde.index.v1+tsv"
	// MediaGenerated holds the generated catalog entries. They have a
	// blob of their own: installations released before it refuse a
	// catalog blob of more than 2000 entries, but skip a blob they do not
	// know.
	MediaGenerated = "application/vnd.varde.catalog-generated.v1+json"
	// MediaReleases holds the package lists of the newest release of
	// catalog apps (ReleaseLine).
	MediaReleases = "application/vnd.varde.releases.v1+jsonl"
)

// Size limits.
const (
	maxBlobName        = 96
	maxMetadataBytes   = 1 << 20
	maxBlobs           = 512
	maxBlobBytes       = 128 << 20
	DefaultMaxUnpacked = 256 << 20
)

var (
	// blobName is the form of every blob name; knownName lists the blobs
	// this version reads. A well-formed name it does not know is skipped,
	// so the package can grow without breaking older installations.
	blobName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*(/[a-z0-9][a-z0-9-]*)*$`)
	knownName = regexp.MustCompile(`^(catalog|generated|releases|index|advisories/[a-z0-9-]{1,64}|enrichment/(kev|epss))$`)
	hexHash   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// knownBlob reports whether this version reads the blob of that name.
func knownBlob(name string) bool { return knownName.MatchString(name) }

// VerifyManifest checks the signatures (feed keys of root, valid now) and
// the structure of a manifest. Freshness and sequence are checked by the
// caller, which knows the stored state.
func VerifyManifest(root *Root, data, sigData []byte, now time.Time, maxUnpacked int64) (*Manifest, error) {
	if len(data) > maxMetadataBytes || len(sigData) > maxMetadataBytes {
		return nil, errors.New("manifest larger than allowed")
	}
	var sigs struct {
		Signatures []Signature `json:"signatures"`
	}
	if err := decodeStrict(sigData, &sigs); err != nil {
		return nil, fmt.Errorf("manifest signature file: %w", err)
	}
	if root.countValid(RoleFeed, data, sigs.Signatures, now) < root.Thresholds.Feed {
		return nil, fmt.Errorf("manifest: %w", ErrSignature)
	}
	var m Manifest
	if err := decodeStrict(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Type == "manifest" && m.SchemaVersion > SpecVersion {
		return nil, fmt.Errorf("manifest: schema %d, this version reads %d: %w", m.SchemaVersion, SpecVersion, ErrTooOld)
	}
	if m.Type != "manifest" || m.SchemaVersion != SpecVersion || m.Sequence < 1 {
		return nil, fmt.Errorf("manifest: unsupported type %q, schema %d or sequence %d", m.Type, m.SchemaVersion, m.Sequence)
	}
	if m.Channel != "" && m.Channel != ChannelPackage && m.Channel != ChannelUplink {
		return nil, fmt.Errorf("manifest: unknown channel %q", m.Channel)
	}
	if !m.ExpiresAt.After(m.CreatedAt) {
		return nil, errors.New("manifest: expires before it was created")
	}
	if len(m.Blobs) == 0 || len(m.Blobs) > maxBlobs {
		return nil, fmt.Errorf("manifest: %d blobs", len(m.Blobs))
	}
	names := map[string]bool{}
	var total int64
	for _, b := range m.Blobs {
		if len(b.Name) > maxBlobName || !blobName.MatchString(b.Name) || names[b.Name] {
			return nil, fmt.Errorf("manifest: invalid or duplicate blob name %q", b.Name)
		}
		names[b.Name] = true
		if !hexHash.MatchString(b.SHA256) {
			return nil, fmt.Errorf("manifest: blob %s: invalid sha256", b.Name)
		}
		if !knownBlob(b.Name) {
			// Neither fetched nor unpacked: its compression, media type
			// and size are for the versions that read it.
			continue
		}
		if b.Compression != "zstd" && b.Compression != "none" {
			return nil, fmt.Errorf("manifest: blob %s: unsupported compression %q", b.Name, b.Compression)
		}
		// Checked per blob before summing, so the total cannot overflow.
		if b.Size < 1 || b.Size > maxBlobBytes || b.UncompressedSize < 1 || b.UncompressedSize > maxUnpacked {
			return nil, fmt.Errorf("manifest: blob %s: invalid size", b.Name)
		}
		if b.Compression == "none" && b.Size != b.UncompressedSize {
			return nil, fmt.Errorf("manifest: blob %s: size mismatch", b.Name)
		}
		want := map[string]string{"catalog": MediaCatalog, "generated": MediaGenerated, "releases": MediaReleases,
			"index": MediaIndex, "enrichment/kev": MediaKEV, "enrichment/epss": MediaEPSS}[b.Name]
		if want == "" {
			want = MediaAdvisories
		}
		if b.MediaType != want {
			return nil, fmt.Errorf("manifest: blob %s: media type %q", b.Name, b.MediaType)
		}
		total += b.UncompressedSize
	}
	if !names["catalog"] {
		return nil, errors.New("manifest: no catalog blob")
	}
	if total > maxUnpacked {
		return nil, fmt.Errorf("manifest: %d bytes unpacked exceed the limit of %d", total, maxUnpacked)
	}
	return &m, nil
}
