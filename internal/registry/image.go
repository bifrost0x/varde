// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// maxManifestBytes caps an index or manifest body.
	maxManifestBytes = 4 << 20
	// maxConfigBytes caps an image config, read only to learn the platform
	// of a single-platform image.
	maxConfigBytes = 1 << 20
)

// Platform names the OS and CPU architecture an image is built for.
type Platform struct{ OS, Arch, Variant string }

// Layer is one filesystem layer of an image.
type Layer struct {
	Digest, MediaType string
	Size              int64
}

// ImageManifest is the manifest of one platform of an image.
type ImageManifest struct {
	Digest       string
	Platform     Platform
	Layers       []Layer
	ConfigDigest string
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}

type manifestDoc struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
}

func isIndex(mediaType string) bool {
	return strings.HasSuffix(mediaType, "image.index.v1+json") || strings.HasSuffix(mediaType, "manifest.list.v2+json")
}

// wants reports whether a platform is among the requested ones. An empty
// variant in the request matches every variant (arm64 images are published
// with and without "v8"); no request at all means every platform.
func wants(want []Platform, p Platform) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if w.OS == p.OS && w.Arch == p.Arch && (w.Variant == "" || w.Variant == p.Variant) {
			return true
		}
	}
	return false
}

// validDigest accepts only sha256:<64 hex>, which also keeps a digest from
// altering the request path.
func validDigest(d string) bool {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// Image reads the manifests of a tag. For an index it follows only the
// entries of the requested platforms (attestation manifests, which carry the
// platform unknown/unknown, are never fetched); an empty platforms list
// means every real platform. A single-platform image is returned when its
// config says it matches. It also returns the digest of what the tag names.
func (c *Client) Image(ctx context.Context, repository, tag string, platforms []Platform) ([]ImageManifest, string, error) {
	host, name, err := endpoint(repository)
	if err != nil {
		return nil, "", err
	}
	s := &session{c: c, host: host, name: name}
	body, mediaType, digest, err := s.manifest(ctx, tag)
	if err != nil {
		return nil, "", err
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("registry: manifest %s: %w", tag, err)
	}
	if doc.MediaType != "" {
		mediaType = doc.MediaType
	}
	if !isIndex(mediaType) {
		m, err := s.single(ctx, digest, doc, platforms)
		if err != nil || m == nil {
			return nil, digest, err
		}
		return []ImageManifest{*m}, digest, nil
	}
	var out []ImageManifest
	seen := map[Platform]bool{}
	for _, d := range doc.Manifests {
		if d.Platform == nil || d.Platform.OS == "" || d.Platform.OS == "unknown" || d.Platform.Architecture == "unknown" {
			continue
		}
		p := Platform{OS: d.Platform.OS, Arch: d.Platform.Architecture, Variant: d.Platform.Variant}
		if !wants(platforms, p) || seen[p] {
			continue
		}
		if !validDigest(d.Digest) {
			return nil, digest, fmt.Errorf("registry: index entry for %s/%s has an invalid digest %q", p.OS, p.Arch, d.Digest)
		}
		seen[p] = true
		mbody, mt, md, err := s.manifest(ctx, d.Digest)
		if err != nil {
			return nil, digest, err
		}
		var md2 manifestDoc
		if err := json.Unmarshal(mbody, &md2); err != nil {
			return nil, digest, fmt.Errorf("registry: manifest %s: %w", d.Digest, err)
		}
		if isIndex(mt) || isIndex(md2.MediaType) {
			return nil, digest, fmt.Errorf("registry: manifest %s: nested index", d.Digest)
		}
		out = append(out, toImage(md, p, md2))
	}
	return out, digest, nil
}

// manifest fetches a manifest by tag or digest and returns its body, media
// type and digest. The digest is computed from the body; when the reference
// was a digest, a body that does not hash to it is rejected.
func (s *session) manifest(ctx context.Context, ref string) (body []byte, mediaType, digest string, err error) {
	resp, err := s.do(ctx, http.MethodGet, "/v2/"+s.name+"/manifests/"+url.PathEscape(ref), http.Header{"Accept": {manifestTypes}}, maxManifestBytes)
	if err != nil {
		return nil, "", "", err
	}
	sum := sha256.Sum256(resp.Body)
	digest = "sha256:" + hex.EncodeToString(sum[:])
	if strings.HasPrefix(ref, "sha256:") && ref != digest {
		return nil, "", "", fmt.Errorf("registry: manifest %s: content hashes to %s", ref, digest)
	}
	mediaType, _, _ = strings.Cut(resp.Header.Get("Content-Type"), ";")
	return resp.Body, strings.TrimSpace(mediaType), digest, nil
}

func toImage(digest string, p Platform, doc manifestDoc) ImageManifest {
	m := ImageManifest{Digest: digest, Platform: p, ConfigDigest: doc.Config.Digest}
	for _, l := range doc.Layers {
		m.Layers = append(m.Layers, Layer{Digest: l.Digest, MediaType: l.MediaType, Size: l.Size})
	}
	return m
}

// single handles a tag that names one image: its platform is in the config
// blob. nil means the image is built for another platform.
func (s *session) single(ctx context.Context, digest string, doc manifestDoc, platforms []Platform) (*ImageManifest, error) {
	if !validDigest(doc.Config.Digest) {
		return nil, errors.New("registry: manifest without a config digest")
	}
	rc, err := s.blob(ctx, doc.Config.Digest, maxConfigBytes)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	var cfg struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("registry: config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("registry: config: %w", err)
	}
	p := Platform{OS: cfg.OS, Arch: cfg.Architecture, Variant: cfg.Variant}
	if !wants(platforms, p) {
		return nil, nil
	}
	m := toImage(digest, p, doc)
	return &m, nil
}

// Blob opens a blob (a layer or config) for reading. The bytes are hashed
// while they are read: a content that does not match the digest ends in an
// error at EOF, so a caller must read to EOF before trusting the data, and
// more than max bytes is an error too. The registry may redirect to another
// host; credentials never follow.
func (c *Client) Blob(ctx context.Context, repository, digest string, max int64) (io.ReadCloser, error) {
	host, name, err := endpoint(repository)
	if err != nil {
		return nil, err
	}
	s := &session{c: c, host: host, name: name}
	return s.blob(ctx, digest, max)
}

func (s *session) blob(ctx context.Context, digest string, max int64) (io.ReadCloser, error) {
	if !validDigest(digest) {
		return nil, fmt.Errorf("registry: unsupported digest %q", digest)
	}
	st, err := s.open(ctx, "/v2/"+s.name+"/blobs/"+digest)
	if err != nil {
		return nil, err
	}
	if n := st.Header.Get("Content-Length"); n != "" {
		var size int64
		if _, err := fmt.Sscan(n, &size); err == nil && size > max {
			_ = st.Body.Close()
			return nil, fmt.Errorf("registry: blob %s is larger than %d bytes", digest, max)
		}
	}
	return &blobReader{c: s.c, rc: st.Body, h: sha256.New(), want: strings.TrimPrefix(digest, "sha256:"), max: max}, nil
}

type blobReader struct {
	c    *Client
	rc   io.ReadCloser
	h    hash.Hash
	want string
	max  int64
	n    int64
	err  error
}

func (b *blobReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	n, err := b.rc.Read(p)
	b.n += int64(n)
	if n > 0 {
		b.h.Write(p[:n])
		b.c.note(http.Header{}, int64(n), false)
	}
	if b.n > b.max {
		b.err = fmt.Errorf("registry: blob larger than %d bytes", b.max)
		return n, b.err
	}
	if err == io.EOF && hex.EncodeToString(b.h.Sum(nil)) != b.want {
		b.err = errors.New("registry: blob content does not match its digest")
		return n, b.err
	}
	return n, err
}

func (b *blobReader) Close() error { return b.rc.Close() }
