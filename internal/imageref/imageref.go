// SPDX-License-Identifier: Apache-2.0

// Package imageref parses container image references and normalises
// repository names so that equivalent spellings compare equal.
package imageref

import (
	"errors"
	"fmt"
	"strings"
)

const maxRefLength = 512

// DockerHub is the canonical registry name of Docker Hub.
const DockerHub = "docker.io"

// Ref is a parsed image reference.
type Ref struct {
	// Repository is the normalised repository including the registry,
	// e.g. "docker.io/library/nginx" or "ghcr.io/immich-app/immich-server".
	Repository string
	Tag        string
	Digest     string
}

// ErrInvalid wraps every parse failure.
var ErrInvalid = errors.New("invalid image reference")

// Parse parses ref ("nginx", "ghcr.io/org/app:v1@sha256:...").
func Parse(ref string) (Ref, error) {
	if ref == "" || len(ref) > maxRefLength {
		return Ref{}, fmt.Errorf("%w: length %d", ErrInvalid, len(ref))
	}
	var r Ref
	name := ref
	if i := strings.IndexByte(name, '@'); i >= 0 {
		r.Digest = name[i+1:]
		name = name[:i]
		if !validDigest(r.Digest) {
			return Ref{}, fmt.Errorf("%w: digest in %q", ErrInvalid, ref)
		}
	}
	// A tag follows the last colon after the last slash (a colon before it
	// belongs to a registry port).
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		r.Tag = name[i+1:]
		name = name[:i]
		if !validTag(r.Tag) {
			return Ref{}, fmt.Errorf("%w: tag in %q", ErrInvalid, ref)
		}
	}
	repo, err := NormaliseRepository(name)
	if err != nil {
		return Ref{}, fmt.Errorf("%w: %q: %w", ErrInvalid, ref, err)
	}
	r.Repository = repo
	return r, nil
}

// linuxserver.io publishes the same images on three registries.
var lsioAliases = []string{"ghcr.io/linuxserver/", DockerHub + "/linuxserver/"}

const lsioCanonical = "lscr.io/linuxserver/"

// NormaliseRepository returns the canonical spelling of a repository name
// without tag or digest: lowercase, registry made explicit, Docker Hub
// official images under "library/", linuxserver.io mirrors folded onto
// lscr.io.
func NormaliseRepository(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty repository")
	}
	if strings.ContainsAny(name, "@ \t") {
		return "", errors.New("unexpected character")
	}
	name = strings.ToLower(name)
	parts := strings.Split(name, "/")
	registry := DockerHub
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		registry, parts = parts[0], parts[1:]
	}
	switch registry {
	case "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		registry = DockerHub
	}
	if !validRegistry(registry) {
		return "", fmt.Errorf("invalid registry %q", registry)
	}
	if registry == DockerHub && len(parts) == 1 {
		parts = append([]string{"library"}, parts...)
	}
	for _, p := range parts {
		if !validComponent(p) {
			return "", fmt.Errorf("invalid path component %q", p)
		}
	}
	repo := registry + "/" + strings.Join(parts, "/")
	for _, alias := range lsioAliases {
		if rest, ok := strings.CutPrefix(repo, alias); ok {
			return lsioCanonical + rest, nil
		}
	}
	return repo, nil
}

// IsLSIO reports whether a normalised repository is a linuxserver.io image.
func IsLSIO(repo string) bool { return strings.HasPrefix(repo, lsioCanonical) }

func validComponent(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		sep := c == '.' || c == '_' || c == '-'
		if !alnum && !sep {
			return false
		}
		if sep && (i == 0 || i == len(s)-1) {
			return false
		}
	}
	return true
}

// validRegistry accepts host[:port] with DNS-style labels.
func validRegistry(s string) bool {
	host, port, hasPort := strings.Cut(s, ":")
	if hasPort {
		if port == "" || len(port) > 5 {
			return false
		}
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return false
			}
		}
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func validTag(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'
		if !ok || (i == 0 && (c == '.' || c == '-')) {
			return false
		}
	}
	return true
}

func validDigest(s string) bool {
	algo, hex, ok := strings.Cut(s, ":")
	if !ok || algo == "" || len(hex) < 32 || len(hex) > 128 {
		return false
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
