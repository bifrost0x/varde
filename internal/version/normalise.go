// SPDX-License-Identifier: Apache-2.0

package version

import (
	"regexp"
	"strings"
)

// floating are tag names that move between releases and therefore never
// identify a version.
var floating = map[string]bool{
	"latest": true, "stable": true, "release": true, "main": true, "master": true,
	"nightly": true, "develop": true, "development": true, "dev": true, "edge": true,
	"beta": true, "alpha": true, "rc": true, "next": true, "preview": true, "testing": true,
	"unstable": true, "canary": true, "current": true, "lts": true, "production": true,
	"prod": true, "experimental": true, "snapshot": true, "head": true, "trunk": true,
	"rolling": true, "devel": true,
}

// development are floating tags that follow a development branch rather
// than releases: an image built from them runs code past the release its
// manifest names.
var development = map[string]bool{
	"main": true, "master": true, "nightly": true, "develop": true, "development": true, "dev": true,
	"edge": true, "beta": true, "alpha": true, "rc": true, "next": true, "preview": true, "testing": true,
	"unstable": true, "canary": true, "experimental": true, "snapshot": true, "head": true, "trunk": true,
	"devel": true,
}

// IsDevelopment reports whether tag follows a development branch ("main",
// "nightly-alpine").
func IsDevelopment(tag string) bool {
	t := strings.ToLower(tag)
	base, _, _ := strings.Cut(t, "-")
	return development[t] || (IsFloating(t) && development[base])
}

// IsFloating reports whether tag is a moving tag: a well-known channel name,
// a channel with a variant suffix ("latest-alpine", "stable-arm64") or any
// tag without a digit. A channel prefix followed by a version
// ("release-4.0.11.2680") is pinned.
func IsFloating(tag string) bool {
	t := strings.ToLower(tag)
	if t == "" || floating[t] {
		return true
	}
	if base, rest, ok := strings.Cut(t, "-"); ok && floating[base] {
		rest = strings.TrimPrefix(rest, "v")
		if rest == "" || rest[0] < '0' || rest[0] > '9' {
			return true
		}
	}
	return !strings.ContainsAny(t, "0123456789")
}

// Normaliser names.
const (
	NormaliserLSIO = "lsio"
)

// ValidNormaliser reports whether name is a known normaliser.
func ValidNormaliser(name string) bool { return name == NormaliserLSIO }

var (
	// linuxserver.io tags and versions: "4.0.11.2680-ls262", "v1.2.3-ls5".
	lsioSuffix = regexp.MustCompile(`^(.+?)-ls\d+$`)
	// Base-image suffix on some linuxserver.io versions: "12.4ubu2604".
	lsioBase = regexp.MustCompile(`^(v?\d+(?:\.\d+)*)ubu\d+$`)
	// linuxserver.io build_version label:
	// "Linuxserver.io version:- 4.0.11.2680-ls262 Build-date:- 2024-11-02T..."
	lsioLabel = regexp.MustCompile(`(?i)version:-?\s*(\S+)`)
)

// Normalise applies a named normaliser. It returns the input unchanged for
// an empty name and ok=false if the normaliser does not apply.
func Normalise(name, s string) (string, bool) {
	switch name {
	case "":
		return s, true
	case NormaliserLSIO:
		if m := lsioLabel.FindStringSubmatch(s); m != nil {
			s = m[1]
		}
		if m := lsioSuffix.FindStringSubmatch(s); m != nil {
			s = m[1]
		}
		if m := lsioBase.FindStringSubmatch(s); m != nil {
			s = m[1]
		}
		return s, true
	default:
		return s, false
	}
}
