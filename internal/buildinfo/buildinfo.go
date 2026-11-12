// SPDX-License-Identifier: Apache-2.0

// Package buildinfo holds the product identity and build metadata. It is the
// single place in Go code where the product name, identifier and repository
// URL are defined.
package buildinfo

const (
	// Product is the product name used in prose and UI.
	Product = "Varde"
	// ID is the lowercase identifier used for binaries, images and labels.
	ID = "varde"
	// EnvPrefix prefixes every environment variable read by the binary.
	EnvPrefix = "VARDE_"
	// LabelPrefix prefixes every container label interpreted by the binary.
	LabelPrefix = "varde."
	// RepoURL is the canonical source repository.
	RepoURL = "https://github.com/bifrost0x/varde"
)

// Set at link time via -ldflags "-X github.com/bifrost0x/varde/internal/buildinfo.Version=...".
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// UserAgent returns the User-Agent for all outbound HTTP requests. It must
// never carry user- or installation-specific data.
func UserAgent() string {
	return ID + "/" + Version + " (+" + RepoURL + ")"
}
