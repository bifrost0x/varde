// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// BinaryName is the file name of a platform's binary: varde-linux-amd64.
func BinaryName(platform string) string { return "varde-" + strings.ReplaceAll(platform, "/", "-") }

// Platforms are the agent binaries the server ships, by the file names of
// the release (varde-linux-amd64).
var Platforms = []string{"linux/amd64", "linux/arm64"}

// Binary is one agent binary the server ships.
type Binary struct {
	Platform string
	Path     string
	SHA256   string
	Size     int64
}

// Binaries are the agent binaries in one directory, hashed once at start.
type Binaries struct {
	byPlatform map[string]Binary
}

// LoadBinaries reads the agent binaries in dir. A missing directory or
// platform is no error: agents for it are then neither installed nor
// updated by the server.
func LoadBinaries(dir string) (*Binaries, error) {
	b := &Binaries{byPlatform: map[string]Binary{}}
	for _, p := range Platforms {
		path := filepath.Join(dir, BinaryName(p))
		fi, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("agent binary %s: %w", path, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("agent binary %s is not a regular file", path)
		}
		sum, err := hashFile(path)
		if err != nil {
			return nil, err
		}
		b.byPlatform[p] = Binary{Platform: p, Path: path, SHA256: sum, Size: fi.Size()}
	}
	return b, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // configured binary directory
	if err != nil {
		return "", fmt.Errorf("read agent binary: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash agent binary %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// For returns the binary for a platform ("linux/amd64").
func (b *Binaries) For(platform string) (Binary, bool) {
	if b == nil {
		return Binary{}, false
	}
	bin, ok := b.byPlatform[platform]
	return bin, ok
}

// Available lists the platforms with a binary.
func (b *Binaries) Available() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.byPlatform))
	for p := range b.byPlatform {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
