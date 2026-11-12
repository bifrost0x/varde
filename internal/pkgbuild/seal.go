// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/fsutil"
)

// The builder keeps two files on the published branch for its next run:
// its store and the counts of the package. More people and tokens can
// write that branch than can sign a package, and a store someone else
// wrote would be signed into the next package as if the builder had
// fetched it. So the builder signs both with the feed key and uses them
// only when the signature holds; otherwise it starts cold.

// sealSuffix names the signature file beside a sealed file.
const sealSuffix = ".sig"

// maxSealed bounds a sealed file (the store of all advisories).
const maxSealed = 1 << 30

func sealMessage(purpose string, data []byte) []byte {
	sum := sha256.Sum256(data)
	return []byte("varde-builder/" + purpose + "\n" + hex.EncodeToString(sum[:]) + "\n")
}

// ReadRegular reads path only if it is a regular file: a symlink on the
// published branch could point at anything the builder can read.
func ReadRegular(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxSealed {
		return nil, fmt.Errorf("%s is larger than allowed", path)
	}
	return os.ReadFile(path) //nolint:gosec // checked above
}

// Seal signs the file at path for purpose and writes the signature beside
// it (<path>.sig).
func Seal(path, purpose string, key ed25519.PrivateKey) error {
	data, err := ReadRegular(path)
	if err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, sealMessage(purpose, data)))
	return fsutil.WriteFileAtomic(path+sealSuffix, []byte(sig+"\n"), 0o644)
}

// ErrNotSealed reports a file without a valid signature of a feed key.
var ErrNotSealed = errors.New("not signed by a feed key of the trust root")

// Verify checks that the file at path was sealed for purpose by a feed key
// of root that is valid at now.
func Verify(path, purpose string, root *feed.Root, now time.Time) error {
	data, err := ReadRegular(path)
	if err != nil {
		return err
	}
	raw, err := ReadRegular(path + sealSuffix)
	if err != nil {
		return fmt.Errorf("%s: %w", path, ErrNotSealed)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || !root.SignedByFeedKey(sealMessage(purpose, data), sig, now) {
		return fmt.Errorf("%s: %w", path, ErrNotSealed)
	}
	return nil
}
