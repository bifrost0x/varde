// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Box encrypts integration credentials at rest with AES-256-GCM. The key
// lives in its own file next to the database, so a copy of the database
// alone (a backup, an export) does not reveal API tokens.
type Box struct {
	aead cipher.AEAD
}

// OpenBox loads the key from path, creating it (mode 0600) on first use.
func OpenBox(path string) (*Box, error) {
	key, err := os.ReadFile(path) //nolint:gosec // path from configuration
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate secret key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create key directory: %w", err)
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, fmt.Errorf("write secret key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("read secret key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secret key %s has %d bytes, want 32", path, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext; id binds the ciphertext to one integration so it
// cannot be moved to another row.
func (b *Box) Seal(id string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, []byte(id)), nil
}

// Open decrypts a value sealed for id.
func (b *Box) Open(id string, sealed []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed secret too short")
	}
	out, err := b.aead.Open(nil, sealed[:n], sealed[n:], []byte(id))
	if err != nil {
		return nil, errors.New("secret cannot be decrypted (wrong key or tampered)")
	}
	return out, nil
}
