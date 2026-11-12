// SPDX-License-Identifier: Apache-2.0

// Package auth implements password hashing, sessions, CSRF protection,
// API tokens and login throttling for the web UI and API.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: RFC 9106 section 4, second recommended option
// (t=3, m=64 MiB, p=4). Stored with every hash, so they can be raised
// later without invalidating existing passwords.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16

	// MinPasswordLength follows NIST SP 800-63B: length, no composition
	// rules.
	MinPasswordLength = 12
	// maxPasswordBytes bounds hashing work for oversized inputs.
	maxPasswordBytes = 256
)

// hashSlots bounds concurrent hashing so that login bursts cannot exhaust
// memory (each hash allocates 64 MiB). A request waits at most hashWait for
// a slot, so a flood cannot build an unbounded queue.
var hashSlots = make(chan struct{}, 1)

var hashWait = 3 * time.Second // variable for tests

// ErrBusy reports that no hashing slot became free in time.
var ErrBusy = errors.New("password hashing busy")

// ErrWeakPassword is returned for passwords outside the accepted length.
var ErrWeakPassword = fmt.Errorf("password must be %d to %d characters", MinPasswordLength, maxPasswordBytes)

// ValidatePassword checks length only (NIST SP 800-63B).
func ValidatePassword(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLength || len(pw) > maxPasswordBytes || !utf8.ValidString(pw) {
		return ErrWeakPassword
	}
	return nil
}

// HashPassword returns an encoded argon2id hash in PHC string format.
func HashPassword(ctx context.Context, pw string) (string, error) {
	if err := ValidatePassword(pw); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key, err := derive(ctx, []byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	if err != nil {
		return "", err
	}
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// ErrMismatch is returned when a password does not match.
var ErrMismatch = errors.New("password does not match")

// VerifyPassword checks pw against an encoded hash in constant time.
func VerifyPassword(ctx context.Context, pw, encoded string) error {
	if len(pw) > maxPasswordBytes {
		return ErrMismatch
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return errors.New("unsupported password hash format")
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return fmt.Errorf("parse hash parameters: %w", err)
	}
	if m == 0 || m > 1024*1024 || t == 0 || t > 16 || p == 0 {
		return errors.New("password hash parameters out of range")
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return errors.New("decode hash: invalid")
	}
	got, err := derive(ctx, []byte(pw), salt, t, m, p, uint32(len(want))) //nolint:gosec // bounded above
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

func derive(ctx context.Context, pw, salt []byte, t, m uint32, p uint8, keyLen uint32) ([]byte, error) {
	timer := time.NewTimer(hashWait)
	defer timer.Stop()
	select {
	case hashSlots <- struct{}{}:
	case <-timer.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-hashSlots }()
	return argon2.IDKey(pw, salt, t, m, p, keyLen), nil
}

// dummyHash is verified against for unknown users so that response times
// do not reveal whether an account exists.
var dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$Qmh7cHVp0d7bAOv4FbAFNrCGCV2c2V8bNh6TzLqY0wQ"

// VerifyDummy spends the same work as a real verification.
func VerifyDummy(ctx context.Context, pw string) {
	_ = VerifyPassword(ctx, pw, dummyHash)
}

// RandomToken returns n random bytes as unpadded base64url.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the hex SHA-256 of a bearer secret (session IDs, API
// tokens, setup tokens). These secrets have 256 bits of entropy, so a fast
// hash is appropriate.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// EqualTokens compares two secrets in constant time.
func EqualTokens(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
