// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// License is an uplink license (docs/feed-architecture.md 5.1): a small
// document signed by a key of role "license" in the trust root. It names no
// customer; Varde verifies it offline.
type License struct {
	ID        string    `json:"license"`
	Plan      string    `json:"plan"`
	NotBefore time.Time `json:"not_before"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyID     string    `json:"key_id"`
}

// PlanUplink is the only plan there is.
const PlanUplink = "uplink"

// MaxLicenseBytes bounds what is accepted as a license, in any form.
const MaxLicenseBytes = 16 << 10

// licenseClockTolerance accepts a license whose validity starts shortly
// after the local clock's time.
const licenseClockTolerance = time.Hour

// ErrLicense reports a license that is malformed or does not apply.
var ErrLicense = errors.New("license not valid")

var licenseID = regexp.MustCompile(`^lic_[A-Za-z0-9]{16,64}$`)

type licenseEnvelope struct {
	Signed    json.RawMessage `json:"signed"`
	Signature string          `json:"signature"`
}

// ParseLicense reads a license as its JSON document or as the base64 of
// it (standard or URL alphabet, padded or not, line breaks allowed), as a
// user would paste it. It returns the license and the JSON document, which
// is what gets stored and sent. The signature is not checked here; see
// (*Root).VerifyLicense.
func ParseLicense(input []byte) (*License, []byte, error) {
	if len(input) > MaxLicenseBytes {
		return nil, nil, fmt.Errorf("%w: larger than %d bytes", ErrLicense, MaxLicenseBytes)
	}
	doc := bytes.TrimSpace(input)
	if len(doc) == 0 {
		return nil, nil, fmt.Errorf("%w: empty", ErrLicense)
	}
	if doc[0] != '{' {
		compact := strings.Join(strings.Fields(string(doc)), "")
		var decoded []byte
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(compact); err == nil {
				decoded = bytes.TrimSpace(b)
				break
			}
		}
		if len(decoded) == 0 || decoded[0] != '{' {
			return nil, nil, fmt.Errorf("%w: neither a license document nor its base64 form", ErrLicense)
		}
		doc = decoded
	}
	l, _, _, err := decodeLicense(doc)
	if err != nil {
		return nil, nil, err
	}
	return l, doc, nil
}

func decodeLicense(doc []byte) (*License, []byte, []byte, error) {
	var env licenseEnvelope
	if err := decodeStrict(doc, &env); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", ErrLicense, err)
	}
	var l License
	if err := decodeStrict(env.Signed, &l); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", ErrLicense, err)
	}
	if !licenseID.MatchString(l.ID) {
		return nil, nil, nil, fmt.Errorf("%w: malformed license ID", ErrLicense)
	}
	if !hexHash.MatchString(l.KeyID) {
		return nil, nil, nil, fmt.Errorf("%w: malformed key ID", ErrLicense)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, nil, fmt.Errorf("%w: malformed signature", ErrLicense)
	}
	return &l, env.Signed, sig, nil
}

// VerifyLicense checks a license document against the license keys of the
// root that are valid at now, then its plan and its validity period.
func (r *Root) VerifyLicense(doc []byte, now time.Time) (*License, error) {
	l, signed, sig, err := decodeLicense(doc)
	if err != nil {
		return nil, err
	}
	k, ok := r.Keys[l.KeyID]
	if !ok || k.Role != RoleLicense || !k.validAt(now) || !ed25519.Verify(k.pub, signed, sig) {
		return nil, fmt.Errorf("license %s: %w", l.ID, ErrSignature)
	}
	if l.Plan != PlanUplink {
		return nil, fmt.Errorf("%w: unknown plan %q", ErrLicense, l.Plan)
	}
	if !l.ExpiresAt.After(l.NotBefore) {
		return nil, fmt.Errorf("%w: expires before it starts", ErrLicense)
	}
	if now.Add(licenseClockTolerance).Before(l.NotBefore) {
		return nil, fmt.Errorf("%w: valid from %s; check the clock", ErrLicense, l.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(l.ExpiresAt) {
		return nil, fmt.Errorf("license %s expired at %s: %w", l.ID, l.ExpiresAt.Format(time.RFC3339), ErrExpired)
	}
	return l, nil
}

// VerifyLicense checks a license against the trust root the client holds
// now, so a rotated license key takes effect with the next root.
func (c *Client) VerifyLicense(doc []byte, now time.Time) (*License, error) {
	root, err := c.trusted()
	if err != nil {
		return nil, err
	}
	return root.VerifyLicense(doc, now)
}
