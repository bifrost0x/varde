// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type licenseFixture struct {
	now        time.Time
	root       *Root
	licenseKey ed25519.PrivateKey
	feedKey    ed25519.PrivateKey
}

func newLicenseFixture(t *testing.T, notBefore, notAfter *time.Time) *licenseFixture {
	t.Helper()
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	rk, _ := NewKey()
	fk, _ := NewKey()
	lk, _ := NewKey()
	data, err := SignRoot(RootSpec{Version: 1, Expires: now.Add(365 * 24 * time.Hour), Environment: EnvDevelopment,
		RootKeys: []ed25519.PublicKey{pub(rk)}, FeedKeys: []ed25519.PublicKey{pub(fk)}, LicenseKeys: []ed25519.PublicKey{pub(lk)},
		LicenseNotBefore: notBefore, LicenseNotAfter: notAfter, RootThreshold: 1, FeedThreshold: 1}, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := ParseRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	return &licenseFixture{now: now, root: root, licenseKey: lk, feedKey: fk}
}

func (f *licenseFixture) license() License {
	return License{ID: "lic_0123456789abcdefABCDEF", Plan: "uplink", NotBefore: f.now.Add(-time.Hour), ExpiresAt: f.now.Add(30 * 24 * time.Hour)}
}

func (f *licenseFixture) issue(t *testing.T, l License, key ed25519.PrivateKey) []byte {
	t.Helper()
	doc, err := IssueLicense(l, key)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestLicenseValid(t *testing.T) {
	f := newLicenseFixture(t, nil, nil)
	doc := f.issue(t, f.license(), f.licenseKey)
	l, err := f.root.VerifyLicense(doc, f.now)
	if err != nil {
		t.Fatalf("valid license refused: %v", err)
	}
	if l.ID != "lic_0123456789abcdefABCDEF" || !l.ExpiresAt.Equal(f.now.Add(30*24*time.Hour)) || l.KeyID != KeyID(pub(f.licenseKey)) {
		t.Errorf("license = %+v", l)
	}
}

func TestParseLicenseForms(t *testing.T) {
	f := newLicenseFixture(t, nil, nil)
	doc := f.issue(t, f.license(), f.licenseKey)
	std := base64.StdEncoding.EncodeToString(doc)
	wrapped := std[:40] + "\r\n" + std[40:90] + "\n" + std[90:]
	for name, in := range map[string][]byte{
		"json":            doc,
		"json whitespace": []byte("\n  " + string(doc) + " \r\n"),
		"base64":          []byte(std),
		"base64 url":      []byte(base64.RawURLEncoding.EncodeToString(doc)),
		"base64 wrapped":  []byte("  " + wrapped + "\n"),
	} {
		l, canon, err := ParseLicense(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(canon) != string(doc) || l.ID != "lic_0123456789abcdefABCDEF" {
			t.Errorf("%s: canonical bytes or license differ", name)
		}
		if _, err := f.root.VerifyLicense(canon, f.now); err != nil {
			t.Errorf("%s: canonical form does not verify: %v", name, err)
		}
	}
	if _, _, err := ParseLicense([]byte(strings.Repeat("A", MaxLicenseBytes+1))); !errors.Is(err, ErrLicense) {
		t.Errorf("oversized input: %v", err)
	}
	for _, in := range []string{"", "   ", "not a license", "{}", `{"signed":{},"signature":""}`} {
		if _, _, err := ParseLicense([]byte(in)); !errors.Is(err, ErrLicense) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestLicenseRefused(t *testing.T) {
	f := newLicenseFixture(t, nil, nil)
	other, _ := NewKey()
	tamper := func(doc []byte) []byte {
		var env map[string]json.RawMessage
		_ = json.Unmarshal(doc, &env)
		env["signed"] = json.RawMessage(strings.Replace(string(env["signed"]), "uplink", "uplinK", 1))
		out, _ := json.Marshal(env)
		return out
	}
	withField := func() []byte {
		signed := []byte(`{"license":"lic_0123456789abcdefABCDEF","plan":"uplink","not_before":"2026-11-11T00:00:00Z","expires_at":"2026-12-11T00:00:00Z","key_id":"` +
			KeyID(pub(f.licenseKey)) + `","customer":"x"}`)
		out, _ := json.Marshal(map[string]any{"signed": json.RawMessage(signed),
			"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(f.licenseKey, signed))})
		return out
	}
	mod := func(m func(*License)) License { l := f.license(); m(&l); return l }
	for name, tc := range map[string]struct {
		doc  []byte
		want error
	}{
		"key not in root": {f.issue(t, f.license(), other), ErrSignature},
		"feed key":        {f.issue(t, f.license(), f.feedKey), ErrSignature},
		"tampered":        {tamper(f.issue(t, f.license(), f.licenseKey)), ErrSignature},
		"unknown field":   {withField(), ErrLicense},
		"bad id":          {f.issue(t, mod(func(l *License) { l.ID = "abc" }), f.licenseKey), ErrLicense},
		"other plan":      {f.issue(t, mod(func(l *License) { l.Plan = "pro" }), f.licenseKey), ErrLicense},
		"expired":         {f.issue(t, mod(func(l *License) { l.ExpiresAt = f.now.Add(-time.Minute) }), f.licenseKey), ErrExpired},
		"not yet valid":   {f.issue(t, mod(func(l *License) { l.NotBefore = f.now.Add(2 * time.Hour) }), f.licenseKey), ErrLicense},
	} {
		if _, err := f.root.VerifyLicense(tc.doc, f.now); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	// Half an hour of clock difference is tolerated.
	soon := f.issue(t, mod(func(l *License) { l.NotBefore = f.now.Add(30 * time.Minute) }), f.licenseKey)
	if _, err := f.root.VerifyLicense(soon, f.now); err != nil {
		t.Errorf("license valid in 30 minutes refused: %v", err)
	}
}

func TestLicenseKeyWindow(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ended := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	f := newLicenseFixture(t, &past, &ended)
	if _, err := f.root.VerifyLicense(f.issue(t, f.license(), f.licenseKey), f.now); !errors.Is(err, ErrSignature) {
		t.Errorf("license signed by a key outside its window: %v", err)
	}
}
