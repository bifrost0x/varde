// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/feed"
)

var now = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func do(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, &out, now)
	return out.String(), err
}

func must(t *testing.T, args ...string) string {
	t.Helper()
	out, err := do(t, args...)
	if err != nil {
		t.Fatalf("vardekeys %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// The whole ceremony: keys, the first root, a check, and a rotation that
// an installation trusting the first root accepts.
func TestCeremony(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	out := must(t, "keygen", "-out", p("root.key"))
	must(t, "keygen", "-out", p("feed.key"))

	// The private key is not printed, is private on disk and is not overwritten.
	priv, err := os.ReadFile(p("root.key"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Split(string(priv), "\n")[1]
	if strings.Contains(out, body) {
		t.Fatal("keygen printed the private key")
	}
	if fi, _ := os.Stat(p("root.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", fi.Mode().Perm())
	}
	if _, err := do(t, "keygen", "-out", p("root.key")); err == nil {
		t.Fatal("an existing key was overwritten")
	}

	summary := must(t, "root", "-version", "1", "-expires", "2028-11-11", "-sign", p("root.key"),
		"-root-pub", p("root.key.pub"), "-feed-pub", p("feed.key.pub"), "-out", p("production.json"))
	if !strings.Contains(summary, "trust root version 1, production, valid through 2028-11-11") || !strings.Contains(summary, "feed keys 1 (threshold 1)") {
		t.Fatalf("summary: %s", summary)
	}
	data, err := os.ReadFile(p("production.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := feed.VerifyRoot(data, now)
	if err != nil || first.Environment != feed.EnvProduction {
		t.Fatalf("root: %+v, %v", first, err)
	}
	if out := must(t, "check", "-root", p("production.json"), "-feed-pub", p("feed.key.pub")); !strings.Contains(out, "is a feed key of this root") {
		t.Fatalf("check: %s", out)
	}
	if _, err := do(t, "check", "-root", p("production.json"), "-feed-pub", p("root.key.pub")); err == nil {
		t.Fatal("a root key passed as a feed key")
	}

	// Nothing is overwritten: not a root, not a public key.
	if _, err := do(t, "root", "-version", "1", "-expires", "2028-11-11", "-sign", p("root.key"),
		"-root-pub", p("root.key.pub"), "-feed-pub", p("feed.key.pub"), "-out", p("production.json")); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("an existing root was overwritten: %v", err)
	}
	if err := os.Remove(p("feed.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := do(t, "keygen", "-out", p("feed.key")); err == nil || !strings.Contains(err.Error(), "feed.key.pub") {
		t.Fatalf("an existing public key was overwritten: %v", err)
	}

	// Rotation: a new feed key, signed by the root key the first root trusts.
	must(t, "keygen", "-out", p("feed2.key"))
	// A rotation names the root it follows, and is checked against it.
	if _, err := do(t, "root", "-version", "2", "-expires", "2029-11-11", "-sign", p("root.key"),
		"-root-pub", p("root.key.pub"), "-feed-pub", p("feed2.key.pub"), "-out", p("production2.json")); err == nil || !strings.Contains(err.Error(), "-previous") {
		t.Fatalf("a rotation without the root it follows: %v", err)
	}
	must(t, "keygen", "-out", p("stranger.key"))
	if _, err := do(t, "root", "-version", "2", "-expires", "2029-11-11", "-previous", p("production.json"), "-sign", p("stranger.key"),
		"-root-pub", p("stranger.key.pub"), "-feed-pub", p("feed2.key.pub"), "-out", p("production2.json")); err == nil || !strings.Contains(err.Error(), "not endorsed") {
		t.Fatalf("a rotation the last root does not endorse: %v", err)
	}
	if _, err := os.Stat(p("production2.json")); err == nil {
		t.Fatal("an unendorsed root was written")
	}
	if _, err := do(t, "root", "-version", "3", "-expires", "2029-11-11", "-previous", p("production.json"), "-sign", p("root.key"),
		"-root-pub", p("root.key.pub"), "-feed-pub", p("feed2.key.pub"), "-out", p("production2.json")); err == nil || !strings.Contains(err.Error(), "does not follow") {
		t.Fatalf("a rotation that skips a version: %v", err)
	}
	must(t, "root", "-version", "2", "-expires", "2029-11-11", "-previous", p("production.json"), "-sign", p("root.key"),
		"-root-pub", p("root.key.pub"), "-feed-pub", p("feed2.key.pub"), "-out", p("production2.json"))
	if out := must(t, "check", "-root", p("production2.json"), "-previous", p("production.json")); !strings.Contains(out, "follows trust root version 1") {
		t.Fatalf("check of a rotation: %s", out)
	}
	// Replacing the root key: signed by the old and by the new one.
	must(t, "root", "-version", "3", "-expires", "2030-11-11", "-previous", p("production2.json"), "-sign", p("root.key"), "-sign", p("stranger.key"),
		"-root-pub", p("stranger.key.pub"), "-feed-pub", p("feed2.key.pub"), "-out", p("production3.json"))
	data2, err := os.ReadFile(p("production2.json"))
	if err != nil {
		t.Fatal(err)
	}
	next, sigs, err := feed.ParseRoot(data2)
	if err != nil {
		t.Fatal(err)
	}
	if err := feed.VerifyRootUpdate(first, next, sigs, now); err != nil {
		t.Fatalf("an installation would refuse the rotation: %v", err)
	}
}

func TestRootMistakes(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	must(t, "keygen", "-out", p("root.key"))
	must(t, "keygen", "-out", p("other.key"))
	must(t, "keygen", "-out", p("feed.key"))
	base := []string{"root", "-version", "1", "-out", p("r.json"), "-feed-pub", p("feed.key.pub")}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"signed by a key the root does not list": {[]string{"-expires", "2028-11-11", "-sign", p("other.key"), "-root-pub", p("root.key.pub")}, "does not verify"},
		"expiry in the past":                     {[]string{"-expires", "2020-01-01", "-sign", p("root.key"), "-root-pub", p("root.key.pub")}, "in the past"},
		"a private key as public key":            {[]string{"-expires", "2028-11-11", "-sign", p("root.key"), "-root-pub", p("root.key")}, "is a private key"},
		"a public key as signing key":            {[]string{"-expires", "2028-11-11", "-sign", p("root.key.pub"), "-root-pub", p("root.key.pub")}, "is not PEM"},
		"nothing to sign with":                   {[]string{"-expires", "2028-11-11", "-root-pub", p("root.key.pub")}, "are required"},
	} {
		_, err := do(t, append(append([]string{}, base...), tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
		if _, statErr := os.Stat(p("r.json")); statErr == nil {
			t.Errorf("%s: a root was written", name)
			_ = os.Remove(p("r.json"))
		}
	}
}

func TestCheckRefusesADevelopmentRoot(t *testing.T) {
	rootKey, _ := feed.NewKey()
	feedKey, _ := feed.NewKey()
	data, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: now.Add(time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{feedKey.Public().(ed25519.PublicKey)}, RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dev.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := do(t, "check", "-root", path); err == nil || !strings.Contains(err.Error(), "only a production root may be embedded") {
		t.Fatalf("err = %v", err)
	}
}

// The expiry date was missed: the rotation that restores updates must
// still be possible. Installations accept a successor of an expired root.
func TestRotationFromAnExpiredRoot(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	must(t, "keygen", "-out", p("root.key"))
	must(t, "keygen", "-out", p("feed.key"))
	must(t, "root", "-version", "1", "-expires", "2026-12-01", "-sign", p("root.key"),
		"-root-pub", p("root.key.pub"), "-feed-pub", p("feed.key.pub"), "-out", p("r1.json"))
	later := now.Add(60 * 24 * time.Hour) // root 1 has expired
	var out bytes.Buffer
	args := []string{"root", "-version", "2", "-expires", "2028-11-11", "-previous", p("r1.json"), "-sign", p("root.key"),
		"-root-pub", p("root.key.pub"), "-feed-pub", p("feed.key.pub"), "-out", p("r2.json")}
	if err := run(args, &out, later); err != nil {
		t.Fatalf("rotation after the expiry: %v", err)
	}
	out.Reset()
	if err := run([]string{"check", "-root", p("r2.json"), "-previous", p("r1.json")}, &out, later); err != nil {
		t.Fatalf("check after the expiry: %v", err)
	}
	// What an installation does with it.
	d1, _ := os.ReadFile(p("r1.json"))
	d2, _ := os.ReadFile(p("r2.json"))
	first, _, err := feed.ParseRoot(d1)
	if err != nil {
		t.Fatal(err)
	}
	next, sigs, err := feed.ParseRoot(d2)
	if err != nil {
		t.Fatal(err)
	}
	if err := feed.VerifyRootUpdate(first, next, sigs, later); err != nil {
		t.Fatalf("an installation would refuse it: %v", err)
	}
}
