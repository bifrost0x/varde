// SPDX-License-Identifier: Apache-2.0

// Command vardekeys makes the keys and the trust root of the data package
// (docs/data-package.md). It is run by the maintainer on a machine that is
// offline, never in CI and never in an installation; it makes no network
// requests.
//
//	vardekeys keygen -out root.key        # a private key and root.key.pub
//	vardekeys root -version 1 -expires 2028-11-11 \
//	    -sign root.key -root-pub root.key.pub -feed-pub feed.key.pub \
//	    -out production.json                # the signed production root
//	vardekeys check -root production.json -feed-pub feed.key.pub
//
// A rotation (version 2 and later) names the root it follows with
// -previous and is refused unless installations trusting that root would
// accept it. No file is ever overwritten.
//
// Private keys are written with mode 0600 and never printed.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/feed"
)

func main() {
	err := run(os.Args[1:], os.Stdout, time.Now())
	if errors.Is(err, errUsage) {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vardekeys:", err)
		os.Exit(1)
	}
}

const usage = `usage: vardekeys <command> [flags]

  keygen -out <file>     write a new Ed25519 private key (PEM) and <file>.pub
  root   ...             sign a production trust root from public keys
  check  -root <file>    verify a trust root and say what it trusts

Run "vardekeys <command> -h" for the flags.`

// errUsage asks for the usage text; main prints it.
var errUsage = errors.New("unknown or missing command")

func run(args []string, out io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], out)
	case "root":
		return signRoot(args[1:], out, now)
	case "check":
		return check(args[1:], out, now)
	default:
		return errUsage
	}
}

// multi collects a repeated flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func keygen(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := fs.String("out", "", "file for the private key; the public key goes to <file>.pub (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("keygen: -out is required")
	}
	priv, err := feed.NewKey()
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	// Neither file is ever overwritten.
	if _, err := os.Lstat(*path + ".pub"); err == nil {
		return fmt.Errorf("keygen: %s.pub exists", *path)
	}
	f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if err := writeNew(*path+".pub", []byte(pub+"\n")); err != nil {
		// The private key just written has no public half on disk: take
		// it back rather than leave a key nobody can name.
		_ = os.Remove(*path)
		return fmt.Errorf("keygen: %w", err)
	}
	_, err = fmt.Fprintf(out, "private key: %s (keep it secret)\npublic key:  %s.pub\n%s\n", *path, *path, pub)
	return err
}

// writeNew writes a public file and refuses to replace an existing one.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // public material
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// checkStep verifies that an installation trusting the root in previous
// accepts data as the next root.
func checkStep(previous string, data []byte, now time.Time) (*feed.Root, error) {
	prevData, err := os.ReadFile(previous) //nolint:gosec // path given by the maintainer
	if err != nil {
		return nil, err
	}
	// The previous root has to hold by itself, but need not be current:
	// a rotation after a missed expiry is how updates come back, and an
	// installation accepts the successor of an expired root.
	parsed, _, err := feed.ParseRoot(prevData)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", previous, err)
	}
	prev, err := feed.VerifyRoot(prevData, parsed.Expires.Add(-time.Second))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", previous, err)
	}
	next, sigs, err := feed.ParseRoot(data)
	if err != nil {
		return nil, err
	}
	if err := feed.VerifyRootUpdate(prev, next, sigs, now); err != nil {
		return nil, fmt.Errorf("installations that trust %s would refuse this root: %w", previous, err)
	}
	return prev, nil
}

func readPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path given by the maintainer
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a PKCS#8 private key", path)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return priv, nil
}

func readPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path given by the maintainer
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(data), "PRIVATE KEY") {
		return nil, fmt.Errorf("%s is a private key; give the .pub file", path)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is not an Ed25519 public key (base64)", path)
	}
	return ed25519.PublicKey(raw), nil
}

func readPublics(paths []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, p := range paths {
		k, err := readPublic(p)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func signRoot(args []string, out io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("root", flag.ContinueOnError)
	version := fs.Int64("version", 0, "version of the root: 1 for the first, the last one plus 1 for a rotation (required)")
	expires := fs.String("expires", "", "last day the root is valid, YYYY-MM-DD (required)")
	path := fs.String("out", "", "file for the signed root (required, must not exist)")
	previous := fs.String("previous", "", "the root this one follows; required from version 2 on")
	var signKeys, rootPubs, feedPubs, licensePubs multi
	fs.Var(&signKeys, "sign", "private root key that signs; repeat. A rotation is signed by a key of the last root and by the new ones")
	fs.Var(&rootPubs, "root-pub", "public root key the root trusts; repeat")
	fs.Var(&feedPubs, "feed-pub", "public feed key the root trusts; repeat")
	fs.Var(&licensePubs, "license-pub", "public license key the root trusts (uplink); repeat")
	rootThreshold := fs.Int("root-threshold", 1, "how many root keys must sign the next root")
	feedThreshold := fs.Int("feed-threshold", 1, "how many feed keys must sign a package")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version < 1 || *expires == "" || *path == "" || len(signKeys) == 0 || len(rootPubs) == 0 || len(feedPubs) == 0 {
		return errors.New("root: -version, -expires, -out, -sign, -root-pub and -feed-pub are required")
	}
	if *version > 1 && *previous == "" {
		return errors.New("root: a rotation needs -previous, the root it follows, so that it can be checked against it")
	}
	if _, err := os.Lstat(*path); err == nil {
		return fmt.Errorf("root: %s exists; a root is never overwritten", *path)
	}
	day, err := time.Parse("2006-01-02", *expires)
	if err != nil {
		return fmt.Errorf("root: -expires: %w", err)
	}
	until := day.Add(24 * time.Hour).UTC()
	if !until.After(now) {
		return errors.New("root: -expires lies in the past")
	}
	spec := feed.RootSpec{Version: *version, Expires: until, Environment: feed.EnvProduction, RootThreshold: *rootThreshold, FeedThreshold: *feedThreshold}
	if spec.RootKeys, err = readPublics(rootPubs); err != nil {
		return err
	}
	if spec.FeedKeys, err = readPublics(feedPubs); err != nil {
		return err
	}
	if spec.LicenseKeys, err = readPublics(licensePubs); err != nil {
		return err
	}
	var signers []ed25519.PrivateKey
	for _, p := range signKeys {
		k, err := readPrivate(p)
		if err != nil {
			return err
		}
		signers = append(signers, k)
	}
	data, err := feed.SignRoot(spec, signers...)
	if err != nil {
		return err
	}
	// A root that does not hold by itself is a mistake in the flags (a
	// signing key that is not among -root-pub, a threshold not met).
	if _, err := feed.VerifyRoot(data, now); err != nil {
		return fmt.Errorf("root: the result does not verify: %w; check that every -root-pub has its -sign key and that the thresholds can be met", err)
	}
	if *previous != "" {
		if _, err := checkStep(*previous, data, now); err != nil {
			return fmt.Errorf("root: %w; a rotation is signed by a root key of the last root and by every new root key", err)
		}
	}
	if err := writeNew(*path, data); err != nil {
		return fmt.Errorf("root: %w", err)
	}
	return describe(out, *path, data, now)
}

func describe(out io.Writer, path string, data []byte, now time.Time) error {
	root, err := feed.VerifyRoot(data, now)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s: trust root version %d, %s, valid through %s\n  root keys %d (threshold %d), feed keys %d (threshold %d), license keys %d\n",
		path, root.Version, root.Environment, root.Expires.Add(-time.Second).UTC().Format("2006-01-02"),
		root.KeyCount(feed.RoleRoot, now), root.Thresholds.Root, root.KeyCount(feed.RoleFeed, now), root.Thresholds.Feed, root.KeyCount(feed.RoleLicense, now))
	return err
}

func check(args []string, out io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("root", "", "trust root to check (required)")
	feedPub := fs.String("feed-pub", "", "also check that this public key is a feed key of the root")
	previous := fs.String("previous", "", "also check that installations trusting this earlier root accept the root as the next one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("check: -root is required")
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	if err := describe(out, *path, data, now); err != nil {
		return fmt.Errorf("check: %w", err)
	}
	root, _, err := feed.ParseRoot(data)
	if err != nil {
		return err
	}
	if root.Environment != feed.EnvProduction {
		return fmt.Errorf("check: %s is a %s root; only a production root may be embedded", *path, root.Environment)
	}
	if root.Version > 1 && *previous == "" {
		return fmt.Errorf("check: version %d is a rotation; give -previous, the root it follows", root.Version)
	}
	if *previous != "" {
		prev, err := checkStep(*previous, data, now)
		if err != nil {
			return fmt.Errorf("check: %w", err)
		}
		if _, err := fmt.Fprintf(out, "  follows trust root version %d: installations that trust it accept this root\n", prev.Version); err != nil {
			return err
		}
	}
	if *feedPub != "" {
		pub, err := readPublic(*feedPub)
		if err != nil {
			return err
		}
		if !root.HasFeedKey(pub, now) {
			return fmt.Errorf("check: %s is not a feed key of this root", *feedPub)
		}
		_, err = fmt.Fprintf(out, "  %s is a feed key of this root\n", *feedPub)
		return err
	}
	return nil
}
