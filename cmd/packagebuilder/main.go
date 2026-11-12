// SPDX-License-Identifier: Apache-2.0

// Command packagebuilder builds the daily data package (ADR 0039,
// docs/data-package.md): it collects the advisories of every repository
// the catalog and the first-party index know, the KEV list and EPSS
// scores, refuses a build that looks broken, signs the package and checks
// the result with the client an installation uses. The daily workflow
// runs it; it is not part of the server.
//
//	VARDE_FEED_KEY="$(cat feed.key)" go run ./cmd/packagebuilder \
//	    -db cache/builder.db -previous published/feed -out work/feed
//
// The private feed key is read from the environment variable
// VARDE_FEED_KEY (PEM, PKCS#8, Ed25519). It is never written or printed.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/index"
	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/pkgbuild"
	"github.com/bifrost0x/varde/internal/store"
)

type config struct {
	db, out, previous, root, catalogDir string
	valid, maxWait                      time.Duration
	force                               bool
	allowDevelopment                    bool
	githubURL, kevURL, epssURL          string
	// http, now and table are replaced in tests.
	http  *httpx.Client
	now   func() time.Time
	table *applists.Table
}

func main() {
	var c config
	flag.StringVar(&c.db, "db", "", "the builder's store: advisories and request state kept between builds (required)")
	flag.StringVar(&c.out, "out", "", "directory to write the package to (required, must not hold a package)")
	flag.StringVar(&c.previous, "previous", "", "directory of the package published before, for the shrink check")
	flag.StringVar(&c.root, "root", "", "trust root to publish with the package (default: the root built into this binary)")
	flag.StringVar(&c.catalogDir, "catalog", "", "catalog directory (default: the built-in catalog)")
	flag.DurationVar(&c.valid, "valid", 7*24*time.Hour, "how long the package is valid")
	flag.DurationVar(&c.maxWait, "max-wait", 5*time.Hour, "longest total wait for GitHub's rate limit to reset")
	flag.BoolVar(&c.force, "force", false, "sign although the package shrank a lot (after checking why)")
	flag.BoolVar(&c.allowDevelopment, "allow-development-root", false, "build under a development root (tests only; installations refuse such a package)")
	flag.StringVar(&c.githubURL, "github-url", "", "GitHub API endpoint (tests)")
	flag.StringVar(&c.kevURL, "kev-url", "", "KEV endpoint (tests)")
	flag.StringVar(&c.epssURL, "epss-url", "", "EPSS endpoint (tests)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, c, os.Getenv, os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "packagebuilder:", err)
		os.Exit(1)
	}
}

// parseKey reads the private feed key. Its errors never repeat the input.
func parseKey(input string) (ed25519.PrivateKey, error) {
	if input == "" {
		return nil, errors.New("VARDE_FEED_KEY is not set: the private feed key (PEM, PKCS#8, Ed25519) is needed to sign the package")
	}
	block, _ := pem.Decode([]byte(input))
	if block == nil {
		return nil, errors.New("VARDE_FEED_KEY is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("VARDE_FEED_KEY is not a PKCS#8 private key")
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("VARDE_FEED_KEY is not an Ed25519 key")
	}
	return priv, nil
}

func run(ctx context.Context, c config, env func(string) string, out io.Writer) error {
	if c.db == "" || c.out == "" {
		return errors.New("-db and -out are required")
	}
	if c.now == nil {
		c.now = time.Now
	}
	now := c.now().UTC()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Everything that can be wrong without asking anyone comes first.
	key, err := parseKey(env("VARDE_FEED_KEY"))
	if err != nil {
		return err
	}
	rootData := feed.EmbeddedRoot()
	if c.root != "" {
		if rootData, err = os.ReadFile(c.root); err != nil {
			return fmt.Errorf("read the trust root: %w", err)
		}
	}
	if len(rootData) == 0 {
		return errors.New("no production root embedded: run the key ceremony (docs/data-package.md)")
	}
	root, _, err := feed.ParseRoot(rootData)
	if err != nil {
		return fmt.Errorf("trust root: %w", err)
	}
	if root.Environment != feed.EnvProduction && !c.allowDevelopment {
		return fmt.Errorf("trust root version %d is a %s root: installations refuse it, and a published mirror with it stops them all (-allow-development-root for tests)", root.Version, root.Environment)
	}
	if !now.Before(root.Expires) {
		return fmt.Errorf("trust root version %d expired on %s", root.Version, root.Expires.Format("2006-01-02"))
	}
	if !root.HasFeedKey(key.Public().(ed25519.PublicKey), now) {
		return fmt.Errorf("VARDE_FEED_KEY is not a feed key of trust root version %d: an installation would refuse the package", root.Version)
	}
	if _, err := os.Stat(filepath.Join(c.out, "v1", "manifest.json")); err == nil {
		return fmt.Errorf("%s already holds a package; write to an empty directory", c.out)
	}
	if entries, err := os.ReadDir(c.out); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty; the package replaces the directory it is written to", c.out)
	}
	if err := checkRootChain(c.previous, root, rootData, now); err != nil {
		return err
	}
	previous, havePrevious, err := baseline(c.previous, root, now, c.force, logger)
	if err != nil {
		return err
	}
	// The store comes back from the published branch. Unless the feed key
	// signed it, it is someone else's: start cold rather than sign it.
	if _, err := os.Lstat(c.db); err == nil {
		if err := pkgbuild.Verify(c.db, pkgbuild.PurposeStore, root, now); err != nil {
			logger.Warn("the builder's store is not signed by a feed key; starting without it", "err", err)
			for _, f := range []string{c.db, c.db + ".sig", c.db + "-wal", c.db + "-shm"} {
				if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
	}

	builtin := catalogdata.FS()
	if c.catalogDir != "" {
		builtin = os.DirFS(c.catalogDir)
	}
	entries, err := catalog.ReadEntries(builtin)
	if err != nil {
		return fmt.Errorf("catalog: %w", err)
	}
	cat, err := catalog.Build(entries, catalog.OriginBuiltin, nil)
	if err != nil {
		return fmt.Errorf("catalog: %w", err)
	}
	table := c.table
	if table == nil {
		if table, err = index.Table(); err != nil {
			return fmt.Errorf("index: %w", err)
		}
	}
	repos, err := pkgbuild.Repos(cat, table)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(c.db), 0o755); err != nil { //nolint:gosec // published beside the package
		return err
	}
	st, err := store.Open(ctx, c.db)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = st.Close()
		}
	}()
	hc := c.http
	if hc == nil {
		hc = httpx.New(httpx.Options{})
	}
	stats, err := pkgbuild.Collect(ctx, repos, pkgbuild.Options{Store: st, HTTP: hc, Token: env("GITHUB_TOKEN"),
		GitHubURL: c.githubURL, KEVURL: c.kevURL, EPSSURL: c.epssURL, Now: c.now, MaxWait: c.maxWait, Log: logger})
	if err != nil {
		return err
	}
	snap, err := pkgbuild.Snapshot(ctx, st, entries, table, repos, now, c.valid)
	if err != nil {
		return err
	}
	counts := pkgbuild.CountsOf(snap, table.Len())
	if err := pkgbuild.Guard(stats, previous, havePrevious, counts, c.force); err != nil {
		return err
	}

	// Written to a directory of its own first: a package that does not
	// pass the client must not be left where the workflow publishes from.
	parent := filepath.Dir(filepath.Clean(c.out))
	if err := os.MkdirAll(parent, 0o755); err != nil { //nolint:gosec // published layout
		return err
	}
	staging, err := os.MkdirTemp(parent, ".package-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	// The earlier roots first: the branch is replaced with every build, and
	// an installation that missed a rotation needs each step of the chain.
	if err := carryRoots(c.previous, staging); err != nil {
		return err
	}
	if err := feed.WriteRoot(staging, root.Version, rootData); err != nil {
		return err
	}
	if _, err := feed.WriteSnapshot(staging, snap, key); err != nil {
		return err
	}
	if err := pkgbuild.WriteCounts(staging, counts); err != nil {
		return err
	}
	if err := pkgbuild.Seal(pkgbuild.CountsPath(staging), pkgbuild.PurposeCounts, key); err != nil {
		return err
	}
	if err := verify(ctx, staging, rootData, root, now); err != nil {
		return fmt.Errorf("the built package does not pass the client: %w", err)
	}
	// The store is signed as it lies on disk, so after it is closed.
	closed = true
	if err := st.Close(); err != nil {
		return err
	}
	if err := pkgbuild.Seal(c.db, pkgbuild.PurposeStore, key); err != nil {
		return err
	}
	if err := os.Remove(c.out); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err // only an empty directory is replaced
	}
	if err := os.Rename(staging, c.out); err != nil {
		return err
	}
	if err := os.Chmod(c.out, 0o755); err != nil { //nolint:gosec // published layout
		return err
	}
	if _, err = fmt.Fprintf(out, "package %d: %d repositories (%d failed), %d advisories, %d KEV, %d EPSS, %d index rows; %d requests, %d waits\n",
		counts.Sequence, stats.Repos, stats.Failed, counts.Advisories, counts.KEV, counts.EPSS, counts.Index, stats.Requests, stats.Waits); err != nil {
		return err
	}
	// What is published for a failing repository is as old as its last
	// successful read: say so where the maintainer looks.
	for _, f := range stats.Failing {
		if _, err := fmt.Fprintln(out, "failing:", f); err != nil {
			return err
		}
	}
	if root.Environment != feed.EnvProduction {
		if _, err := fmt.Fprintf(out, "built under a DEVELOPMENT trust root (%s): not for publishing\n", root.Environment); err != nil {
			return err
		}
	}
	days := int(root.Expires.Sub(now).Hours() / 24)
	note := ""
	if days < rootWarnDays {
		note = " - ROTATE THE ROOT NOW: after that day no installation updates any more (docs/data-package.md)"
	}
	_, err = fmt.Fprintf(out, "trust root version %d expires in %d days%s\n", root.Version, days, note)
	return err
}

// rootWarnDays is how long before the root expires the summary shouts.
const rootWarnDays = 90

// baseline reads the counts of the package published before. They are
// trusted only when the feed key sealed them. A published package without
// a valid baseline is refused: the shrink check would be skipped without
// anyone noticing. force goes on without a baseline (after a feed key
// rotation the old seal no longer verifies).
func baseline(previous string, root *feed.Root, now time.Time, force bool, logger *slog.Logger) (pkgbuild.Counts, bool, error) {
	if previous == "" {
		return pkgbuild.Counts{}, false, nil
	}
	if _, err := os.Lstat(filepath.Join(previous, "v1", "manifest.json")); errors.Is(err, os.ErrNotExist) {
		return pkgbuild.Counts{}, false, nil // nothing published yet
	}
	err := pkgbuild.Verify(pkgbuild.CountsPath(previous), pkgbuild.PurposeCounts, root, now)
	if err == nil {
		counts, have, rerr := pkgbuild.ReadCounts(previous)
		if rerr == nil && have {
			return counts, true, nil
		}
		err = errors.Join(rerr, errors.New("no counts"))
	}
	if force {
		logger.Warn("the published package has no valid baseline; building without the shrink check", "err", err)
		return pkgbuild.Counts{}, false, nil
	}
	return pkgbuild.Counts{}, false, fmt.Errorf("the published package has no valid baseline (%w): find out why, then build with -force", err)
}

// checkRootChain compares the root to publish with the one published
// before. An older root would make every installation refuse the mirror
// as a rollback; a skipped version breaks the chain they walk; another
// root under the same version would split installations; and a next
// version the published root does not endorse would strand them all.
func checkRootChain(previous string, root *feed.Root, rootData []byte, now time.Time) error {
	if previous == "" {
		return nil
	}
	data, err := pkgbuild.ReadRegular(filepath.Join(previous, "v1", "root.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("published trust root: %w", err)
	}
	published, _, err := feed.ParseRoot(data)
	if err != nil {
		return fmt.Errorf("published trust root: %w", err)
	}
	switch {
	case root.Version < published.Version:
		return fmt.Errorf("trust root version %d is older than the published version %d: build from a release that embeds the current root", root.Version, published.Version)
	case root.Version > published.Version+1:
		return fmt.Errorf("trust root version %d skips versions after the published %d: installations follow the chain one version at a time", root.Version, published.Version)
	case root.Version == published.Version && !bytes.Equal(data, rootData):
		return fmt.Errorf("trust root version %d differs from the published root of the same version: a changed root needs the next version", root.Version)
	case root.Version == published.Version+1:
		_, sigs, err := feed.ParseRoot(rootData)
		if err != nil {
			return err
		}
		if err := feed.VerifyRootUpdate(published, root, sigs, now); err != nil {
			return fmt.Errorf("installations that trust the published root would refuse this one: %w", err)
		}
	}
	return nil
}

// carryRoots copies the published root chain (v1/root/<n>.json) from
// previous into dir.
func carryRoots(previous, dir string) error {
	if previous == "" {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(previous, "v1", "root"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "v1", "root"), 0o755); err != nil { //nolint:gosec // published layout
		return err
	}
	for _, e := range entries {
		// Only what is a root file by name, by kind and by content: the
		// branch it comes from is writable by more than can sign, and a
		// symlink there could point at the builder's own environment.
		m := rootFile.FindStringSubmatch(e.Name())
		if m == nil {
			return fmt.Errorf("published root chain: unexpected entry %s", e.Name())
		}
		data, err := pkgbuild.ReadRegular(filepath.Join(previous, "v1", "root", e.Name()))
		if err != nil {
			return fmt.Errorf("published root chain: %w", err)
		}
		r, _, err := feed.ParseRoot(data)
		if err != nil {
			return fmt.Errorf("published root chain: %s: %w", e.Name(), err)
		}
		if strconv.FormatInt(r.Version, 10) != m[1] {
			return fmt.Errorf("published root chain: %s holds root version %d", e.Name(), r.Version)
		}
		if err := os.WriteFile(filepath.Join(dir, "v1", "root", e.Name()), data, 0o644); err != nil { //nolint:gosec // public metadata
			return err
		}
	}
	return nil
}

var rootFile = regexp.MustCompile(`^([1-9][0-9]{0,8})\.json$`)

// verify installs the package from dir with the client an installation
// uses, into a store and a directory of its own.
func verify(ctx context.Context, dir string, rootData []byte, root *feed.Root, now time.Time) error {
	tmp, err := os.MkdirTemp("", "varde-package-verify-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	st, err := store.Open(ctx, filepath.Join(tmp, "verify.db"))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	fetch, err := feed.NewFetcher("file://"+filepath.ToSlash(abs), nil, nil)
	if err != nil {
		return err
	}
	base, err := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err != nil {
		return err
	}
	client := &feed.Client{Dir: filepath.Join(tmp, "feed"), Store: st, Catalog: catalog.NewLive(base), Log: slog.New(slog.DiscardHandler),
		Now: func() time.Time { return now }, AllowDevelopment: root.Environment != feed.EnvProduction,
		Pick: func() feed.Channel { return feed.Channel{Name: feed.ChannelPackage, Mirrors: []feed.Fetcher{fetch}} }}
	if _, err := client.Init(rootData); err != nil {
		return err
	}
	res, err := client.Update(ctx)
	if err != nil {
		return err
	}
	if !res.Applied {
		return errors.New("the client did not install it")
	}
	return nil
}
