// SPDX-License-Identifier: Apache-2.0

// Command packagebuilder builds the daily data package (ADR 0039,
// docs/data-package.md): it collects the advisories of every repository
// the catalog and the first-party index know, the KEV list and EPSS
// scores, refuses a build that looks broken, signs the package and checks
// the result with the client an installation uses. The daily workflow
// runs it; it is not part of the server.
//
// Before the advisories it generates catalog entries for the index images
// no reviewed entry covers (internal/catgen) and reads the package lists
// of the newest release of every catalog app (internal/releases); both go
// into the package. The readable list of generated entries is written to
// catalog/generated.json and catalog/generated.md beside the package.
//
// Time: the data workflow stops the job after 350 minutes. The generator
// starts no project after -generate-time (90 min), the release reads start
// no image after -releases-until (150 min), both from the start of the
// build; the advisory collection gets the rest, and its waits for GitHub's
// rate limit (-max-wait) are shortened by the time already spent.
//
// Registries: GITHUB_TOKEN raises GitHub's rate limit for the generator
// too (without it the generator stops asking GitHub at the first rate
// limit and re-checks less). VARDE_DOCKERHUB_USER and
// VARDE_DOCKERHUB_TOKEN, when both are set, authenticate to Docker Hub;
// without them the release reads make at most 90 manifest requests, below
// Docker Hub's anonymous limit of 100 pulls in 6 hours per address.
//
//	VARDE_FEED_KEY="$(cat feed.key)" go run ./cmd/packagebuilder \
//	    -db cache/builder.db -previous published/feed -out work/feed
//
// The private feed key is read from the environment variable
// VARDE_FEED_KEY (PEM, PKCS#8, Ed25519). It is never written or printed.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
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
	"strings"
	"syscall"
	"time"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/index"
	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/catgen"
	"github.com/bifrost0x/varde/internal/eval"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/pkgbuild"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/releases"
	"github.com/bifrost0x/varde/internal/store"
)

type config struct {
	db, out, previous, root, catalogDir string
	valid, maxWait                      time.Duration
	force                               bool
	allowDevelopment                    bool
	githubURL, kevURL, epssURL          string
	// osv and nvd switch the second advisory sources on (ADR 0042);
	// osvURL and nvdURL override their endpoints in tests.
	osv, nvd       bool
	osvURL, nvdURL string
	// generate and releases switch the catalog generator and the release
	// reads on; generateFor and releasesUntil bound them from the start of
	// the build, maxManifests the manifest requests of the release reads
	// (0: by whether Docker Hub credentials are set).
	generate, releases bool
	// tags switches the tag lists on: the release tags of every catalog
	// image, read before the release package lists and bounded by the
	// same releasesUntil.
	tags                       bool
	generateFor, releasesUntil time.Duration
	maxManifests               int
	// storeLimit, releasesBudget and layerCache override the size bounds
	// of the published store, the releases blob and the layer reads kept
	// (defaultStoreLimit, feed.DefaultReleasesBudget,
	// defaultLayerCache); tests set them.
	storeLimit, releasesBudget, layerCache int64
	// http, now, table, sources and readReleases are replaced in tests.
	http    *httpx.Client
	now     func() time.Time
	table   *applists.Table
	sources *genSources
	// readReleases reads the release package lists (releases.Reader.Run).
	readReleases func(ctx context.Context, cat *catalog.Catalog, order []string) ([]feed.ReleaseLine, releases.Stats, error)
	// readTags reads the release tags (releases.TagReader.Run).
	readTags func(ctx context.Context, cat *catalog.Catalog, order []string) ([]feed.TagLine, releases.TagStats, error)
}

// genSources are what the generator asks; nil fields are left unset.
type genSources struct {
	registry catgen.RegistryAPI
	github   catgen.GitHubAPI
	nvd      catgen.NVDAPI
	hub      catgen.HubAPI
}

// Defaults of the time and request bounds (see the package comment).
const (
	defaultGenerateFor   = 90 * time.Minute
	defaultReleasesUntil = 150 * time.Minute
	// anonymousManifests stays below Docker Hub's 100 anonymous pulls in
	// 6 hours; manifest GETs count as pulls.
	anonymousManifests = 90
	// registryTimeout bounds one registry request that is read whole (a
	// tag list, a manifest, a token). Blobs are streamed and have no such
	// bound in the HTTP client: the release reader bounds each blob by its
	// size and each image by time and the -releases-until deadline
	// (releases.Reader).
	registryTimeout = 10 * time.Minute
	// defaultStoreLimit bounds the store as it is published, compressed
	// (builder.db.gz): GitHub refuses a file over 100 MiB on a branch.
	// Over it the builder drops its layer reads, and refuses to publish
	// a store still over it.
	defaultStoreLimit = 80 << 20
	// defaultLayerCache bounds the layer reads kept after a build; the
	// oldest beyond it go first.
	defaultLayerCache = 40 << 20
)

func main() {
	var c config
	flag.StringVar(&c.db, "db", "", "the builder's store: advisories and request state kept between builds (required)")
	flag.StringVar(&c.out, "out", "", "directory to write the package to (required, must not hold a package)")
	flag.StringVar(&c.previous, "previous", "", "directory of the package published before, for the shrink check")
	flag.StringVar(&c.root, "root", "", "trust root to publish with the package (default: the root built into this binary)")
	flag.StringVar(&c.catalogDir, "catalog", "", "catalog directory (default: the built-in catalog)")
	flag.DurationVar(&c.valid, "valid", 7*24*time.Hour, "how long the package is valid")
	flag.DurationVar(&c.maxWait, "max-wait", 5*time.Hour, "longest total wait for GitHub's rate limit to reset, less the time the generator and the release reads took")
	flag.BoolVar(&c.force, "force", false, "sign although the package shrank a lot (after checking why)")
	flag.BoolVar(&c.allowDevelopment, "allow-development-root", false, "build under a development root (tests only; installations refuse such a package)")
	flag.StringVar(&c.githubURL, "github-url", "", "GitHub API endpoint (tests)")
	flag.StringVar(&c.kevURL, "kev-url", "", "KEV endpoint (tests)")
	flag.StringVar(&c.epssURL, "epss-url", "", "EPSS endpoint (tests)")
	flag.BoolVar(&c.generate, "generate", true, "generate and check catalog entries for index images without a reviewed entry")
	flag.BoolVar(&c.osv, "osv", true, "ask osv.dev about the osv_packages of catalog apps")
	flag.BoolVar(&c.nvd, "nvd", true, "ask the NVD about the CPEs of catalog apps whose projects publish no complete advisories")
	flag.BoolVar(&c.tags, "tags", true, "read the release tags of the images of every catalog app")
	flag.BoolVar(&c.releases, "releases", true, "read the package lists of the newest release of every catalog app")
	flag.DurationVar(&c.generateFor, "generate-time", defaultGenerateFor, "the generator starts no project this long after the start of the build")
	flag.DurationVar(&c.releasesUntil, "releases-until", defaultReleasesUntil, "the release reads start no image this long after the start of the build")
	flag.IntVar(&c.maxManifests, "max-manifests", 0, "manifest requests of the release reads (default 600 with Docker Hub credentials, 90 without)")
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
	var cases []eval.ContainerCase
	if c.generate {
		var err error
		if cases, err = eval.ContainerCases(); err != nil {
			return fmt.Errorf("eval corpus: %w", err)
		}
	}

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

	// The generator and the release reads first: they have deadlines,
	// the advisory collection only a bound on its waits.
	prevGenerated, err := readPreviousGenerated(c.previous)
	if err != nil {
		logger.Warn("the published list of generated entries does not read; the summary compares with the builder's store", "err", err)
	}
	reg := c.registry(env)
	var (
		rep       catgen.Report
		generated []catalog.Entry
	)
	if c.generate {
		g := c.generator(st, hc, reg, env, cases, now)
		if rep, err = g.Run(ctx, table, cat); err != nil {
			return fmt.Errorf("catalog generator: %w", err)
		}
		// Not nil: a package without generated entries says so.
		generated = append([]catalog.Entry{}, rep.Shipped...)
	}
	candidates, err := st.AllCandidates(ctx)
	if err != nil {
		return err
	}
	var (
		lines          []feed.ReleaseLine
		relStats       releases.Stats
		releaseCatalog *catalog.Catalog
	)
	var (
		tagLines []feed.TagLine
		tagStats releases.TagStats
	)
	// The catalog as an installation builds it from the package: the
	// reviewed entries over the generated ones.
	layered, err := catalog.BuildLayered(entries, catalog.OriginBuiltin, generated, nil)
	if err != nil {
		return fmt.Errorf("catalog with generated entries: %w", err)
	}
	for _, d := range layered.DroppedGenerated() {
		logger.Warn("generated entry left out beside the reviewed ones", "entry", d)
	}
	if c.tags || c.releases {
		order := releases.Priority(layered, appWeights(candidates))
		if c.tags {
			// Before the package lists: a tag list costs one request and
			// no pull, so every image gets one whatever the lists cost.
			read := c.readTags
			if read == nil {
				r := &releases.TagReader{Store: st, Registry: reg, Now: c.now,
					Deadline: now.Add(orDefault(c.releasesUntil, defaultReleasesUntil)), Log: logger}
				read = r.Run
			}
			if tagLines, tagStats, err = read(ctx, layered, order); err != nil {
				return fmt.Errorf("tag lists: %w", err)
			}
			// Not nil: a package without tag lists says so.
			tagLines = append([]feed.TagLine{}, tagLines...)
		}
		releaseCatalog = layered
	}
	if c.releases {
		layered := releaseCatalog
		read := c.readReleases
		if read == nil {
			r := &releases.Reader{Store: st, Registry: reg, Now: c.now, MaxManifests: c.manifests(env),
				MaxShipBytes: orDefault64(c.releasesBudget, feed.DefaultReleasesBudget),
				Deadline:     now.Add(orDefault(c.releasesUntil, defaultReleasesUntil)), Log: logger}
			read = r.Run
		}
		if lines, relStats, err = read(ctx, layered, releases.Priority(layered, appWeights(candidates))); err != nil {
			return fmt.Errorf("release reads: %w", err)
		}
		lines = append([]feed.ReleaseLine{}, lines...)
	}

	// The waits for GitHub's rate limit share the time left. None left
	// (or -max-wait 0) means no wait at all; Collect would read a zero as
	// its default, so the least positive bound stands for it.
	wait := c.maxWait - c.now().Sub(now)
	if wait <= 0 {
		wait = time.Nanosecond
	}
	stats, err := pkgbuild.Collect(ctx, repos, pkgbuild.Options{Store: st, HTTP: hc, Token: env("GITHUB_TOKEN"),
		GitHubURL: c.githubURL, KEVURL: c.kevURL, EPSSURL: c.epssURL, Now: c.now, MaxWait: wait, Log: logger,
		Apps: layered.Apps(), OSV: c.osv, NVD: c.nvd, OSVURL: c.osvURL, NVDURL: c.nvdURL, NVDKey: env("VARDE_NVD_API_KEY")})
	if err != nil {
		return err
	}
	var second []*catalog.App
	if c.osv || c.nvd {
		second = layered.Apps()
	}
	snap, err := pkgbuild.Snapshot(ctx, st, entries, table, repos, second, now, c.valid)
	if err != nil {
		return err
	}
	snap.Generated = generated
	if c.tags {
		snap.Tags = tagLines
	}
	var (
		fitted int
		pruned store.PruneStats
	)
	if c.releases {
		// The lines come in priority order: those that do not fit the
		// room the other blobs leave go, the lowest first, and the store
		// keeps only the reads that ship and the layer reads they use.
		room, err := snap.ReleasesRoom(c.releasesBudget)
		if err != nil {
			return err
		}
		kept, _, err := feed.FitReleases(lines, room)
		if err != nil {
			return err
		}
		fitted, snap.Releases = len(lines)-len(kept), kept
		keys := make([]store.ReleaseReadKey, len(kept))
		for i, l := range kept {
			keys[i] = releases.StoreKey(l)
		}
		if pruned, err = st.PruneBuilderReads(ctx, keys, orDefault64(c.layerCache, defaultLayerCache)); err != nil {
			return err
		}
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
	manifest, err := feed.WriteSnapshot(staging, snap, key)
	if err != nil {
		return err
	}
	var releasesUnpacked int64
	if counts.ReleasesBytes, releasesUnpacked, err = blobSize(manifest, "releases"); err != nil {
		return err
	}
	if err := pkgbuild.GuardReleases(counts.ReleasesBytes); err != nil {
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
	storeSize, droppedLayers, err := fitStore(ctx, c.db, orDefault64(c.storeLimit, defaultStoreLimit), logger)
	if err != nil {
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
	var diff genDiff
	if !c.generate {
		// A list left from an earlier build in the same directory would be
		// published as this build's.
		for _, f := range []string{generatedJSON, generatedMD} {
			if err := os.Remove(filepath.Join(parent, generatedDir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if c.generate {
		cur := generatedState(candidates, rep, now, counts.Sequence)
		diff = diffGenerated(prevGenerated, cur, rep)
		if err := writeGenerated(parent, cur, renderGenerated(cur, diff, rep)); err != nil {
			return fmt.Errorf("list of generated entries: %w", err)
		}
	}
	if _, err = fmt.Fprintf(out, "package %d: %d repositories (%d failed), %d advisories, %d KEV, %d EPSS, %d index rows; %d requests, %d waits\n",
		counts.Sequence, stats.Repos, stats.Failed, counts.Advisories, counts.KEV, counts.EPSS, counts.Index, stats.Requests, stats.Waits); err != nil {
		return err
	}
	if c.generate {
		if _, err := fmt.Fprintf(out, "generated: %d entries (%d new, %d changed, %d dropped images; %d failed, %d not checked)\n",
			len(generated), len(diff.New), len(diff.Changed), len(diff.Dropped), len(rep.Failed), len(rep.Skipped)); err != nil {
			return err
		}
		if len(rep.Stopped) > 0 {
			if _, err := fmt.Fprintln(out, "generator stopped early:", strings.Join(rep.Stopped, ", ")); err != nil {
				return err
			}
		}
	}
	if c.releases {
		if _, err := fmt.Fprintf(out, "releases: %d lines, %d bytes compressed, %d unpacked (%d images: %d read, %d unchanged, %d failed, %d not started, %d too large; %d partial, %d stale; %d lines over the size budget); %d manifest requests\n",
			counts.Releases, counts.ReleasesBytes, releasesUnpacked, relStats.Images, relStats.Read, relStats.Unchanged, relStats.Failed, relStats.NotStarted,
			relStats.TooLarge, relStats.Partial, relStats.Stale, fitted, relStats.Manifests); err != nil {
			return err
		}
	}
	if c.osv || c.nvd {
		if _, err := fmt.Fprintf(out, "second sources: osv.dev %d apps, %d requests%s; NVD %d apps, %d requests%s\n",
			stats.OSVApps, stats.OSVRequests, stopped(stats.OSVError), stats.NVDApps, stats.NVDRequests, stopped(stats.NVDError)); err != nil {
			return err
		}
	}
	if c.tags {
		if _, err := fmt.Fprintf(out, "tags: %d images with release tags (%d images: %d read, %d fresh, %d failed, %d not started, %d without a release tag; %d stale)\n",
			len(tagLines), tagStats.Images, tagStats.Read, tagStats.Fresh, tagStats.Failed, tagStats.NotStarted, tagStats.NoRelease, tagStats.Stale); err != nil {
			return err
		}
	}
	note := ""
	if droppedLayers > 0 {
		note = fmt.Sprintf("; %d layer reads dropped to stay under %d bytes", droppedLayers, orDefault64(c.storeLimit, defaultStoreLimit))
	}
	if _, err := fmt.Fprintf(out, "store: builder.db.gz %d bytes; pruned %d release reads and %d layer reads, %d bytes of layer reads kept%s\n",
		storeSize, pruned.Reads, pruned.Layers, pruned.LayerBytes, note); err != nil {
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
	note = ""
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

// registry is the registry client of the generator and the release reads,
// with the Docker Hub credentials when both are set.
// builderTagPages bounds a tag list of the builder: a hundred thousand
// tags. The largest repositories of the catalog list some forty thousand.
const builderTagPages = 100

func (c config) registry(env func(string) string) *registry.Client {
	return registry.New(httpx.New(httpx.Options{Timeout: registryTimeout}),
		registry.WithCredentials("docker.io", env("VARDE_DOCKERHUB_USER"), env("VARDE_DOCKERHUB_TOKEN")),
		registry.WithTagPages(builderTagPages))
}

// manifests is the manifest budget of the release reads.
func (c config) manifests(env func(string) string) int {
	switch {
	case c.maxManifests > 0:
		return c.maxManifests
	case env("VARDE_DOCKERHUB_USER") != "" && env("VARDE_DOCKERHUB_TOKEN") != "":
		return releases.DefaultMaxManifests
	}
	return anonymousManifests
}

// generator sets up the catalog generator; its sources are the real
// clients unless a test replaced them.
func (c config) generator(st *store.Store, hc *httpx.Client, reg *registry.Client, env func(string) string, cases []eval.ContainerCase, start time.Time) *catgen.Generator {
	g := &catgen.Generator{Store: st, Now: c.now, Deadline: start.Add(orDefault(c.generateFor, defaultGenerateFor)), EvalCases: cases}
	if c.sources == nil {
		g.Registry = reg
		g.GitHub = &catgen.GitHub{HTTP: hc, Token: env("GITHUB_TOKEN"), BaseURL: c.githubURL}
		g.NVD = &catgen.NVD{HTTP: hc}
		g.Hub = &catgen.Hub{HTTP: hc}
		return g
	}
	g.Registry, g.GitHub = c.sources.registry, c.sources.github
	if c.sources.nvd != nil {
		g.NVD = c.sources.nvd
	}
	if c.sources.hub != nil {
		g.Hub = c.sources.hub
	}
	return g
}

// appWeights are the weights of the generated apps for the order of the
// release reads: the heaviest image of each project.
func appWeights(candidates []store.Candidate) map[string]int64 {
	w := map[string]int64{}
	for _, cand := range candidates {
		owner, name, ok := strings.Cut(cand.Repo, "/")
		if !ok {
			continue
		}
		id := catalog.DerivedID(owner, name)
		w[id] = max(w[id], cand.Weight)
	}
	return w
}

// blobSize is the compressed and the unpacked size of the named blob of a
// manifest; 0 when the package has none.
func blobSize(manifest []byte, name string) (size, unpacked int64, err error) {
	var m feed.Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return 0, 0, fmt.Errorf("written manifest: %w", err)
	}
	for _, b := range m.Blobs {
		if b.Name == name {
			return b.Size, b.UncompressedSize, nil
		}
	}
	return 0, 0, nil
}

// fitStore measures the closed store as the workflow publishes it
// (gzip -9) and returns that size. Over limit it drops the layer reads,
// which the next build reads again, and measures once more; a store still
// over limit is refused, so no build publishes a file GitHub would refuse.
func fitStore(ctx context.Context, path string, limit int64, logger *slog.Logger) (size int64, dropped int, err error) {
	if size, err = gzipSize(path); err != nil {
		return 0, 0, err
	}
	if size <= limit {
		return size, 0, nil
	}
	logger.Warn("the builder's store is too large to publish; dropping its layer reads", "bytes", size, "limit", limit)
	st, err := store.Open(ctx, path)
	if err != nil {
		return 0, 0, err
	}
	dropped, err = st.DropLayerReads(ctx)
	if err = errors.Join(err, st.Close()); err != nil {
		return 0, 0, err
	}
	if size, err = gzipSize(path); err != nil {
		return 0, 0, err
	}
	if size > limit {
		return size, dropped, fmt.Errorf("the builder's store is %d bytes compressed without its layer reads, over the limit of %d: "+
			"GitHub refuses files over 100 MiB on the branch data; find what grew (docs/data-package.md)", size, limit)
	}
	return size, dropped, nil
}

// gzipSize is the size of the file compressed as scripts/publish-data.sh
// compresses it.
func gzipSize(path string) (int64, error) {
	f, err := os.Open(path) //nolint:gosec // the builder's own store
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	var n countWriter
	zw, err := gzip.NewWriterLevel(&n, gzip.BestCompression)
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(zw, f); err != nil {
		return 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	return int64(n), nil
}

// countWriter counts what is written to it.
type countWriter int64

func (c *countWriter) Write(p []byte) (int, error) {
	*c += countWriter(len(p))
	return len(p), nil
}

// orDefault64 is n, or def when n is not positive.
func orDefault64(n, def int64) int64 {
	if n > 0 {
		return n
	}
	return def
}

// orDefault is d, or def when d is not positive: a zero bound would stop
// the work before it starts.
func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// stopped words a source that ended early for the summary.
func stopped(err string) string {
	if err == "" {
		return ""
	}
	return " (stopped early: " + oneLine(err) + ")"
}
