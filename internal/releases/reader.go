// SPDX-License-Identifier: Apache-2.0

// Package releases reads the package lists of the newest release of the
// catalog's apps from their registries, inside the daily data build: for
// each image of an app it resolves the newest release tag as the registry
// resolver orders tags, squashes the release's layers for linux/amd64 and
// linux/arm64 and reads them as a running container is read. The lines go
// into the signed package, so an installation can tell which of its
// findings that release fixes without asking a registry itself. It runs in
// the builder, never in an installation.
package releases

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imagelayers"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/inventory/docker"
	"github.com/bifrost0x/varde/internal/registry"
)

// DefaultMaxManifests and DefaultMaxBytes are the budgets of one run when
// the Reader leaves them zero: manifest requests (Docker Hub counts them as
// pulls) and bytes read from registries.
const (
	DefaultMaxManifests = 600
	DefaultMaxBytes     = 20 << 30
)

const (
	// StaleAfter is the age from which a shipped line counts as stale in
	// Stats; it still ships, with its read time.
	StaleAfter = 30 * 24 * time.Hour
	// maxLineBytes is the longest line an installation's parser of the
	// releases blob accepts; a longer one would cost it the whole blob.
	maxLineBytes = 16 << 20
	// maxConfigBytes bounds an image config blob.
	maxConfigBytes = 1 << 20
	// manifestsPerImage is the most manifest requests one image read
	// makes: the index and one manifest per platform.
	manifestsPerImage = 3
	// maxLayerRecord bounds a decompressed layer record from the store:
	// the kept bytes of a view and their JSON encoding.
	maxLayerRecord = 2 * (256 << 20)
)

// Platforms are the platforms read of every release, keyed as the store
// keys a release read. arm64 matches every variant.
var Platforms = []registry.Platform{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}}

func platformKey(p registry.Platform) string { return p.OS + "/" + p.Arch }

// versionRe is the bound feed.ReleaseLine.Validate puts on a version; a
// tag whose version fails it is not read at all.
var versionRe = regexp.MustCompile(`^[A-Za-z0-9._+~:-]{1,128}$`)

// Store is the builder state the reader keeps; *store.Store has it.
type Store interface {
	LayerRead(ctx context.Context, digest string) (files []byte, partial, ok bool, err error)
	PutLayerRead(ctx context.Context, digest string, files []byte, partial bool, readAt time.Time) error
	ReleaseRead(ctx context.Context, appID, image, platform string) (tag, indexDigest string, line []byte, ok bool, err error)
	PutReleaseRead(ctx context.Context, appID, image, platform, tag, indexDigest string, line []byte, readAt time.Time) error
	ReleaseReadLimits(ctx context.Context, appID, image, platform string) (string, error)
	SetReleaseReadLimits(ctx context.Context, appID, image, platform, limits string) error
}

// Reader reads release package lists. MaxManifests and MaxBytes bound the
// registry work of one run (DefaultMaxManifests and DefaultMaxBytes when
// zero).
type Reader struct {
	Store
	Registry     *registry.Client
	Now          func() time.Time
	MaxManifests int
	MaxBytes     int64
	// Limits bound each squashed view; imagelayers.DefaultLimits when
	// zero.
	Limits imagelayers.Limits
	Log    *slog.Logger
	// Deadline, when set, ends the run's registry work: no image starts
	// after it, as when a budget is spent. It keeps the data build inside
	// its time limit; the images left are read by a later build.
	Deadline time.Time

	// registryRepo maps an image to the repository asked of the registry;
	// tests point it at a server, whose host a catalog image cannot name.
	registryRepo func(image string) string
}

func (r *Reader) remote(image string) string {
	if r.registryRepo != nil {
		return r.registryRepo(image)
	}
	return image
}

// Stats says what a run did.
type Stats struct {
	// Images is the number of app images with a tag source considered.
	Images int
	// Read counts the images read from the registry this run, Unchanged
	// those whose newest release was read before under the same digest.
	Read, Unchanged int
	// Failed counts images the registry did not serve (an error, a cut
	// tag list); their earlier lines still ship.
	Failed int
	// NoRelease counts images without a tag the app's tag rule reads a
	// version from, or without a linux/amd64 or linux/arm64 image.
	NoRelease int
	// NotStarted counts images left for a later run because a budget was
	// spent; BudgetSpent says one was.
	NotStarted  int
	BudgetSpent bool
	// DeadlinePassed says the Deadline stopped the run.
	DeadlinePassed bool
	// TooLarge counts images whose layers alone exceed MaxBytes; they
	// are skipped and the run goes on.
	TooLarge int
	// Lines, Partial and Stale count the shipped lines: all, those of an
	// incomplete read, and those read more than StaleAfter ago.
	Lines, Partial, Stale int
	// Invalid counts lines left out because they fail validation (an
	// invalid version, too many packages).
	Invalid int
	// Manifests and Bytes are the registry usage of the run.
	Manifests int
	Bytes     int64
}

// job is one image of an app to read.
type job struct {
	app   *catalog.App
	image string
}

// Run reads the newest release of each image of the catalog's apps, in
// the order of order (app IDs by priority; reviewed apps go before
// generated ones whatever order says, and apps order leaves out follow by
// ID), and returns the lines to ship. A budget spent or the Deadline stops
// new reads; what was read by then ships, and so does every earlier line of
// an app image that is still in the catalog, with its read time. A registry failure
// costs the image; only a store failure or the end of ctx ends the run.
func (r *Reader) Run(ctx context.Context, cat *catalog.Catalog, order []string) ([]feed.ReleaseLine, Stats, error) {
	var st Stats
	start := r.Registry.Budget()
	jobs := r.jobs(cat, order)
	st.Images = len(jobs)
	cur := map[job]readID{}
	for i, j := range jobs {
		if err := ctx.Err(); err != nil {
			return nil, st, err
		}
		if !r.Deadline.IsZero() && !r.Now().Before(r.Deadline) {
			st.DeadlinePassed = true
		}
		if st.BudgetSpent || st.DeadlinePassed {
			st.NotStarted += len(jobs) - i
			break
		}
		if err := r.read(ctx, j, start, &st, cur); err != nil {
			return nil, st, err
		}
	}
	used := r.usage(start)
	st.Manifests, st.Bytes = used.ManifestRequests, used.Bytes
	lines, err := r.shipped(ctx, jobs, cur, &st)
	if err != nil {
		return nil, st, err
	}
	return lines, st, nil
}

// Priority orders app IDs for Run: reviewed apps by ID, then generated
// apps by weight (heaviest first) and ID.
func Priority(cat *catalog.Catalog, weight map[string]int64) []string {
	var reviewed, generated []string
	for _, a := range cat.Apps() {
		if a.Origin == catalog.OriginGenerated {
			generated = append(generated, a.ID)
		} else {
			reviewed = append(reviewed, a.ID)
		}
	}
	sort.Strings(reviewed)
	sort.Slice(generated, func(i, j int) bool {
		a, b := generated[i], generated[j]
		if weight[a] != weight[b] {
			return weight[a] > weight[b]
		}
		return a < b
	})
	return append(reviewed, generated...)
}

// jobs lists the images to read in priority order: per app, its images
// whose version chain reads tags. A generated app's images are only those
// the generator checked; one it joined or knows by label only is read as
// the derived entry would read it, which no release read stands behind.
func (r *Reader) jobs(cat *catalog.Catalog, order []string) []job {
	rank := map[string]int{}
	for i, id := range order {
		if _, ok := rank[id]; !ok {
			rank[id] = i
		}
	}
	apps := slices.Clone(cat.Apps())
	sort.SliceStable(apps, func(i, j int) bool {
		a, b := apps[i], apps[j]
		ga, gb := a.Origin == catalog.OriginGenerated, b.Origin == catalog.OriginGenerated
		if ga != gb {
			return gb
		}
		ra, oka := rank[a.ID]
		rb, okb := rank[b.ID]
		switch {
		case oka && okb:
			return ra < rb
		case oka != okb:
			return oka
		}
		return a.ID < b.ID
	})
	var out []job
	for _, a := range apps {
		if a.Origin == catalog.OriginDerived {
			continue
		}
		seen := map[string]bool{}
		for _, img := range a.Images {
			repo, err := imageref.NormaliseRepository(img.Match)
			if err != nil || seen[repo] || identify.ReadsAsDerived(a, repo) || !readsTags(a.Version) {
				continue
			}
			seen[repo] = true
			out = append(out, job{app: a, image: repo})
		}
	}
	return out
}

// readsTags reports whether a version chain reads a version from the tag:
// an explicit tag source, or the default chain, which ends in one.
func readsTags(v catalog.VersionSpec) bool {
	if len(v.Sources) == 0 {
		return true
	}
	for _, s := range v.Sources {
		if s.Tag != "" {
			return true
		}
	}
	return false
}

func (r *Reader) usage(start registry.Usage) registry.Usage {
	u := r.Registry.Budget()
	return registry.Usage{ManifestRequests: u.ManifestRequests - start.ManifestRequests, Bytes: u.Bytes - start.Bytes}
}

func (r *Reader) maxManifests() int {
	if r.MaxManifests > 0 {
		return r.MaxManifests
	}
	return DefaultMaxManifests
}

func (r *Reader) maxBytes() int64 {
	if r.MaxBytes > 0 {
		return r.MaxBytes
	}
	return DefaultMaxBytes
}

func (r *Reader) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

// stored is the stored release read of one platform.
type stored struct {
	platform, tag, digest, limits string
	line                          feed.ReleaseLine
}

// readID names one read of a release: its tag and the digest it named.
type readID struct{ tag, digest string }

// read reads the newest release of one image and stores its lines. An
// error is returned only for the store or ctx; the registry's errors are
// counted and logged.
func (r *Reader) read(ctx context.Context, j job, start registry.Usage, st *Stats, cur map[job]readID) error {
	log := r.log().With("app", j.app.ID, "image", j.image)
	if r.usage(start).ManifestRequests+manifestsPerImage > r.maxManifests() || r.usage(start).Bytes >= r.maxBytes() {
		st.BudgetSpent = true
		st.NotStarted++
		return nil
	}
	failed := func(msg string, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st.Failed++
		log.Info(msg, "err", err)
		return nil
	}
	tags, complete, err := r.Registry.AllTags(ctx, r.remote(j.image))
	if err != nil {
		return failed("release read: tag list failed", err)
	}
	if !complete {
		// The newest tag may be on a page that was not read.
		return failed("release read: tag list cut short", errors.New("more tags than the registry client lists"))
	}
	keep, less := registry.TagOrder(j.app, j.image)
	ranked := registry.Rank(tags, keep, less)
	if len(ranked) == 0 {
		st.NoRelease++
		log.Info("release read: no release tag")
		return nil
	}
	tag := ranked[0]
	version, _ := identify.TagVersion(j.app, j.image, tag)
	if !versionRe.MatchString(version) {
		st.Invalid++
		log.Warn("release read: tag names a version the package cannot carry", "tag", tag, "version", version)
		return nil
	}
	digest, err := r.Registry.Digest(ctx, r.remote(j.image), tag)
	if err != nil {
		return failed("release read: tag digest failed", err)
	}
	prev, err := r.stored(ctx, j)
	if err != nil {
		return err
	}
	if r.unchanged(prev, tag, digest) {
		st.Unchanged++
		cur[j] = readID{tag, digest}
		return r.confirm(ctx, j, prev, tag, digest)
	}
	ms, index, err := r.Registry.Image(ctx, r.remote(j.image), tag, Platforms)
	if err != nil {
		return failed("release read: manifests failed", err)
	}
	if len(ms) == 0 {
		st.NoRelease++
		log.Info("release read: no linux/amd64 or linux/arm64 image", "tag", tag)
		return nil
	}
	reads := make([]platformRead, 0, len(ms))
	for _, m := range ms {
		cfg, err := r.config(ctx, j.image, m.ConfigDigest)
		var se *storeError
		if errors.As(err, &se) {
			return se.err
		}
		if err != nil {
			return failed("release read: image config failed", err)
		}
		reads = append(reads, platformRead{m: m, cfg: cfg, cache: &layerCache{store: r.Store, now: r.Now, log: log, recs: map[string]*imagelayers.LayerRecord{}}})
	}
	// The layers the cache cannot serve must fit the byte budget before
	// the first of them is fetched.
	var need int64
	for _, pr := range reads {
		n, err := pr.cache.missing(ctx, pr.m.Layers, pr.cfg, r.Limits)
		var se *storeError
		if errors.As(err, &se) {
			return se.err
		}
		if err != nil {
			return failed("release read: layers refused", err)
		}
		need += n
	}
	if need > r.maxBytes() {
		// Not even a whole run's budget reads it; the next image may fit.
		st.TooLarge++
		log.Warn("release read: layers larger than the byte budget", "tag", tag, "bytes", need)
		return nil
	}
	if r.usage(start).Bytes+need > r.maxBytes() {
		st.BudgetSpent = true
		st.NotStarted++
		return nil
	}
	now := r.Now().UTC()
	lines := make([]feed.ReleaseLine, 0, len(reads))
	for _, pr := range reads {
		l, err := r.readPlatform(ctx, j, pr)
		if err != nil {
			if pr.cache.err != nil {
				return pr.cache.err
			}
			return failed("release read: layers failed", err)
		}
		l.Tag, l.Version, l.Read = tag, version, now
		if index != pr.m.Digest {
			l.IndexDigest = index
		}
		lines = append(lines, l)
	}
	st.Read++
	// All platforms are stored together, so a stored digest stands for a
	// complete read of the release (unchanged). Lines of an earlier read
	// stay stored (a platform the release dropped, a line left out) but
	// are not shipped next to this read.
	cur[j] = readID{tag, index}
	limits := imagelayers.LimitsKey(r.Limits)
	for _, l := range lines {
		if err := l.Validate(); err != nil {
			st.Invalid++
			log.Warn("release read: line left out", "platform", platformKey(l.Platform.Registry()), "err", err)
			continue
		}
		b, err := json.Marshal(l)
		if err != nil {
			return err
		}
		if len(b) >= maxLineBytes {
			st.Invalid++
			log.Warn("release read: line left out", "platform", platformKey(l.Platform.Registry()), "err", "longer than an installation reads")
			continue
		}
		key := platformKey(requested(l.Platform.Registry()))
		if err := r.PutReleaseRead(ctx, j.app.ID, j.image, key, tag, index, b, now); err != nil {
			return err
		}
		if err := r.SetReleaseReadLimits(ctx, j.app.ID, j.image, key, limits); err != nil {
			return err
		}
	}
	return nil
}

// requested maps the platform of a manifest to the requested platform it
// matched (arm64 of every variant is stored as linux/arm64).
func requested(p registry.Platform) registry.Platform {
	return registry.Platform{OS: p.OS, Arch: p.Arch}
}

// stored returns the stored reads of an image's platforms.
func (r *Reader) stored(ctx context.Context, j job) ([]stored, error) {
	var out []stored
	for _, p := range Platforms {
		tag, digest, b, ok, err := r.ReleaseRead(ctx, j.app.ID, j.image, platformKey(p))
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		s := stored{platform: platformKey(p), tag: tag, digest: digest}
		if err := json.Unmarshal(b, &s.line); err != nil {
			// Read again: the line is replaced.
			s.digest = ""
		}
		if s.limits, err = r.ReleaseReadLimits(ctx, j.app.ID, j.image, s.platform); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// latest returns the stored platforms of the image's latest read: of id
// when known, else of the read with the newest read time (the platforms of
// a read share it). Rows of a superseded read are left out.
func latest(prev []stored, id readID, known bool) []stored {
	if !known {
		var newest time.Time
		for _, s := range prev {
			if s.digest != "" && s.line.Read.After(newest) {
				newest, id = s.line.Read, readID{s.tag, s.digest}
			}
		}
	}
	var out []stored
	for _, s := range prev {
		if s.digest != "" && s.tag == id.tag && s.digest == id.digest {
			out = append(out, s)
		}
	}
	return out
}

// unchanged reports whether the latest read is of the newest release under
// the digest its tag names now, made with the current limits where it
// stopped at one. The platforms of a read are stored together, so the
// latest read's rows stand for the whole release.
func (r *Reader) unchanged(prev []stored, tag, digest string) bool {
	last := latest(prev, readID{}, false)
	if len(last) == 0 || last[0].tag != tag || last[0].digest != digest {
		return false
	}
	limits := imagelayers.LimitsKey(r.Limits)
	for _, s := range last {
		if s.line.Partial && s.limits != limits {
			// Other limits may read it in full.
			return false
		}
	}
	return true
}

// confirm renews the read time of the stored lines of a release whose tag
// still names the digest read: the package list read is the list of that
// release today.
func (r *Reader) confirm(ctx context.Context, j job, prev []stored, tag, digest string) error {
	now := r.Now().UTC()
	for _, s := range prev {
		if s.tag != tag || s.digest != digest {
			continue
		}
		s.line.Read = now
		b, err := json.Marshal(s.line)
		if err != nil {
			return err
		}
		if err := r.PutReleaseRead(ctx, j.app.ID, j.image, s.platform, tag, digest, b, now); err != nil {
			return err
		}
		if err := r.SetReleaseReadLimits(ctx, j.app.ID, j.image, s.platform, s.limits); err != nil {
			return err
		}
	}
	return nil
}

// config reads the parts of an image config the package reader uses. A
// config is immutable like a layer, so what was read of it is kept in the
// layer reads under its own digest (layer records are keyed by
// imagelayers.LayerKeys, which never equal a blob's digest): a release
// whose layers are all cached is read again without a blob request.
func (r *Reader) config(ctx context.Context, image, digest string) (docker.ImageConfig, error) {
	var cfg docker.ImageConfig
	b, _, ok, err := r.LayerRead(ctx, digest)
	if err != nil {
		return cfg, &storeError{err}
	}
	if ok && decodeGzipJSON(b, maxConfigBytes, &cfg) == nil {
		return cfg, nil
	}
	cfg, err = r.fetchConfig(ctx, image, digest)
	if err != nil {
		return cfg, err
	}
	b, err = encodeGzipJSON(cfg)
	if err != nil {
		return cfg, err
	}
	if err := r.PutLayerRead(ctx, digest, b, false, r.Now()); err != nil {
		return cfg, &storeError{err}
	}
	return cfg, nil
}

// storeError marks a store failure among the registry's.
type storeError struct{ err error }

func (e *storeError) Error() string { return e.err.Error() }
func (e *storeError) Unwrap() error { return e.err }

func (r *Reader) fetchConfig(ctx context.Context, image, digest string) (docker.ImageConfig, error) {
	rc, err := r.Registry.Blob(ctx, r.remote(image), digest, maxConfigBytes)
	if err != nil {
		return docker.ImageConfig{}, err
	}
	defer func() { _ = rc.Close() }()
	// Read to the end: the digest is checked there.
	b, err := io.ReadAll(rc)
	if err != nil {
		return docker.ImageConfig{}, err
	}
	var doc struct {
		Config struct {
			Labels     map[string]string `json:"Labels"`
			WorkingDir string            `json:"WorkingDir"`
			Entrypoint []string          `json:"Entrypoint"`
			Cmd        []string          `json:"Cmd"`
		} `json:"config"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return docker.ImageConfig{}, fmt.Errorf("image config: %w", err)
	}
	c := doc.Config
	return docker.ImageConfig{Labels: c.Labels, WorkingDir: c.WorkingDir, Entrypoint: c.Entrypoint, Cmd: c.Cmd}, nil
}

// platformRead is one platform of a release to read.
type platformRead struct {
	m     registry.ImageManifest
	cfg   docker.ImageConfig
	cache *layerCache
}

// readPlatform squashes one platform's layers and reads its packages.
func (r *Reader) readPlatform(ctx context.Context, j job, pr platformRead) (feed.ReleaseLine, error) {
	open := func(ctx context.Context, l registry.Layer) (io.ReadCloser, error) {
		// imagelayers drains a layer to its end without a bound of its
		// own; the blob reader ends at the size the manifest gives.
		return r.Registry.Blob(ctx, r.remote(j.image), l.Digest, l.Size)
	}
	v, err := imagelayers.BuildCached(ctx, pr.m.Layers, open, pr.cfg, r.Limits, pr.cache)
	if err != nil {
		return feed.ReleaseLine{}, err
	}
	pkgs, err := docker.ReadPackages(ctx, v.Source(), pr.cfg)
	partial := false
	switch {
	case errors.Is(err, docker.ErrNoPackageDatabase):
		// The release says what it is but its packages are unread: not
		// clean, incomplete.
		partial = true
	case err != nil:
		return feed.ReleaseLine{}, err
	}
	if len(pkgs.Packages) > inventory.MaxImagePackages {
		// The app's own manifest comes first and stays.
		pkgs.Packages, partial = pkgs.Packages[:inventory.MaxImagePackages], true
	}
	// A read may find the view incomplete, so Partial is asked after it.
	partial = partial || pkgs.Partial || v.Partial()
	return feed.ReleaseLine{
		AppID:          j.app.ID,
		Image:          j.image,
		Platform:       feed.PlatformOf(pr.m.Platform),
		ManifestDigest: pr.m.Digest,
		Distro:         pkgs.Distro,
		OS:             pkgs.OS,
		Partial:        partial,
		Packages:       pkgs.Packages,
	}, nil
}

// shipped returns the stored lines of every job's latest read (the read
// of this run where there was one), valid ones only.
func (r *Reader) shipped(ctx context.Context, jobs []job, cur map[job]readID, st *Stats) ([]feed.ReleaseLine, error) {
	now := r.Now()
	var out []feed.ReleaseLine
	for _, j := range jobs {
		prev, err := r.stored(ctx, j)
		if err != nil {
			return nil, err
		}
		for _, s := range prev {
			if s.digest == "" {
				// A stored line that does not decode.
				st.Invalid++
			}
		}
		id, known := cur[j]
		for _, s := range latest(prev, id, known) {
			if err := s.line.Validate(); err != nil || s.line.AppID != j.app.ID || s.line.Image != j.image {
				st.Invalid++
				r.log().Warn("release read: stored line left out", "app", j.app.ID, "image", j.image, "platform", s.platform, "err", err)
				continue
			}
			st.Lines++
			if s.line.Partial {
				st.Partial++
			}
			if now.Sub(s.line.Read) > StaleAfter {
				st.Stale++
			}
			out = append(out, s.line)
		}
	}
	return out, nil
}

// layerCache keeps layer records in the store's layer reads, as gzip
// JSON keyed by imagelayers.LayerKeys; a layer cut at a limit is never
// recorded, so the partial flag is always false. It remembers what it loaded for the
// build that follows the budget check. A store failure is kept in err, so
// the run ends instead of counting it as a registry failure.
type layerCache struct {
	store Store
	now   func() time.Time
	log   *slog.Logger
	recs  map[string]*imagelayers.LayerRecord
	err   error
}

// missing returns the most bytes building the view of layers with cfg
// fetches: the layers whose record is missing or not known to hold the
// content cfg reads, up to the layer at which the build reaches
// LayerBytes. The unpacked size of a layer not read yet is unknown; it is
// taken as the least its compressed size allows (minUnpacked), so the
// count goes on at least as far as the build does. A store failure is a
// *storeError.
func (c *layerCache) missing(ctx context.Context, layers []registry.Layer, cfg docker.ImageConfig, lim imagelayers.Limits) (int64, error) {
	keys, err := imagelayers.LayerKeys(layers, lim)
	if err != nil {
		return 0, err
	}
	bound := lim.LayerBytes
	if bound <= 0 {
		bound = imagelayers.DefaultLimits.LayerBytes
	}
	var need, unpacked int64
	for i, key := range keys {
		if unpacked >= bound {
			break
		}
		rec, err := c.Layer(ctx, key)
		if err != nil {
			return 0, &storeError{err}
		}
		switch {
		case rec != nil && rec.Covers(cfg):
			unpacked += rec.Used
		case rec != nil:
			need += layers[i].Size
			unpacked += rec.Used
		default:
			need += layers[i].Size
			unpacked += minUnpacked(layers[i].Size)
		}
	}
	return need, nil
}

// minUnpacked is a lower bound of the unpacked size of a compressed layer
// of size bytes: gzip and zstd add at most a few bytes per block (stored
// blocks of incompressible content) plus headers, a plain tar nothing.
func minUnpacked(size int64) int64 {
	return max(size-size/1024-1024, 0)
}

func (c *layerCache) Layer(ctx context.Context, key string) (*imagelayers.LayerRecord, error) {
	if rec, ok := c.recs[key]; ok {
		return rec, nil
	}
	b, _, ok, err := c.store.LayerRead(ctx, key)
	if err != nil {
		c.err = err
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	rec, err := decodeRecord(b)
	if err != nil {
		// A record that does not decode is read again and replaced.
		c.log.Warn("release read: layer record unreadable", "key", key, "err", err)
		return nil, nil
	}
	c.recs[key] = rec
	return rec, nil
}

func (c *layerCache) PutLayer(ctx context.Context, key string, rec *imagelayers.LayerRecord) error {
	b, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	if err := c.store.PutLayerRead(ctx, key, b, false, c.now()); err != nil {
		c.err = err
		return err
	}
	c.recs[key] = rec
	return nil
}

func encodeRecord(rec *imagelayers.LayerRecord) ([]byte, error) { return encodeGzipJSON(rec) }

func decodeRecord(b []byte) (*imagelayers.LayerRecord, error) {
	var rec imagelayers.LayerRecord
	if err := decodeGzipJSON(b, maxLayerRecord, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// encodeGzipJSON is the form of a layer read in the store.
func encodeGzipJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeGzipJSON decodes a layer read of at most max bytes unpacked.
func decodeGzipJSON(b []byte, max int64, v any) error {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(zr, max+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > max {
		return errors.New("layer read too large")
	}
	return json.Unmarshal(data, v)
}
