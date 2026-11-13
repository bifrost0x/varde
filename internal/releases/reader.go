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
	"github.com/bifrost0x/varde/internal/store"
)

// DefaultMaxManifests and DefaultMaxBytes are the budgets of one run when
// the Reader leaves them zero: manifest requests (Docker Hub counts them as
// pulls) and bytes read from registries.
const (
	DefaultMaxManifests = 600
	DefaultMaxBytes     = 20 << 30
)

// Defaults of the time bounds of the registry work (Reader).
const (
	DefaultImageTimeout = 30 * time.Minute
	DefaultBlobTimeout  = 2 * time.Minute
	DefaultBlobRate     = 1 << 20
	DefaultOverrun      = 20 * time.Minute
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

// Platforms are the platforms read of every release. arm64 matches every
// variant; each image of the index is read and stored under the platform
// of its line, variant included (feed.ReleasePlatform.Key).
var Platforms = []registry.Platform{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}}

// versionRe is the bound feed.ReleaseLine.Validate puts on a version; a
// tag whose version fails it is not read at all.
var versionRe = regexp.MustCompile(`^[A-Za-z0-9._+~:-]{1,128}$`)

// Store is the builder state the reader keeps; *store.Store has it.
type Store interface {
	LayerRead(ctx context.Context, digest string) (files []byte, partial, ok bool, err error)
	PutLayerRead(ctx context.Context, digest string, files []byte, partial bool, readAt time.Time) error
	ReleaseReadPlatforms(ctx context.Context, appID, image string) ([]string, error)
	ReleaseRead(ctx context.Context, appID, image, platform string) (tag, indexDigest string, line []byte, ok bool, err error)
	PutReleaseRead(ctx context.Context, appID, image, platform, tag, indexDigest string, line []byte, readAt time.Time) error
	ReleaseReadLimits(ctx context.Context, appID, image, platform string) (string, error)
	SetReleaseReadLimits(ctx context.Context, appID, image, platform, limits string) error
	ReleaseReadLayers(ctx context.Context, appID, image, platform string) (string, error)
	SetReleaseReadLayers(ctx context.Context, appID, image, platform, layers string) error
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
	// MaxShipBytes is the size of the releases blob the lines read are
	// for (feed.DefaultReleasesBudget when zero): once the lines of the
	// images read so far fill it, no image starts, since what a later
	// image adds would not ship.
	MaxShipBytes int64
	Log          *slog.Logger
	// Deadline, when set, ends the run's registry work: no image starts
	// after it, as when a budget is spent. It keeps the data build inside
	// its time limit; the images left are read by a later build. An image
	// started before it is cut Overrun after it.
	Deadline time.Time

	// The registry work of one image and of one blob is bounded in time,
	// so a registry that answers slowly or trickles a blob costs that
	// image, not the build: ImageTimeout bounds an image (default
	// DefaultImageTimeout), BlobTimeout plus the time the blob's size
	// takes at BlobRate bytes a second one blob (defaults
	// DefaultBlobTimeout and DefaultBlobRate), Overrun how long an image
	// may run past the Deadline (default DefaultOverrun). The store is
	// not bounded by them.
	ImageTimeout, BlobTimeout, Overrun time.Duration
	BlobRate                           int64

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
	// DeadlinePassed says the Deadline stopped the run; ShipFull says the
	// lines of the images before filled MaxShipBytes.
	DeadlinePassed, ShipFull bool
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
// ID), and returns the lines to ship, in that order. A budget spent, the
// Deadline, or lines that fill MaxShipBytes stop new reads; what was read
// by then ships, and so does every earlier line of an app image that is
// still in the catalog, with its read time. A registry failure costs the
// image; only a store failure or the end of ctx ends the run.
func (r *Reader) Run(ctx context.Context, cat *catalog.Catalog, order []string) ([]feed.ReleaseLine, Stats, error) {
	var st Stats
	start := r.Registry.Budget()
	jobs := r.jobs(cat, order)
	st.Images = len(jobs)
	cur := map[job]readID{}
	ship := r.MaxShipBytes
	if ship <= 0 {
		ship = feed.DefaultReleasesBudget
	}
	var size feed.ReleaseSizer
	var out []feed.ReleaseLine
	for _, j := range jobs {
		if err := ctx.Err(); err != nil {
			return nil, st, err
		}
		if !r.Deadline.IsZero() && !r.Now().Before(r.Deadline) {
			st.DeadlinePassed = true
		}
		st.ShipFull = st.ShipFull || size.Size >= ship
		if !st.BudgetSpent && !st.DeadlinePassed && !st.ShipFull {
			if err := r.read(ctx, j, start, &st, cur); err != nil {
				return nil, st, err
			}
		} else {
			st.NotStarted++
		}
		lines, err := r.jobLines(ctx, j, cur, &st)
		if err != nil {
			return nil, st, err
		}
		if _, err := size.Add(lines); err != nil {
			return nil, st, err
		}
		out = append(out, lines...)
	}
	used := r.usage(start)
	st.Manifests, st.Bytes = used.ManifestRequests, used.Bytes
	return out, st, nil
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
	platform, tag, digest, limits, layers string
	line                                  feed.ReleaseLine
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
	// Registry requests run under the image's time bound; the store and
	// the end of the run under ctx alone.
	rctx, cancel := r.imageContext(ctx)
	defer cancel()
	tags, complete, err := r.Registry.AllTags(rctx, r.remote(j.image))
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
	digest, err := r.Registry.Digest(rctx, r.remote(j.image), tag)
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
	ms, index, err := r.Registry.Image(rctx, r.remote(j.image), tag, Platforms)
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
		cfg, err := r.config(ctx, rctx, j.image, m.ConfigDigest)
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
	// The layer reads each platform's read used: its config and its layer
	// records. The builder keeps only layer reads a stored read names.
	used := make(map[string]string, len(reads))
	for _, pr := range reads {
		keys, err := imagelayers.LayerKeys(pr.m.Layers, r.Limits)
		if err != nil {
			return failed("release read: layers refused", err)
		}
		b, err := json.Marshal(append([]string{pr.m.ConfigDigest}, keys...))
		if err != nil {
			return err
		}
		used[pr.m.Digest] = string(b)
	}
	for _, pr := range reads {
		l, err := r.readPlatform(ctx, rctx, j, pr)
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
			log.Warn("release read: line left out", "platform", l.Platform.Key(), "err", err)
			continue
		}
		b, err := json.Marshal(l)
		if err != nil {
			return err
		}
		if len(b) >= maxLineBytes {
			st.Invalid++
			log.Warn("release read: line left out", "platform", l.Platform.Key(), "err", "longer than an installation reads")
			continue
		}
		// Keyed with the variant, as installations keep the lines: two
		// images of one architecture in different variants are two reads.
		key := l.Platform.Key()
		if err := r.PutReleaseRead(ctx, j.app.ID, j.image, key, tag, index, b, now); err != nil {
			return err
		}
		if err := r.SetReleaseReadLimits(ctx, j.app.ID, j.image, key, limits); err != nil {
			return err
		}
		if err := r.SetReleaseReadLayers(ctx, j.app.ID, j.image, key, used[l.ManifestDigest]); err != nil {
			return err
		}
	}
	return nil
}

// stored returns the stored reads of an image's platforms.
func (r *Reader) stored(ctx context.Context, j job) ([]stored, error) {
	platforms, err := r.ReleaseReadPlatforms(ctx, j.app.ID, j.image)
	if err != nil {
		return nil, err
	}
	var out []stored
	for _, p := range platforms {
		tag, digest, b, ok, err := r.ReleaseRead(ctx, j.app.ID, j.image, p)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		s := stored{platform: p, tag: tag, digest: digest}
		if err := json.Unmarshal(b, &s.line); err != nil || s.line.Platform.Key() != p {
			// Read again: the line is replaced. A line stored under
			// another platform than its own would ship next to the line
			// of that platform.
			s.digest = ""
		}
		if s.limits, err = r.ReleaseReadLimits(ctx, j.app.ID, j.image, s.platform); err != nil {
			return nil, err
		}
		if s.layers, err = r.ReleaseReadLayers(ctx, j.app.ID, j.image, s.platform); err != nil {
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
		if err := r.SetReleaseReadLayers(ctx, j.app.ID, j.image, s.platform, s.layers); err != nil {
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
//
// The store is asked under ctx, the registry under rctx.
func (r *Reader) config(ctx, rctx context.Context, image, digest string) (docker.ImageConfig, error) {
	var cfg docker.ImageConfig
	b, _, ok, err := r.LayerRead(ctx, digest)
	if err != nil {
		return cfg, &storeError{err}
	}
	if ok && decodeGzipJSON(b, maxConfigBytes, &cfg) == nil {
		return cfg, nil
	}
	cfg, err = r.fetchConfig(rctx, image, digest)
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

// imageContext bounds the registry work of one image: ImageTimeout, and
// no later than Overrun after the Deadline. Durations, not the Reader's
// clock, set the bound: Now may be a test's or a replayed clock.
func (r *Reader) imageContext(ctx context.Context) (context.Context, context.CancelFunc) {
	d := orDuration(r.ImageTimeout, DefaultImageTimeout)
	if !r.Deadline.IsZero() {
		d = min(d, r.Deadline.Sub(r.Now())+orDuration(r.Overrun, DefaultOverrun))
	}
	return context.WithTimeout(ctx, d)
}

// blob opens a blob of image under a time bound of its own: BlobTimeout
// plus the time max bytes take at BlobRate, within ctx's bound. The bound
// ends when the blob is closed.
func (r *Reader) blob(ctx context.Context, image, digest string, max int64) (io.ReadCloser, error) {
	rate := r.BlobRate
	if rate <= 0 {
		rate = DefaultBlobRate
	}
	d := orDuration(r.BlobTimeout, DefaultBlobTimeout) + time.Duration(max/rate)*time.Second
	bctx, cancel := context.WithTimeout(ctx, d)
	rc, err := r.Registry.Blob(bctx, r.remote(image), digest, max)
	if err != nil {
		cancel()
		return nil, err
	}
	return &boundBlob{ReadCloser: rc, cancel: cancel}, nil
}

// boundBlob ends a blob's time bound when it is closed.
type boundBlob struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *boundBlob) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

func orDuration(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// storeError marks a store failure among the registry's.
type storeError struct{ err error }

func (e *storeError) Error() string { return e.err.Error() }
func (e *storeError) Unwrap() error { return e.err }

func (r *Reader) fetchConfig(ctx context.Context, image, digest string) (docker.ImageConfig, error) {
	rc, err := r.blob(ctx, image, digest, maxConfigBytes)
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

// readPlatform squashes one platform's layers and reads its packages. The
// layer cache works under ctx, the registry under rctx.
func (r *Reader) readPlatform(ctx, rctx context.Context, j job, pr platformRead) (feed.ReleaseLine, error) {
	open := func(_ context.Context, l registry.Layer) (io.ReadCloser, error) {
		// imagelayers drains a layer to its end without a bound of its
		// own; the blob reader ends at the size the manifest gives, and
		// the blob's time bound at the time that size may take.
		return r.blob(rctx, j.image, l.Digest, l.Size)
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

// jobLines returns the stored lines of a job's latest read (the read of
// this run where there was one), valid ones only.
func (r *Reader) jobLines(ctx context.Context, j job, cur map[job]readID, st *Stats) ([]feed.ReleaseLine, error) {
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
	var out []feed.ReleaseLine
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
		if r.Now().Sub(s.line.Read) > StaleAfter {
			st.Stale++
		}
		out = append(out, s.line)
	}
	return out, nil
}

// StoreKey names the stored release read a shipped line came from: the
// store keeps one read per app, image and platform with its variant.
func StoreKey(l feed.ReleaseLine) store.ReleaseReadKey {
	return store.ReleaseReadKey{AppID: l.AppID, Image: l.Image, Platform: l.Platform.Key()}
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
