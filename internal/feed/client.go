// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/fsutil"
	"github.com/bifrost0x/varde/internal/store"
)

// Store is the persistence the feed client needs.
type Store interface {
	ApplyFeed(ctx context.Context, d store.FeedData, now time.Time) error
	FeedState(ctx context.Context) (store.FeedState, error)
	FeedFloor(ctx context.Context, channel string) (store.FeedFloor, error)
	TouchFeedVerified(ctx context.Context, sequence int64, now time.Time) error
	ClearFeed(ctx context.Context) error
	// ReplaceReleasePackages keeps the release package lists of the
	// active package, replacing those of the one before.
	// marker names the package's releases blob, so a start with the
	// package already kept does not write the table again.
	ReplaceReleasePackages(ctx context.Context, marker string, rows []store.ReleasePackageRow) error
	ReleasePackagesMarker(ctx context.Context) (string, error)
}

// Channel is one place the feed can come from. Channels share the trust
// root and the format; each has its own mirrors and its own rollback floor.
type Channel struct {
	Name    string
	Mirrors []Fetcher
}

// Channel names.
const (
	// ChannelPackage is the daily data package every installation reads.
	ChannelPackage = "package"
	// ChannelUplink is the subscription service.
	ChannelUplink = "uplink"
	// ChannelStatic is the feed of the static feed and hybrid modes.
	ChannelStatic = "feed"
)

// Client keeps the local copy of the feed current.
type Client struct {
	// Mirrors are tried in order; the first one that yields a verified
	// manifest wins. They are the static channel, used when Pick is nil.
	Mirrors []Fetcher
	// Pick, when set, chooses the channel of each update: the uplink
	// switch moves between the data package and the uplink at runtime.
	Pick func() Channel
	// Dir holds the trusted root, the active and previous manifests and the
	// blob cache.
	Dir   string
	Store Store
	// Catalog receives the feed catalog (plus local entries from LocalDir).
	Catalog  *catalog.Live
	LocalDir fs.FS
	Log      *slog.Logger
	Now      func() time.Time
	// MaxUnpacked caps the total uncompressed size (default 256 MB).
	MaxUnpacked int64
	// AllowDevelopment accepts roots marked "development" (feeds from
	// cmd/feedbuilder). Off by default, so a rotation cannot switch a
	// production installation to development keys.
	AllowDevelopment bool
	// InUse, when set, is asked under the client's lock before an update:
	// a refresh that was chosen while the feed was in use but runs after
	// it was left (Deactivate) must not install it again.
	InUse func() bool

	mu   sync.Mutex
	etag map[string]string // per mirror
	// index is the first-party index of the active package.
	index atomic.Pointer[applists.Table]
}

// Files inside Dir.
const (
	trustedRootFile = "root.json"
	activeManifest  = "manifest.json"
	activeSig       = "manifest.json.sig"
	previousDir     = "previous"
	blobDir         = "blobs"
)

// Init stores the initial trust root unless one is already trusted, and
// returns the trusted root. A stored root always wins, whatever its
// version: a different root reaches an installation only as a verified
// step of the chain, never through configuration or an update of Varde.
func (c *Client) Init(initialRoot []byte) (*Root, error) {
	if err := os.MkdirAll(filepath.Join(c.Dir, blobDir), 0o700); err != nil {
		return nil, fmt.Errorf("feed directory: %w", err)
	}
	stored, err := os.ReadFile(filepath.Join(c.Dir, trustedRootFile)) //nolint:gosec // fixed path in the data directory
	if err == nil {
		r, sigs, perr := ParseRoot(stored)
		if perr != nil {
			return nil, fmt.Errorf("stored trust root: %w", perr)
		}
		if err := r.verifySelf(sigs, r.Expires.Add(-time.Second)); err != nil {
			return nil, fmt.Errorf("stored trust root: %w", err)
		}
		if err := c.checkEnvironment(r); err != nil {
			return nil, fmt.Errorf("stored trust root: %w", err)
		}
		return r, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read trust root: %w", err)
	}
	if len(initialRoot) == 0 {
		return nil, errors.New("no feed trust root: set VARDE_FEED_ROOT_FILE to the root.json of the feed")
	}
	r, sigs, err := ParseRoot(initialRoot)
	if err != nil {
		return nil, fmt.Errorf("initial trust root: %w", err)
	}
	if err := c.checkEnvironment(r); err != nil {
		return nil, fmt.Errorf("initial trust root: %w", err)
	}
	// The initial root is trusted because the operator configured it; its
	// self-signature still has to hold.
	if err := r.verifySelf(sigs, r.Expires.Add(-time.Second)); err != nil {
		return nil, fmt.Errorf("initial trust root: %w", err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(c.Dir, trustedRootFile), initialRoot, 0o600); err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) trusted() (*Root, error) {
	data, err := os.ReadFile(filepath.Join(c.Dir, trustedRootFile)) //nolint:gosec // fixed path in the data directory
	if err != nil {
		return nil, fmt.Errorf("read trust root: %w", err)
	}
	r, _, err := ParseRoot(data)
	return r, err
}

// LoadActive verifies the installed manifest at startup and activates its
// catalog, so the server works offline with the last verified feed. An
// expired manifest is still used (better than nothing) and reported.
func (c *Client) LoadActive(ctx context.Context) error {
	root, err := c.trusted()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(c.Dir, activeManifest)) //nolint:gosec // fixed path in the data directory
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(c.Dir, activeSig)) //nolint:gosec // fixed path in the data directory
	if err != nil {
		return err
	}
	m, err := VerifyManifest(root, data, sig, c.now(), c.maxUnpacked())
	if err != nil {
		return fmt.Errorf("installed manifest: %w", err)
	}
	content, err := c.readContent(ctx, m, nil)
	if err != nil {
		return fmt.Errorf("installed feed: %w", err)
	}
	cat, err := c.buildCatalog(content)
	if err != nil {
		return fmt.Errorf("installed feed catalog: %w", err)
	}
	c.Catalog.Set(cat)
	c.index.Store(content.Index)
	c.setReleases(ctx, content.Releases, releasesMarker(m))
	if !c.now().Before(m.ExpiresAt) {
		c.Log.Warn("installed feed has expired; using it until a fresh one verifies", "sequence", m.Sequence, "expired", m.ExpiresAt)
	}
	c.Log.Info("feed loaded", "sequence", m.Sequence, "catalog", m.CatalogVersion, "apps", cat.Len())
	return nil
}

// Deactivate leaves the feed: base becomes the catalog again, the feed's
// advisories are removed and the installed manifest is forgotten, so a
// later Update installs the current snapshot afresh. The trusted root, the
// blob cache and the stored sequence stay; the sequence keeps refusing
// older feeds.
func (c *Client) Deactivate(ctx context.Context, base *catalog.Catalog) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range []string{activeManifest, activeSig} {
		if err := os.Remove(filepath.Join(c.Dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("leave feed: %w", err)
		}
	}
	c.etag = nil
	c.index.Store(nil)
	c.setReleases(ctx, nil, "")
	// The catalog first: even when the database refuses, analysis must not
	// go on with the feed's catalog. The caller repeats a failed leave.
	c.Catalog.Set(base)
	return c.Store.ClearFeed(ctx)
}

// ActiveChannel names the channel of the installed manifest, or "" when
// none is installed (never updated, or left with Deactivate). It does not
// wait for a running update: the manifest file is replaced atomically, and
// during an install it answers for the state before or after it.
func (c *Client) ActiveChannel(ctx context.Context) string {
	st, err := c.Store.FeedState(ctx)
	if err != nil || !c.activeMatches(st) {
		return ""
	}
	return st.Channel
}

// Index returns the first-party index of the active package, or nil when
// no package is active or it carries none. Safe for concurrent use.
func (c *Client) Index() *applists.Table { return c.index.Load() }

// setReleases keeps the release package lists of a package in the store,
// where the pages read them per app image; a package without them clears
// the table. They are not kept in memory: only the pages read them, a few
// at a time. Release lists only answer which release
// fixes a finding: failing to keep them is logged and leaves the catalog
// and the advisories of the package applied. marker is the digest of the
// releases blob (releasesMarker): when the store already holds that blob's
// lists, as on most starts, they are not written again.
func (c *Client) setReleases(ctx context.Context, lines []ReleaseLine, marker string) {
	if kept, err := c.Store.ReleasePackagesMarker(ctx); err != nil {
		c.Log.Warn("release package lists: stored marker not readable; writing them again", "err", err)
	} else if kept == marker {
		return
	}
	rows := make([]store.ReleasePackageRow, 0, len(lines))
	for _, l := range lines {
		data, err := json.Marshal(l)
		if err != nil {
			c.Log.Warn("release package list not kept", "app", l.AppID, "image", l.Image, "err", err)
			continue
		}
		rows = append(rows, store.ReleasePackageRow{AppID: l.AppID, Image: l.Image, Platform: l.Platform.Key(),
			Tag: l.Tag, Version: l.Version, Line: data})
	}
	if err := c.Store.ReplaceReleasePackages(ctx, marker, rows); err != nil {
		c.Log.Warn("release package lists of the package not kept; release fixes are not shown until the next package", "err", err)
	}
}

// releasesMarker names the releases blob of m: its digest, or "" when the
// package has none (the state of an empty table).
func releasesMarker(m *Manifest) string {
	for _, b := range m.Blobs {
		if b.Name == "releases" {
			return "sha256:" + b.SHA256
		}
	}
	return ""
}

// buildCatalog makes the catalog of a package: the reviewed entries over
// the generated ones, and the local directory over both. Generated entries
// that collide with reviewed ones are dropped, not refused.
func (c *Client) buildCatalog(content *Content) (*catalog.Catalog, error) {
	cat, err := catalog.BuildLayered(content.Catalog, catalog.OriginFeed, content.Generated, c.LocalDir)
	if err != nil {
		return nil, err
	}
	if dropped := cat.DroppedGenerated(); len(dropped) > 0 {
		c.Log.Info("generated catalog entries left out", "count", len(dropped), "first", dropped[0])
	}
	return cat, nil
}

// Forget removes the installed manifest from dir, the feed directory of a
// client that is not running, so that a later client installs afresh. The
// trusted root and the blob cache stay.
func Forget(dir string) error {
	var errs []error
	for _, name := range []string{activeManifest, activeSig} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Result reports what Update did.
type Result struct {
	Mirror    string
	Sequence  int64
	Applied   bool
	Unchanged bool
}

// Update runs the client update algorithm against the mirrors in order.
// Any failure leaves the previous verified state active.
func (c *Client) Update(ctx context.Context) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The requester may have given up while another update held the lock.
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if c.InUse != nil && !c.InUse() {
		return Result{}, ErrNotInUse
	}
	ch := Channel{Name: ChannelStatic, Mirrors: c.Mirrors}
	if c.Pick != nil {
		ch = c.Pick()
	}
	if len(ch.Mirrors) == 0 {
		return Result{}, errors.New("no feed mirror configured")
	}
	var errs []error
	for _, m := range ch.Mirrors {
		res, err := c.updateFrom(ctx, ch.Name, m)
		if err == nil {
			res.Mirror = m.String()
			return res, nil
		}
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		c.Log.Warn("feed mirror failed", "mirror", m.String(), "err", err)
		errs = append(errs, fmt.Errorf("%s: %w", m.String(), err))
	}
	return Result{}, errors.Join(errs...)
}

func (c *Client) updateFrom(ctx context.Context, channel string, f Fetcher) (Result, error) {
	now := c.now()
	root, err := c.updateRoot(ctx, f, now)
	if err != nil {
		return Result{}, err
	}
	if !now.Before(root.Expires) {
		return Result{}, fmt.Errorf("trust root version %d: %w", root.Version, ErrExpired)
	}

	if c.etag == nil {
		c.etag = map[string]string{}
	}
	state, stateErr := c.Store.FeedState(ctx)
	if stateErr != nil && !errors.Is(stateErr, store.ErrNotFound) {
		return Result{}, stateErr
	}
	// The installed manifest only counts when it came from this channel:
	// after a switch the picked channel is installed afresh.
	haveState := stateErr == nil && state.Channel == channel
	floor, err := c.Store.FeedFloor(ctx, channel)
	if err != nil {
		return Result{}, err
	}
	etag := ""
	if haveState && c.activeMatches(state) {
		etag = c.etag[f.String()]
	}
	data, newETag, notModified, err := f.Get(ctx, "v1/manifest.json", etag, maxMetadataBytes)
	if err != nil {
		return Result{}, err
	}
	if notModified {
		// Unchanged since the last verified fetch from this mirror; the
		// stored manifest must still be fresh (freeze protection).
		if !now.Before(state.ExpiresAt) {
			return Result{}, fmt.Errorf("manifest %d unchanged but expired at %s: %w", state.Sequence, state.ExpiresAt.Format(time.RFC3339), ErrExpired)
		}
		if err := c.Store.TouchFeedVerified(ctx, state.Sequence, now); err != nil {
			return Result{}, err
		}
		return Result{Sequence: state.Sequence, Unchanged: true}, nil
	}
	sig, _, _, err := f.Get(ctx, "v1/manifest.json.sig", "", maxMetadataBytes)
	if err != nil {
		return Result{}, err
	}
	m, err := VerifyManifest(root, data, sig, now, c.maxUnpacked())
	if err != nil {
		return Result{}, err
	}
	// The static channel reads manifests that name no channel; the others
	// read only their own.
	want := channel
	if channel == ChannelStatic {
		want = ""
	}
	if m.Channel != want {
		return Result{}, fmt.Errorf("manifest %d is for channel %q, not %q: %w", m.Sequence, m.Channel, channel, ErrMismatch)
	}
	if !now.Before(m.ExpiresAt) {
		return Result{}, fmt.Errorf("manifest %d expired at %s: %w", m.Sequence, m.ExpiresAt.Format(time.RFC3339), ErrExpired)
	}
	if m.CreatedAt.After(now.Add(time.Hour)) {
		return Result{}, fmt.Errorf("manifest %d created in the future (%s); check the clock", m.Sequence, m.CreatedAt.Format(time.RFC3339))
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	switch {
	case m.Sequence < floor.Sequence:
		return Result{}, fmt.Errorf("manifest sequence %d < applied %d: %w", m.Sequence, floor.Sequence, ErrRollback)
	case m.Sequence == floor.Sequence && hash != floor.ManifestSHA256:
		return Result{}, fmt.Errorf("manifest sequence %d reused with different content: %w", m.Sequence, ErrRollback)
	}
	if haveState && m.Sequence == state.Sequence && c.activeMatches(state) {
		if err := c.Store.TouchFeedVerified(ctx, state.Sequence, now); err != nil {
			return Result{}, err
		}
		c.etag[f.String()] = newETag
		return Result{Sequence: m.Sequence, Unchanged: true}, nil
	}

	content, err := c.readContent(ctx, m, f)
	if err != nil {
		return Result{}, err
	}
	cat, err := c.buildCatalog(content)
	if err != nil {
		return Result{}, fmt.Errorf("feed catalog: %w", err)
	}
	if err := c.install(ctx, channel, m, data, sig, hash, content, now); err != nil {
		return Result{}, err
	}
	c.Catalog.Set(cat)
	c.index.Store(content.Index)
	c.setReleases(ctx, content.Releases, releasesMarker(m))
	c.etag[f.String()] = newETag
	c.gc(m)
	c.Log.Info("feed applied", "channel", channel, "sequence", m.Sequence, "catalog", m.CatalogVersion, "advisories", len(content.Advisories), "mirror", f.String())
	return Result{Sequence: m.Sequence, Applied: true}, nil
}

// updateRoot walks the root chain from the trusted version to the newest
// one the mirror offers. Every step is verified before it is stored.
func (c *Client) updateRoot(ctx context.Context, f Fetcher, now time.Time) (*Root, error) {
	trusted, err := c.trusted()
	if err != nil {
		return nil, err
	}
	latestData, _, _, err := f.Get(ctx, "v1/root.json", "", maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	latest, _, err := ParseRoot(latestData)
	if err != nil {
		return nil, err
	}
	if latest.Version < trusted.Version {
		return nil, fmt.Errorf("mirror offers root version %d, %d is trusted: %w", latest.Version, trusted.Version, ErrRollback)
	}
	for v := trusted.Version + 1; v <= latest.Version; v++ {
		data := latestData
		if v < latest.Version {
			if data, _, _, err = f.Get(ctx, fmt.Sprintf("v1/root/%d.json", v), "", maxMetadataBytes); err != nil {
				return nil, fmt.Errorf("root version %d: %w", v, err)
			}
		}
		next, sigs, err := ParseRoot(data)
		if err != nil {
			return nil, err
		}
		if err := VerifyRootUpdate(trusted, next, sigs, now); err != nil {
			return nil, err
		}
		if err := c.checkEnvironment(next); err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(filepath.Join(c.Dir, trustedRootFile), data, 0o600); err != nil {
			return nil, err
		}
		c.Log.Info("feed trust root updated", "version", next.Version)
		trusted = next
	}
	return trusted, nil
}

// readContent loads every blob, from the cache or the fetcher (nil means
// cache only), verifies hashes before decompressing and parses the result.
func (c *Client) readContent(ctx context.Context, m *Manifest, f Fetcher) (*Content, error) {
	content := &Content{}
	for _, b := range m.Blobs {
		if !knownBlob(b.Name) {
			continue
		}
		path := filepath.Join(c.Dir, blobDir, b.SHA256)
		data, err := os.ReadFile(path) //nolint:gosec // name is a validated hex hash
		if err == nil && checkHash(b, data) != nil {
			data, err = nil, os.ErrNotExist // corrupt cache entry: fetch again
		}
		if err != nil {
			if f == nil {
				return nil, fmt.Errorf("blob %s missing from the cache", b.Name)
			}
			if data, _, _, err = f.Get(ctx, "v1/blobs/sha256/"+b.SHA256, "", b.Size); err != nil {
				return nil, fmt.Errorf("blob %s: %w", b.Name, err)
			}
			if err := checkHash(b, data); err != nil {
				return nil, err
			}
			if err := fsutil.WriteFileAtomic(path, data, 0o600); err != nil {
				return nil, err
			}
		}
		raw, err := unpack(b, data)
		if err != nil {
			return nil, err
		}
		if err := content.parse(b, raw); err != nil {
			return nil, err
		}
	}
	return content, nil
}

// install applies the verified content: database first (one transaction),
// then the manifest files (previous kept for fallback). A crash between the
// two leaves the database ahead; activeMatches then forces a reinstall of
// the same sequence on the next update.
func (c *Client) install(ctx context.Context, channel string, m *Manifest, data, sig []byte, hash string, content *Content, now time.Time) error {
	err := c.Store.ApplyFeed(ctx, store.FeedData{
		State:      store.FeedState{Channel: channel, Sequence: m.Sequence, ManifestSHA256: hash, CreatedAt: m.CreatedAt, ExpiresAt: m.ExpiresAt, VerifiedAt: now},
		Advisories: content.Advisories, KEV: content.KEV, EPSS: content.EPSS,
	}, now)
	if err != nil {
		return err
	}
	prev := filepath.Join(c.Dir, previousDir)
	if err := os.MkdirAll(prev, 0o700); err != nil {
		return fmt.Errorf("feed directory: %w", err)
	}
	for _, name := range []string{activeManifest, activeSig} {
		if old, err := os.ReadFile(filepath.Join(c.Dir, name)); err == nil { //nolint:gosec // fixed path
			if err := fsutil.WriteFileAtomic(filepath.Join(prev, name), old, 0o600); err != nil {
				return err
			}
		}
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(c.Dir, activeSig), sig, 0o600); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(c.Dir, activeManifest), data, 0o600)
}

// activeMatches reports whether the manifest file on disk is the one the
// database says was applied.
func (c *Client) activeMatches(st store.FeedState) bool {
	data, err := os.ReadFile(filepath.Join(c.Dir, activeManifest)) //nolint:gosec // fixed path
	if err != nil {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == st.ManifestSHA256
}

// gc removes blobs referenced by neither the active nor the previous
// manifest.
func (c *Client) gc(active *Manifest) {
	keep := map[string]bool{}
	for _, b := range active.Blobs {
		keep[b.SHA256] = true
	}
	if root, err := c.trusted(); err == nil {
		data, err1 := os.ReadFile(filepath.Join(c.Dir, previousDir, activeManifest)) //nolint:gosec // fixed path
		sig, err2 := os.ReadFile(filepath.Join(c.Dir, previousDir, activeSig))       //nolint:gosec // fixed path
		if err1 == nil && err2 == nil {
			// Signatures are not re-checked against key windows here: the
			// file only decides which cache entries to keep.
			if prev, err := VerifyManifest(root, data, sig, c.now(), c.maxUnpacked()); err == nil {
				for _, b := range prev.Blobs {
					keep[b.SHA256] = true
				}
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(c.Dir, blobDir))
	if err != nil {
		return
	}
	for _, e := range entries {
		if !keep[e.Name()] && !strings.HasPrefix(e.Name(), ".") {
			_ = os.Remove(filepath.Join(c.Dir, blobDir, e.Name()))
		}
	}
}

func (c *Client) maxUnpacked() int64 {
	if c.MaxUnpacked > 0 {
		return c.MaxUnpacked
	}
	return DefaultMaxUnpacked
}

// ErrNotInUse reports an update of a feed that is switched off.
var ErrNotInUse = errors.New("the feed is not in use")

// ErrDevelopmentRoot reports a development root without explicit opt-in.
var ErrDevelopmentRoot = errors.New("development trust root refused; set VARDE_FEED_ALLOW_DEVELOPMENT_ROOT=true only for tests")

func (c *Client) checkEnvironment(r *Root) error {
	if r.Environment == EnvDevelopment && !c.AllowDevelopment {
		return fmt.Errorf("root version %d: %w", r.Version, ErrDevelopmentRoot)
	}
	return nil
}
