// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/store"
)

// Defaults of the Checker.
const (
	// DefaultTTL is how long a registry answer stands before the image is
	// asked again: rebuilt images appear within hours, and Docker Hub
	// limits anonymous clients.
	DefaultTTL = 6 * time.Hour
	// DefaultPerRun bounds the images asked per run; each costs one or
	// two HEAD requests (Docker Hub does not count them as pulls) and,
	// for a pinned tag without a stored tag list, one tag list.
	DefaultPerRun = 10
	// DefaultReadsPerRun bounds the candidate images read per run.
	DefaultReadsPerRun = 2
	// DefaultReadBytes bounds the layer bytes of one candidate read.
	DefaultReadBytes = 1 << 30
	// maxLayerCache bounds the layer reads kept for candidate reads.
	maxLayerCache = 256 << 20
)

// Store is what the Checker reads and writes.
type Store interface {
	Workloads(ctx context.Context, f store.WorkloadFilter) ([]inventory.Workload, error)
	Hosts(ctx context.Context) ([]inventory.Host, error)
	Findings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	RepositoryTags(ctx context.Context) (map[string]store.RepositoryTags, error)
	UpstreamChecks(ctx context.Context) (map[store.UpstreamKey]store.UpstreamCheck, error)
	RecordUpstreamCheck(ctx context.Context, c store.UpstreamCheck) error
	PruneUpstreamChecks(ctx context.Context, keep map[store.UpstreamKey]bool) error
	TrimLayerReads(ctx context.Context, maxBytes int64) (int, error)
}

// Registry is the part of the registry client the Checker uses: HEAD
// requests for digests and tag lists.
type Registry interface {
	Digest(ctx context.Context, repository, tag string) (string, error)
	Tags(ctx context.Context, repository string) ([]string, error)
}

// CandidateReader reads the package list of an image in the registry
// (releases.Reader.ReadImage).
type CandidateReader interface {
	ReadImage(ctx context.Context, image, ref string, platform registry.Platform, maxBytes int64) (remedy.Candidate, error)
}

// Checker asks the registries, for every container with image findings,
// whether a newer image exists: what the running tag points to now and the
// newest tag on its track. It only reads; it never pulls or recreates
// anything. With ReadCandidates on it also reads the package list of a
// newer image, so Varde can tell what that image fixes.
type Checker struct {
	Client Registry
	Reader CandidateReader
	Store  Store
	// Enabled reads the registry setting on every run; ReadCandidates the
	// setting that allows reading candidate images; CrossMajor the one
	// that lets a track cross a major version. Nil means off.
	Enabled, ReadCandidates, CrossMajor func() bool
	// TTL is how long an answer stands (DefaultTTL when zero).
	TTL time.Duration
	// PerRun, ReadsPerRun and ReadBytes bound a run (defaults above).
	PerRun, ReadsPerRun int
	ReadBytes           int64
	// Changed runs the analysis after an answer changed.
	Changed func(ctx context.Context)
	Log     *slog.Logger
	Now     func() time.Time
}

// Run checks every interval until ctx ends.
func (c *Checker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if on(c.Enabled) {
			if n, err := c.Once(ctx); err != nil && ctx.Err() == nil {
				c.Log.Warn("upstream check failed", "err", err)
			} else if n > 0 && c.Changed != nil {
				c.Changed(ctx)
			}
		}
		t.Reset(interval)
	}
}

func on(f func() bool) bool { return f != nil && f() }

// job is one running image to ask about.
type job struct {
	key      store.UpstreamKey
	platform registry.Platform
}

// Jobs lists the running images of containers with active, affected image
// findings, each once, and the keys of every such image (for pruning).
func Jobs(ws []inventory.Workload, hosts []inventory.Host, fs []store.Finding) ([]job, map[store.UpstreamKey]bool) {
	withImage := map[string]bool{}
	for _, f := range fs {
		if f.MatchState != string(match.Affected) || f.State == store.StateResolved {
			continue
		}
		if _, _, ok := distro.ParseSystemAppID(f.AppID); !ok {
			continue
		}
		var m match.Finding
		if json.Unmarshal(f.Detail, &m) == nil && m.Image {
			withImage[f.WorkloadID] = true
		}
	}
	arch := map[string]string{}
	for _, h := range hosts {
		arch[h.ID] = h.Arch
	}
	var out []job
	keys := map[store.UpstreamKey]bool{}
	for _, w := range ws {
		if w.Container == nil || w.RemovedAt != nil || !withImage[w.ID] {
			continue
		}
		p := remedy.HostPlatform(arch[w.HostID])
		k, ok := KeyOf(w.Container, p)
		if !ok || keys[k] {
			continue
		}
		keys[k] = true
		out = append(out, job{key: k, platform: p})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].key, out[j].key
		if a.Repository != b.Repository {
			return a.Repository < b.Repository
		}
		if a.Tag != b.Tag {
			return a.Tag < b.Tag
		}
		return a.RunningDigest+a.Platform < b.RunningDigest+b.Platform
	})
	return out, keys
}

// Once runs one round and returns how many answers changed.
func (c *Checker) Once(ctx context.Context) (int, error) {
	ws, err := c.Store.Workloads(ctx, store.WorkloadFilter{Kind: inventory.KindContainer})
	if err != nil {
		return 0, err
	}
	hosts, err := c.Store.Hosts(ctx)
	if err != nil {
		return 0, err
	}
	fs, err := c.Store.Findings(ctx, store.FindingFilter{})
	if err != nil {
		return 0, err
	}
	known, err := c.Store.UpstreamChecks(ctx)
	if err != nil {
		return 0, err
	}
	tagLists, err := c.Store.RepositoryTags(ctx)
	if err != nil {
		return 0, err
	}
	jobs, keep := Jobs(ws, hosts, fs)
	now := c.now()
	// Images never asked first, then the oldest answers.
	sort.SliceStable(jobs, func(i, j int) bool {
		return known[jobs[i].key].Checked.Before(known[jobs[j].key].Checked)
	})
	listed := map[string][]string{}
	changed, asked, reads := 0, 0, 0
	for _, j := range jobs {
		prev, had := known[j.key]
		if had && now.Sub(prev.Checked) < c.ttl() && !c.wantsRead(prev, reads) {
			continue
		}
		if asked >= c.perRun() {
			break
		}
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		asked++
		rec := c.check(ctx, j, prev, tagLists, listed, &reads, now)
		if err := c.Store.RecordUpstreamCheck(ctx, rec); err != nil {
			return changed, err
		}
		if !had || differs(prev, rec) {
			changed++
		}
	}
	if err := c.Store.PruneUpstreamChecks(ctx, keep); err != nil {
		return changed, err
	}
	if reads > 0 {
		if _, err := c.Store.TrimLayerReads(ctx, maxLayerCache); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// wantsRead reports whether an answer that still stands lacks a candidate
// read that this run may make.
func (c *Checker) wantsRead(prev store.UpstreamCheck, reads int) bool {
	return c.Reader != nil && on(c.ReadCandidates) && prev.Error == "" && prev.CandidateDigest != "" &&
		prev.Candidate == nil && prev.CandidateError == "" && reads < c.readsPerRun()
}

// check asks the registry about one image. Every failure ends in the
// record's Error, in the words of the pages, and is logged; none is taken
// for an answer.
func (c *Checker) check(ctx context.Context, j job, prev store.UpstreamCheck, tagLists map[string]store.RepositoryTags, listed map[string][]string, reads *int, now time.Time) store.UpstreamCheck {
	rec := store.UpstreamCheck{UpstreamKey: j.key, Checked: now}
	log := c.Log.With("repository", j.key.Repository, "tag", j.key.Tag)
	fail := func(what string, err error) store.UpstreamCheck {
		rec.Error = registry.Reason(err)
		log.Info("upstream check: "+what, "reason", rec.Error, "err", err)
		return rec
	}
	head, err := c.Client.Digest(ctx, j.key.Repository, j.key.Tag)
	if err != nil {
		return fail("tag digest not read", err)
	}
	rec.HeadDigest = head
	if head != j.key.RunningDigest {
		// The tag was moved: a rebuilt floating tag, or a re-pushed one.
		rec.CandidateTag, rec.CandidateDigest = j.key.Tag, head
	}
	if !Floating(j.key.Tag) {
		// A version tag may have a newer release on its track, which
		// stands above a rebuild of the running one: a rebuild that fixes
		// nothing must not hide a release that does.
		tags, err := c.tags(ctx, j.key.Repository, tagLists, listed)
		if err != nil {
			return fail("tag list not read", err)
		}
		newer, ok := Track(j.key.Tag, tags, on(c.CrossMajor))
		if ok && newer != "" {
			d, err := c.Client.Digest(ctx, j.key.Repository, newer)
			if err != nil {
				return fail("digest of the newer tag not read", err)
			}
			rec.CandidateTag, rec.CandidateDigest = newer, d
		}
	}
	if rec.CandidateDigest == "" {
		return rec
	}
	// A candidate read stands as long as the candidate does: an image
	// under one digest never changes. So does a failure that a read of the
	// same image would repeat; any other is tried again.
	if prev.CandidateDigest == rec.CandidateDigest && (prev.Candidate != nil || lasting(prev.CandidateError)) {
		rec.Candidate, rec.CandidateReadAt, rec.CandidateError = prev.Candidate, prev.CandidateReadAt, prev.CandidateError
		return rec
	}
	if c.Reader == nil || !on(c.ReadCandidates) || *reads >= c.readsPerRun() {
		return rec
	}
	*reads++
	cand, err := c.Reader.ReadImage(ctx, j.key.Repository, rec.CandidateDigest, j.platform, c.readBytes())
	if err != nil {
		rec.CandidateError = readReason(err)
		log.Info("upstream check: candidate image not read", "candidate", rec.CandidateTag, "reason", rec.CandidateError, "err", err)
		return rec
	}
	b, err := EncodeCandidate(cand)
	if err != nil {
		rec.CandidateError = "its package list could not be stored"
		log.Warn("upstream check: candidate not encoded", "err", err)
		return rec
	}
	rec.Candidate, rec.CandidateReadAt = b, now
	return rec
}

// Reasons of a failed candidate read that a read of the same image repeats.
const (
	readTooLarge   = "it is larger than Varde reads"
	readNoPlatform = "it has no build for the host's platform"
)

// lasting reports whether a candidate read failed for a reason the image
// itself gives, rather than the registry or the network.
func lasting(reason string) bool { return reason == readTooLarge || reason == readNoPlatform }

// readReason words why a candidate read failed.
func readReason(err error) string {
	switch {
	case errors.Is(err, remedy.ErrImageTooLarge):
		return readTooLarge
	case errors.Is(err, remedy.ErrNoPlatform):
		return readNoPlatform
	}
	return "reading it failed: " + registry.Reason(err)
}

// tags is the tag list of a repository: the stored list when one exists,
// else one read per run.
func (c *Checker) tags(ctx context.Context, repository string, stored map[string]store.RepositoryTags, listed map[string][]string) ([]string, error) {
	if t, ok := stored[repository]; ok && t.Error == "" && len(t.Tags) > 0 {
		return t.Tags, nil
	}
	if t, ok := listed[repository]; ok {
		return t, nil
	}
	t, err := c.Client.Tags(ctx, repository)
	if err != nil && len(t) == 0 {
		return nil, err
	}
	listed[repository] = t
	return t, nil
}

// differs reports whether a new answer changes what Varde would say.
func differs(a, b store.UpstreamCheck) bool {
	return a.HeadDigest != b.HeadDigest || a.CandidateDigest != b.CandidateDigest || a.CandidateTag != b.CandidateTag ||
		(a.Candidate == nil) != (b.Candidate == nil) || a.Error != b.Error || a.CandidateError != b.CandidateError
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return DefaultTTL
}

func (c *Checker) perRun() int {
	if c.PerRun > 0 {
		return c.PerRun
	}
	return DefaultPerRun
}

func (c *Checker) readsPerRun() int {
	if c.ReadsPerRun > 0 {
		return c.ReadsPerRun
	}
	return DefaultReadsPerRun
}

func (c *Checker) readBytes() int64 {
	if c.ReadBytes > 0 {
		return c.ReadBytes
	}
	return DefaultReadBytes
}
