// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/version"
)

// Store is what the resolver reads and writes.
type Store interface {
	Workloads(ctx context.Context, f store.WorkloadFilter) ([]inventory.Workload, error)
	Identifications(ctx context.Context) (map[string]identify.Result, error)
	ImageTags(ctx context.Context) (map[string]store.ImageTag, error)
	RecordImageTag(ctx context.Context, t store.ImageTag) error
}

const (
	// perRun bounds the images asked per run, tagLimit the HEAD requests
	// per image: the newest matching tags are asked first.
	perRun   = 10
	tagLimit = 25
	// retryAfter is how long a miss is kept before the image is asked
	// again (new releases appear under new tags).
	retryAfter = 24 * time.Hour
)

// Resolver asks the registries for the version tags of running images
// whose version Varde cannot read otherwise.
type Resolver struct {
	Client  *Client
	Store   Store
	Catalog func() *catalog.Catalog
	// Enabled reads the setting on every run; the resolver only talks to
	// registries when the user switched it on.
	Enabled func() bool
	// Changed runs the analysis after a new tag was found.
	Changed func(ctx context.Context)
	Log     *slog.Logger
	Now     func() time.Time
}

// Run resolves every interval until ctx ends.
func (r *Resolver) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if r.Enabled() {
			if n, err := r.Once(ctx); err != nil && ctx.Err() == nil {
				r.Log.Warn("registry resolution failed", "err", err)
			} else if n > 0 && r.Changed != nil {
				r.Changed(ctx)
			}
		}
		t.Reset(interval)
	}
}

// Job is one image to resolve.
type Job struct {
	App        *catalog.App
	Repository string
	Digest     string
}

// Jobs lists the images that need a registry answer: identified apps whose
// version is unknown or disputed, with a registry digest, not answered yet
// (or a miss older than retryAfter).
func Jobs(cat *catalog.Catalog, ws []inventory.Workload, ids map[string]identify.Result, known map[string]store.ImageTag, now time.Time) []Job {
	var out []Job
	seen := map[string]bool{}
	for _, w := range ws {
		c := w.Container
		id := ids[w.ID]
		if c == nil || !id.Confidence.Notifiable() || (id.Version != "" && id.Trust != identify.Conflict) {
			continue
		}
		app, ok := cat.App(id.AppID)
		if !ok {
			continue
		}
		ref, err := imageref.Parse(c.ImageRef)
		if err != nil {
			continue
		}
		digest := RepoDigest(c, ref.Repository)
		key := ref.Repository + "@" + digest
		if digest == "" || seen[key] {
			continue
		}
		if k, ok := known[key]; ok && (k.Tag != "" || now.Sub(k.Checked) < retryAfter) {
			continue
		}
		seen[key] = true
		out = append(out, Job{App: app, Repository: ref.Repository, Digest: digest})
	}
	return out
}

// RepoDigest returns the registry digest of the image for the repository,
// from the container's RepoDigests ("repo@sha256:...").
func RepoDigest(c *inventory.Container, repository string) string {
	for _, rd := range c.RepoDigests {
		name, digest, ok := strings.Cut(rd, "@")
		if !ok {
			continue
		}
		if r, err := imageref.Parse(name); err == nil && r.Repository == repository {
			return digest
		}
	}
	return ""
}

// Once runs one round and returns how many tags were found.
func (r *Resolver) Once(ctx context.Context) (int, error) {
	ws, err := r.Store.Workloads(ctx, store.WorkloadFilter{Kind: inventory.KindContainer})
	if err != nil {
		return 0, err
	}
	ids, err := r.Store.Identifications(ctx)
	if err != nil {
		return 0, err
	}
	known, err := r.Store.ImageTags(ctx)
	if err != nil {
		return 0, err
	}
	now := r.Now()
	jobs := Jobs(r.Catalog(), ws, ids, known, now)
	found := 0
	for i, j := range jobs {
		if i >= perRun {
			break
		}
		if err := ctx.Err(); err != nil {
			return found, err
		}
		app := j.App
		keep := func(tag string) bool {
			_, ok := identify.TagVersion(app, j.Repository, tag)
			return ok
		}
		less := func(a, b string) bool {
			va, _ := identify.TagVersion(app, j.Repository, a)
			vb, _ := identify.TagVersion(app, j.Repository, b)
			x, errA := version.Parse(app.Version.Scheme, va)
			y, errB := version.Parse(app.Version.Scheme, vb)
			if errA != nil || errB != nil {
				return a > b
			}
			c, ok := x.Compare(y)
			return ok && c > 0
		}
		tag, rerr := r.Client.Resolve(ctx, j.Repository, j.Digest, keep, less, tagLimit)
		rec := store.ImageTag{Repository: j.Repository, Digest: j.Digest, Tag: tag, Checked: now}
		if rerr != nil {
			// One registry failing must not stop the others; the miss is
			// recorded and retried after retryAfter.
			rec.Error = rerr.Error()
			r.Log.Info("registry did not answer for an image", "repository", j.Repository, "err", rerr)
		}
		if err := r.Store.RecordImageTag(ctx, rec); err != nil {
			return found, err
		}
		if tag != "" {
			found++
		}
	}
	if err := r.updateTagLists(ctx, ws, ids, now); err != nil {
		return found, err
	}
	return found, nil
}
