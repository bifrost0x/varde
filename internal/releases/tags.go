// SPDX-License-Identifier: Apache-2.0

package releases

import (
	"context"
	"log/slog"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/store"
)

const (
	// DefaultTagsEvery is how long a stored tag list stands before the
	// registry is asked again: a release reaches installations with the
	// next daily build.
	DefaultTagsEvery = 20 * time.Hour
	// DefaultTagsKeep is how long a tag list ships that could not be
	// read again. An old list still names releases that exist; it only
	// misses the newest.
	DefaultTagsKeep = 14 * 24 * time.Hour
	// DefaultTagTimeout bounds the tag list of one image.
	DefaultTagTimeout = 2 * time.Minute
)

// TagStore keeps the tag lists between builds; *store.Store has it.
type TagStore interface {
	RepositoryTags(ctx context.Context) (map[string]store.RepositoryTags, error)
	RecordRepositoryTags(ctx context.Context, t store.RepositoryTags) error
}

// TagLister lists every tag of a repository; *registry.Client has it.
type TagLister interface {
	AllTags(ctx context.Context, repository string) (tags []string, complete bool, err error)
}

// TagReader reads the release tags of the images of catalog apps. A tag
// list costs no pull and no layer, so it is read for every image, whatever
// the budget of the package lists (Reader) allows: which releases exist is
// known for the whole catalog, what is in them for the part that fits.
type TagReader struct {
	Store    TagStore
	Registry TagLister
	Now      func() time.Time
	// Every, Keep and Timeout default to DefaultTagsEvery, DefaultTagsKeep
	// and DefaultTagTimeout.
	Every, Keep, Timeout time.Duration
	// Deadline, when set, ends the registry work: lists not read by then
	// ship as stored and are read by a later build.
	Deadline time.Time
	Log      *slog.Logger

	// registryRepo maps an image to the repository asked of the registry
	// (tests).
	registryRepo func(image string) string
}

// TagStats counts one run.
type TagStats struct {
	// Images is the number of images with a tag rule; Read were listed
	// in this run, Fresh stood from an earlier one, Failed could not be
	// listed, NotStarted were left to a later build by the deadline.
	Images, Read, Fresh, Failed, NotStarted int
	// NoRelease lists hold no tag the rule reads a release from; Stale
	// lists ship although their read failed or did not start.
	NoRelease, Stale int
}

// Run returns one line per image whose release tags are known, in the
// order of order (Priority). Only a failing store or an ended context is
// an error; a registry that fails costs its image.
func (r *TagReader) Run(ctx context.Context, cat *catalog.Catalog, order []string) ([]feed.TagLine, TagStats, error) {
	var st TagStats
	now := r.Now
	if now == nil {
		now = time.Now
	}
	every, keep, timeout := orDuration(r.Every, DefaultTagsEvery), orDuration(r.Keep, DefaultTagsKeep), orDuration(r.Timeout, DefaultTagTimeout)
	log := r.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	known, err := r.Store.RepositoryTags(ctx)
	if err != nil {
		return nil, st, err
	}
	out := []feed.TagLine{}
	seen := map[string]bool{}
	for _, j := range jobsOf(cat, order) {
		if err := ctx.Err(); err != nil {
			return nil, st, err
		}
		if seen[j.image] {
			continue // one list per repository, for the app that ranks first
		}
		seen[j.image] = true
		st.Images++
		rec, have := known[j.image]
		have = have && rec.Error == ""
		switch {
		case have && now().Sub(rec.Checked) < every:
			st.Fresh++
		case !r.Deadline.IsZero() && !now().Before(r.Deadline):
			st.NotStarted++
		default:
			remote := j.image
			if r.registryRepo != nil {
				remote = r.registryRepo(j.image)
			}
			rctx, cancel := context.WithTimeout(ctx, timeout)
			tags, complete, err := r.Registry.AllTags(rctx, remote)
			cancel()
			if ctx.Err() != nil {
				return nil, st, ctx.Err()
			}
			if err != nil || !complete {
				// A list cut short may miss the newest release; the
				// stored one is the better answer.
				st.Failed++
				log.Info("tag list not read", "image", j.image, "complete", complete, "err", err)
				break
			}
			st.Read++
			keepTag, less := registry.TagOrder(j.app, j.image)
			ranked := registry.Rank(tags, keepTag, less)
			if len(ranked) > feed.MaxTagsPerLine {
				ranked = ranked[:feed.MaxTagsPerLine]
			}
			rec, have = store.RepositoryTags{Repository: j.image, Tags: ranked, Checked: now()}, true
			if err := r.Store.RecordRepositoryTags(ctx, rec); err != nil {
				return nil, st, err
			}
		}
		if !have || now().Sub(rec.Checked) >= keep {
			continue
		}
		line := feed.TagLine{AppID: j.app.ID, Image: j.image, Read: rec.Checked.UTC(), Tags: rec.Tags}
		if len(line.Tags) > feed.MaxTagsPerLine {
			line.Tags = line.Tags[:feed.MaxTagsPerLine]
		}
		if len(line.Tags) == 0 {
			st.NoRelease++
			continue
		}
		if err := line.Validate(); err != nil {
			// A tag the package cannot carry costs the image, not the build.
			st.Failed++
			log.Warn("tag list left out", "image", j.image, "err", err)
			continue
		}
		if now().Sub(rec.Checked) >= every {
			st.Stale++
		}
		out = append(out, line)
	}
	return out, st, nil
}
