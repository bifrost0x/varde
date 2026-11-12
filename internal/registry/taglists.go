// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"sort"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// tagListsEvery is how often the tag list of a repository is read again;
// new releases appear under new tags.
const tagListsEvery = 24 * time.Hour

// TagStore keeps the release tags of repositories.
type TagStore interface {
	Findings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	RepositoryTags(ctx context.Context) (map[string]store.RepositoryTags, error)
	RecordRepositoryTags(ctx context.Context, t store.RepositoryTags) error
}

// TagListJob is one repository whose release tags are needed.
type TagListJob struct {
	App        *catalog.App
	Repository string
}

// TagListJobs lists the repositories of containers with open affected
// findings whose tag list is missing or older than a day: those are the
// only ones an update suggestion needs (ADR 0029).
func TagListJobs(cat *catalog.Catalog, ws []inventory.Workload, ids map[string]identify.Result, findings []store.Finding, known map[string]store.RepositoryTags, now time.Time) []TagListJob {
	affected := map[string]bool{}
	for _, f := range findings {
		if f.MatchState == "affected" && f.State != store.StateResolved {
			affected[f.WorkloadID] = true
		}
	}
	var out []TagListJob
	seen := map[string]bool{}
	for _, w := range ws {
		if w.Container == nil || !affected[w.ID] {
			continue
		}
		app, ok := cat.App(ids[w.ID].AppID)
		if !ok {
			continue
		}
		ref, err := imageref.Parse(w.Container.ImageRef)
		if err != nil || seen[ref.Repository] {
			continue
		}
		seen[ref.Repository] = true
		if k, ok := known[ref.Repository]; ok && now.Sub(k.Checked) < tagListsEvery {
			continue
		}
		out = append(out, TagListJob{App: identify.AppForImage(app, ref.Repository), Repository: ref.Repository})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repository < out[j].Repository })
	return out
}

// updateTagLists reads the release tags of the repositories that need
// them, at most perRun per run.
func (r *Resolver) updateTagLists(ctx context.Context, ws []inventory.Workload, ids map[string]identify.Result, now time.Time) error {
	ts, ok := r.Store.(TagStore)
	if !ok {
		return nil
	}
	findings, err := ts.Findings(ctx, store.FindingFilter{})
	if err != nil {
		return err
	}
	known, err := ts.RepositoryTags(ctx)
	if err != nil {
		return err
	}
	for i, j := range TagListJobs(r.Catalog(), ws, ids, findings, known, now) {
		if i >= perRun {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := ts.RecordRepositoryTags(ctx, r.readTags(ctx, j, now)); err != nil {
			return err
		}
	}
	return nil
}

// readTags lists the release tags of one repository. A failure is part of
// the record, retried after tagListsEvery; one registry failing must not
// stop the others.
func (r *Resolver) readTags(ctx context.Context, j TagListJob, now time.Time) store.RepositoryTags {
	tags, err := r.Client.Tags(ctx, j.Repository)
	rec := store.RepositoryTags{Repository: j.Repository, Checked: now}
	// Only release tags of the app are kept; the rest (branches, commit
	// tags) cannot be a suggestion.
	for _, t := range tags {
		if _, ok := identify.TagVersion(j.App, j.Repository, t); ok {
			rec.Tags = append(rec.Tags, t)
		}
	}
	if err != nil {
		r.Log.Info("registry tag list not read", "repository", j.Repository, "err", err)
		if len(rec.Tags) == 0 {
			// A partial list is still useful; an empty one is a failure.
			rec.Error = err.Error()
		}
	}
	return rec
}
