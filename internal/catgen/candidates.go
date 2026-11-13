// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

// Candidate states besides store.CandidateShipped.
const (
	// StatusFailed: the last check failed; the candidate is tried again
	// after store.RecheckAfter, within the budget of new candidates.
	StatusFailed = "failed"
	// StatusRetired: the image left the index or got a reviewed entry.
	StatusRetired = "retired"
)

// maxProbes bounds the conditional release requests per build that look
// for changed inputs of shipped entries not yet due.
const maxProbes = 600

// group is one project of the index: every index image of a repository
// that no reviewed entry matches. A generated entry stands for all of
// them, as a derived entry does: it takes the derived entry's ID, so an
// image left out would lose its derived entry.
type group struct {
	repo    string // "owner/name"
	entries []applists.Entry
	weight  int64
}

func (gr *group) images() []string {
	out := make([]string, 0, len(gr.entries))
	for _, e := range gr.entries {
		out = append(out, e.Image)
	}
	return out
}

// groups collects the index images without a reviewed entry by repository;
// the table is sorted, so each group's images are too.
func groups(idx *applists.Table, reviewed *catalog.Catalog) map[string]*group {
	out := map[string]*group{}
	for _, e := range idx.Entries() {
		if _, ok := reviewed.ByImage(e.Image); ok {
			continue
		}
		repo := strings.TrimPrefix(e.Repo, "github.com/")
		gr := out[repo]
		if gr == nil {
			gr = &group{repo: repo}
			out[repo] = gr
		}
		gr.entries = append(gr.entries, e)
	}
	return out
}

// weight ranks an image: its Docker Hub pull count, or the number of kinds
// of evidence of its index row on other registries (and when Docker Hub
// does not know the repository).
func (g *Generator) weight(ctx context.Context, e applists.Entry) (int64, error) {
	if rest, ok := strings.CutPrefix(e.Image, "docker.io/"); ok && g.Hub != nil {
		n, err := g.Hub.PullCount(ctx, rest)
		switch {
		case err == nil:
			return n, nil
		case !notFound(err):
			return 0, err
		}
	}
	return int64(len(e.Lists)), nil
}

// plan is the work of one build.
type plan struct {
	// fresh are new groups and failed groups due again, heaviest first;
	// the budget applies to them.
	fresh []*group
	// due are shipped groups whose result is older than RecheckAfter, that
	// lost an image or that gained one. Their entries are withheld or
	// aging, so they are checked outside the budget.
	due []*group
	// probe are the other shipped groups, oldest result first.
	probe []*group
}

// planRun sorts the groups into the work of this build. rows holds the
// candidate of every image of every group; forced names groups that must
// be checked again whatever their age.
func planRun(grs map[string]*group, rows map[string]store.Candidate, forced map[string]bool, now time.Time, budget int) plan {
	type ranked struct {
		gr      *group
		checked time.Time // oldest result of the group
		fresh   bool
		shipped bool // every image shipped
		some    bool // at least one image shipped
	}
	var all []ranked
	for _, gr := range grs {
		r := ranked{gr: gr, shipped: true}
		for _, e := range gr.entries {
			c := rows[e.Image]
			if c.CheckedAt.IsZero() {
				r.fresh = true
			}
			if c.Status != store.CandidateShipped {
				r.shipped = false
			} else {
				r.some = true
			}
			if r.checked.IsZero() || c.CheckedAt.Before(r.checked) {
				r.checked = c.CheckedAt
			}
			gr.weight = max(gr.weight, c.Weight)
		}
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.gr.weight != b.gr.weight {
			return a.gr.weight > b.gr.weight
		}
		return a.gr.repo < b.gr.repo
	})
	var p plan
	var retry, probe []ranked
	old := now.Add(-store.RecheckAfter)
	for _, r := range all {
		switch {
		case r.fresh && r.some:
			p.due = append(p.due, r.gr)
		case r.fresh:
			p.fresh = append(p.fresh, r.gr)
		case r.shipped && (forced[r.gr.repo] || r.checked.Before(old)):
			p.due = append(p.due, r.gr)
		case r.shipped:
			probe = append(probe, r)
		case r.checked.Before(old) || forced[r.gr.repo]:
			retry = append(retry, r)
		}
	}
	sort.SliceStable(retry, func(i, j int) bool { return retry[i].checked.Before(retry[j].checked) })
	for _, r := range retry {
		p.fresh = append(p.fresh, r.gr)
	}
	// The budget counts images, never-checked ones first.
	used, n := 0, 0
	for n < len(p.fresh) && used < budget {
		used += len(p.fresh[n].entries)
		n++
	}
	p.fresh = p.fresh[:n]
	sort.SliceStable(probe, func(i, j int) bool { return probe[i].checked.Before(probe[j].checked) })
	for i, r := range probe {
		if i >= maxProbes {
			break
		}
		p.probe = append(p.probe, r.gr)
	}
	return p
}
