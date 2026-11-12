// SPDX-License-Identifier: Apache-2.0

// Package catgen generates catalog entries for the images of the
// first-party index that no reviewed entry covers, inside the daily data
// build (ADR 0039). Each entry is proved by machine checks (C1 to C5,
// checks.go) against the live tags, the project's GitHub releases and NVD;
// only an entry that passes every check ships, as origin "generated",
// beneath the reviewed entries. A wrong entry is worse than none: a
// candidate that fails a check is recorded and not shipped, and an
// installation keeps the entry it derives itself. It runs in the builder,
// never in an installation.
package catgen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

// DefaultBudget is how many new candidates a build checks when Budget is
// not set; the rest waits for the next build.
const DefaultBudget = 150

// releasesSource is the source state key under which the ETag of a
// repository's release list is kept.
const releasesSource = "catgen-releases"

// Store is the builder state the generator keeps; *store.Store has it.
type Store interface {
	UpsertCandidate(ctx context.Context, c store.Candidate) error
	AllCandidates(ctx context.Context) ([]store.Candidate, error)
	SourceState(ctx context.Context, source, key string) (store.SourceState, error)
	PutSourceState(ctx context.Context, st store.SourceState) error
}

// Generator makes and checks the generated entries. Every source is an
// interface, so tests run without a network.
type Generator struct {
	Store
	Registry RegistryAPI
	GitHub   GitHubAPI
	NVD      NVDAPI
	Hub      HubAPI
	Now      func() time.Time
	// Budget is the number of new candidates (images) per build;
	// DefaultBudget when zero.
	Budget int
}

// Report is the outcome of a build. Images name the candidates.
type Report struct {
	// Shipped are all generated entries that checks their checks, this
	// build or before, sorted by name.
	Shipped []catalog.Entry
	// New, Changed and Dropped are images whose entry shipped for the first
	// time, changed beyond its verified date, or stopped shipping.
	New, Changed, Dropped []string
	// Failed maps an image to the check it failed this build.
	Failed map[string]string
	// Reasons says, per failed image, what failed.
	Reasons map[string]string
	// Skipped maps an image that could not be checked (a source did not
	// answer) to the error; it keeps its earlier state.
	Skipped map[string]string
}

func (g *Generator) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Generator) budget() int {
	if g.Budget > 0 {
		return g.Budget
	}
	return DefaultBudget
}

// Run brings the candidate set in line with the index, checks this build's
// share of it and returns every entry to ship. Errors of a source skip the
// candidate; only the store failing ends the run.
func (g *Generator) Run(ctx context.Context, idx *applists.Table, reviewed *catalog.Catalog) (Report, error) {
	now := g.now()
	rep := Report{Failed: map[string]string{}, Reasons: map[string]string{}, Skipped: map[string]string{}}
	all, err := g.AllCandidates(ctx)
	if err != nil {
		return rep, err
	}
	rows := make(map[string]store.Candidate, len(all))
	for _, c := range all {
		rows[c.Image] = c
	}
	grs := groups(idx, reviewed)
	inIndex := map[string]string{} // image -> repo
	for _, gr := range grs {
		for _, e := range gr.entries {
			inIndex[e.Image] = gr.repo
		}
	}

	// Images that left the index or got a reviewed entry retire. Their
	// project, if it stays, is checked again: its entry still names them.
	forced := map[string]bool{}
	for _, c := range all {
		if repo, ok := inIndex[c.Image]; (ok && repo == c.Repo) || c.Status == StatusRetired {
			continue
		}
		if c.Status == store.CandidateShipped {
			rep.Dropped = append(rep.Dropped, c.Image)
			forced[c.Repo] = true
		}
		c.Status, c.FailedCheck, c.EntryYAML, c.CheckedAt, c.ShippedAt = StatusRetired, "", "", now, time.Time{}
		if err := g.UpsertCandidate(ctx, c); err != nil {
			return rep, err
		}
		rows[c.Image] = c
	}

	// New images (and retired ones that came back) become candidates.
	for repo, gr := range grs {
		for _, e := range gr.entries {
			if c, ok := rows[e.Image]; ok && c.Status != StatusRetired && c.Repo == repo {
				continue
			}
			w, err := g.weight(ctx, e)
			if err != nil {
				rep.Skipped[e.Image] = err.Error()
				continue
			}
			c := store.Candidate{Image: e.Image, Repo: repo, Weight: w}
			if err := g.UpsertCandidate(ctx, c); err != nil {
				return rep, err
			}
			rows[e.Image] = c
		}
	}
	// A project with an image that has no candidate yet waits a build.
	for repo, gr := range grs {
		for _, e := range gr.entries {
			if _, ok := rows[e.Image]; !ok {
				delete(grs, repo)
				break
			}
		}
	}

	p := planRun(grs, rows, forced, now, g.budget())
	work := append(append([]*group(nil), p.fresh...), p.due...)
	prefetched := map[string]fetched{}
	for _, gr := range p.probe {
		f, changed, err := g.probe(ctx, gr.repo)
		if err != nil || !changed {
			continue
		}
		prefetched[gr.repo] = f
		work = append(work, gr)
	}
	for _, gr := range work {
		if err := g.checkAndRecord(ctx, gr, reviewed, rows, prefetched[gr.repo], now, &rep); err != nil {
			return rep, err
		}
	}
	rep.Shipped = shipped(rows)
	sort.Strings(rep.New)
	sort.Strings(rep.Changed)
	sort.Strings(rep.Dropped)
	return rep, nil
}

// fetched is a release list read in this build.
type fetched struct {
	rels []Release
	etag string
	ok   bool
}

// probe asks whether the release list of a shipped entry changed since its
// last check, with the ETag of that check. A repository without a stored
// ETag is not probed; its entry waits for RecheckAfter.
func (g *Generator) probe(ctx context.Context, repo string) (fetched, bool, error) {
	st, err := g.SourceState(ctx, releasesSource, repo)
	if err != nil || st.ETag == "" {
		return fetched{}, false, err
	}
	rels, etag, notModified, err := g.GitHub.Releases(ctx, repo, st.ETag)
	if err != nil || notModified {
		return fetched{}, false, err
	}
	return fetched{rels: rels, etag: etag, ok: true}, true, nil
}

// checkAndRecord checks a group and stores the outcome for each image.
func (g *Generator) checkAndRecord(ctx context.Context, gr *group, reviewed *catalog.Catalog, rows map[string]store.Candidate, f fetched, now time.Time, rep *Report) error {
	o, err := g.checkGroup(ctx, gr, reviewed, f, now.UTC().Format(time.DateOnly))
	if err != nil {
		for _, img := range gr.images() {
			rep.Skipped[img] = err.Error()
		}
		return nil
	}
	if o.etag != "" {
		st := store.SourceState{Source: releasesSource, Key: gr.repo, ETag: o.etag, LastAttempt: now, LastSuccess: now}
		if err := g.PutSourceState(ctx, st); err != nil {
			return err
		}
	}
	for _, e := range gr.entries {
		prev := rows[e.Image]
		c := prev
		c.Repo, c.CheckedAt, c.InputsHash = gr.repo, now, o.hash
		was := prev.Status == store.CandidateShipped
		if o.failed != nil {
			c.Status, c.FailedCheck, c.EntryYAML, c.ShippedAt = StatusFailed, o.failed.check, "", time.Time{}
			rep.Failed[e.Image] = o.failed.check
			rep.Reasons[e.Image] = o.failed.detail
			if was {
				rep.Dropped = append(rep.Dropped, e.Image)
			}
		} else {
			c.Status, c.FailedCheck, c.EntryYAML = store.CandidateShipped, "", o.yaml
			switch {
			case !was:
				c.ShippedAt = now
				rep.New = append(rep.New, e.Image)
			case withoutVerified(prev.EntryYAML) != withoutVerified(o.yaml):
				rep.Changed = append(rep.Changed, e.Image)
			}
		}
		if err := g.UpsertCandidate(ctx, c); err != nil {
			return err
		}
		rows[e.Image] = c
	}
	return nil
}

// withoutVerified drops the verified line, which changes with every
// passing check.
func withoutVerified(entry string) string {
	var b strings.Builder
	for _, l := range strings.Split(entry, "\n") {
		if !strings.HasPrefix(l, "verified:") {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// shipped returns one entry per shipped project, sorted by name. The
// images of a project carry the same entry; should they ever differ, the
// first image's wins, so the package stays reproducible.
func shipped(rows map[string]store.Candidate) []catalog.Entry {
	images := make([]string, 0, len(rows))
	for img := range rows {
		images = append(images, img)
	}
	sort.Strings(images)
	byRepo := map[string]string{}
	for _, img := range images {
		c := rows[img]
		if _, seen := byRepo[c.Repo]; !seen && c.Status == store.CandidateShipped && c.EntryYAML != "" {
			byRepo[c.Repo] = c.EntryYAML
		}
	}
	out := make([]catalog.Entry, 0, len(byRepo))
	for repo, data := range byRepo {
		owner, name, _ := strings.Cut(repo, "/")
		out = append(out, catalog.Entry{Name: catalog.DerivedID(owner, name) + ".yaml", Data: data})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// outcome is the result of checking a group: the entry, or the failed
// check.
type outcome struct {
	yaml, hash, etag string
	failed           *failure
}

// checkGroup runs C1 to C5 on the entry for a project. A failed check is
// an outcome; an error means a source did not answer.
func (g *Generator) checkGroup(ctx context.Context, gr *group, reviewed *catalog.Catalog, f fetched, date string) (o outcome, err error) {
	verdict := func(err error) (outcome, error) {
		var fl *failure
		if errors.As(err, &fl) {
			o.failed = fl
			return o, nil
		}
		return o, err
	}
	owner, name, _ := strings.Cut(gr.repo, "/")
	id := catalog.DerivedID(owner, name)
	images := gr.images()
	if err := checkClaims(reviewed, id, gr.repo, images); err != nil {
		return verdict(err)
	}
	if err := checkEvidence(gr.entries); err != nil {
		return verdict(err)
	}

	rels, etag := f.rels, f.etag
	if !f.ok {
		rels, etag, _, err = g.GitHub.Releases(ctx, gr.repo, "")
		if err != nil {
			if notFound(err) {
				return verdict(fail(CheckTags, "%s has no GitHub releases", gr.repo))
			}
			return o, err
		}
	}
	o.etag = etag
	h := sha256.New()
	for _, r := range rels {
		fmt.Fprintf(h, "release %s %t %t\n", r.Tag, r.Prerelease, r.Draft)
	}

	tagLists := make([][]string, 0, len(images))
	for _, img := range images {
		tags, err := g.Registry.Tags(ctx, img)
		if err != nil {
			if notFound(err) {
				return verdict(fail(CheckTags, "image %s has no tag list", img))
			}
			return o, err
		}
		sorted := append([]string(nil), tags...)
		sort.Strings(sorted)
		fmt.Fprintf(h, "tags %s %s\n", img, strings.Join(sorted, ","))
		tagLists = append(tagLists, tags)
	}
	// The hash is of what was read, also for a candidate that fails.
	defer func() { o.hash = hex.EncodeToString(h.Sum(nil)) }()

	tpl, streams, ok := pickTemplate(tagLists, releaseSet(rels))
	if !ok {
		return verdict(fail(CheckTags, "no template matches at least %d release tags and no floating tag of %s", minReleaseTags, strings.Join(images, ", ")))
	}
	for i, img := range images {
		if err := g.checkStream(ctx, img, streams[i]); err != nil {
			return verdict(err)
		}
		fmt.Fprintf(h, "newest %s %s\n", img, streams[i].newest)
	}
	for _, s := range streams {
		if err := checkVersion(tpl.Scheme, s.newestVersion, rels); err != nil {
			return verdict(err)
		}
	}

	cpe := ""
	if g.NVD != nil {
		if cpe, err = g.findCPE(ctx, gr.repo); err != nil {
			return o, err
		}
		if cpe != "" {
			if err := g.checkCPE(ctx, cpe, []string{gr.repo}); err != nil {
				return verdict(err)
			}
		}
	}
	fmt.Fprintf(h, "cpe %s\n", cpe)

	data, err := entryYAML(id, gr.repo, images, tpl, cpe, date)
	if err != nil {
		return o, err
	}
	app, err := catalog.Parse(id+".yaml", data)
	if err != nil {
		return verdict(fail(CheckSchema, "%v", err))
	}
	if app.Advisories.Coverage == catalog.CoverageFull {
		return verdict(fail(CheckSchema, "a generated entry cannot claim full coverage"))
	}
	o.yaml = string(data)
	return o, nil
}

// entryDoc is the YAML form of a generated entry, in the field order of
// the reviewed entries.
type entryDoc struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Homepage    string      `yaml:"homepage"`
	Images      []imageDoc  `yaml:"images"`
	OCISource   []string    `yaml:"oci_source"`
	Version     versionDoc  `yaml:"version"`
	Advisories  advisoryDoc `yaml:"advisories"`
	Maintainers []string    `yaml:"maintainers_of_entry,flow"`
	Verified    string      `yaml:"verified"`
}

type imageDoc struct {
	Match string `yaml:"match"`
}

type versionDoc struct {
	Scheme  string      `yaml:"scheme"`
	Sources []sourceDoc `yaml:"sources"`
}

type sourceDoc struct {
	Tag string `yaml:"tag"`
}

type advisoryDoc struct {
	Coverage    string   `yaml:"coverage"`
	GitHubRepos []string `yaml:"github_repos,flow"`
	CPE         []string `yaml:"cpe,omitempty,flow"`
	Notes       string   `yaml:"notes"`
}

// entryYAML writes the entry. Its text depends only on its inputs and the
// date, so an unchanged project gives an unchanged entry.
func entryYAML(id, repo string, images []string, tpl Template, cpe, date string) ([]byte, error) {
	_, name, _ := strings.Cut(repo, "/")
	checks := "C1 (schema, nothing a reviewed entry claims), C2 (first-party evidence for every image), C3 (tag rule from the fixed templates), C4 (newest tag on the newest release's line)"
	doc := entryDoc{
		ID: id, Name: name, Homepage: "https://github.com/" + repo,
		OCISource:   []string{"https://github.com/" + repo},
		Version:     versionDoc{Scheme: string(tpl.Scheme), Sources: []sourceDoc{{Tag: tpl.Pattern}}},
		Advisories:  advisoryDoc{Coverage: catalog.CoveragePartial, GitHubRepos: []string{repo}},
		Maintainers: []string{"generator"},
		Verified:    date,
	}
	for _, img := range images {
		doc.Images = append(doc.Images, imageDoc{Match: img})
	}
	if cpe != "" {
		doc.Advisories.CPE = []string{cpe}
		checks += ", C5 (CPE in NVD, tied to the repository)"
	}
	doc.Advisories.Notes = "Generated by the package builder and checked by machine, not reviewed by a person. Passed " + checks + "."
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("generated entry %s: %w", id, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("generated entry %s: %w", id, err)
	}
	return b.Bytes(), nil
}
