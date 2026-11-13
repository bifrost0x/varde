// SPDX-License-Identifier: Apache-2.0

// Package catgen generates catalog entries for the images of the
// first-party index that no reviewed entry covers, inside the daily data
// build (ADR 0039). Each entry is proved by machine checks (C1 to C6,
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
	"github.com/bifrost0x/varde/internal/eval"
	"github.com/bifrost0x/varde/internal/identify"
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
	// Deadline, when set, ends the build's network work: no project is
	// started after it. What was checked by then is recorded and ships.
	Deadline time.Time
	// EvalCases are the container cases of the eval corpus (eval.Load);
	// C6 compares an entry with the derived one on the cases of its
	// images. None: that part of C6 holds.
	EvalCases []eval.ContainerCase
}

// Report is the outcome of a build. Images name the candidates.
type Report struct {
	// Shipped holds the entries to ship, sorted by name: one per project
	// whose images all passed their latest check, this build or before.
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
	// Stopped names the sources this build stopped asking because they
	// refused with a rate limit, and "deadline" when the time ran out.
	Stopped []string
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

// past reports that the deadline has come.
func (g *Generator) past() bool {
	return !g.Deadline.IsZero() && !g.now().Before(g.Deadline)
}

// storeError marks a failure of the builder store, which ends the run;
// every other error only skips a candidate.
type storeError struct{ err error }

func (e storeError) Error() string { return e.err.Error() }
func (e storeError) Unwrap() error { return e.err }

// Run brings the candidate set in line with the index, checks this build's
// share of it and returns every entry to ship. Errors of a source skip the
// candidate, and a source that refuses with a rate limit is not asked
// again in this build; only the store failing ends the run.
func (g *Generator) Run(ctx context.Context, idx *applists.Table, reviewed *catalog.Catalog) (Report, error) {
	rg, l := g.limited()
	rep, err := rg.run(ctx, idx, reviewed, l)
	rep.Stopped = l.order
	return rep, err
}

// WithRateLimits returns a copy of g whose sources, like those of a build,
// are not asked again once they refused because of their rate limit; the
// weekly check of the reviewed entries (cmd/catalogcheck) runs its
// CheckReviewed calls on it. stopped names the sources it stopped asking,
// in order.
func (g *Generator) WithRateLimits() (limited *Generator, stopped func() []string) {
	rg, l := g.limited()
	return rg, func() []string { return append([]string(nil), l.order...) }
}

func (g *Generator) limited() (*Generator, *limits) {
	l := &limits{stopped: map[string]bool{}}
	rg := *g
	rg.Registry = limitedRegistry{inner: g.Registry, l: l}
	rg.GitHub = limitedGitHub{inner: g.GitHub, l: l}
	if g.NVD != nil {
		rg.NVD = limitedNVD{inner: g.NVD, l: l}
	}
	if g.Hub != nil {
		rg.Hub = limitedHub{inner: g.Hub, l: l}
	}
	return &rg, l
}

func (g *Generator) run(ctx context.Context, idx *applists.Table, reviewed *catalog.Catalog, l *limits) (Report, error) {
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

	// C1's claims and C2 need no network: every project, every build.
	ids := map[string]int{}
	for repo := range grs {
		owner, name, _ := strings.Cut(repo, "/")
		ids[catalog.DerivedID(owner, name)]++
	}
	open := map[string]*group{}
	for repo, gr := range grs {
		err := precheck(reviewed, gr, ids)
		var f *failure
		if !errors.As(err, &f) {
			open[repo] = gr
			continue
		}
		if err := g.record(ctx, gr, rows, outcome{failed: f}, now, &rep); err != nil {
			return rep, err
		}
	}

	// New images (and retired ones that came back, and ones whose C1 or
	// C2 failure is gone) become candidates.
	for repo, gr := range open {
		for _, e := range gr.entries {
			c, ok := rows[e.Image]
			if ok && c.Status != StatusRetired && c.Repo == repo &&
				(c.Status != StatusFailed || (c.FailedCheck != CheckSchema && c.FailedCheck != CheckEvidence)) {
				continue
			}
			if g.past() {
				l.stop(stopDeadline)
				rep.Skipped[e.Image] = "deadline reached"
				continue
			}
			w, err := g.weight(ctx, e)
			if err != nil {
				rep.Skipped[e.Image] = err.Error()
				continue
			}
			nc := store.Candidate{Image: e.Image, Repo: repo, Weight: w}
			if ok && c.Repo == repo {
				nc.Weight = max(nc.Weight, c.Weight)
			}
			if err := g.UpsertCandidate(ctx, nc); err != nil {
				return rep, err
			}
			rows[e.Image] = nc
		}
	}
	// A project with an image that has no candidate yet waits a build;
	// shipped leaves its old entry out meanwhile.
	for repo, gr := range open {
		for _, e := range gr.entries {
			if _, ok := rows[e.Image]; !ok {
				delete(open, repo)
				break
			}
		}
	}

	p := planRun(open, rows, forced, now, g.budget())
	// Due re-checks come first: their entries are aging or withheld, and
	// one that a deadline keeps waiting expires as stale. Then the probes
	// of the other shipped entries and the re-checks they call for, then
	// the new candidates, which can wait a build.
	check := func(grs []*group, prefetched map[string]fetched) (bool, error) {
		for _, gr := range grs {
			if g.past() {
				l.stop(stopDeadline)
				return false, nil
			}
			if err := g.checkAndRecord(ctx, gr, reviewed, rows, prefetched[gr.repo], now, &rep); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	more, err := check(p.due, nil)
	if err != nil {
		return rep, err
	}
	var changed []*group
	prefetched := map[string]fetched{}
	for _, gr := range p.probe {
		if !more {
			break
		}
		if g.past() {
			l.stop(stopDeadline)
			more = false
			break
		}
		f, ok, err := g.probe(ctx, gr.repo)
		if err != nil {
			return rep, err
		}
		if ok {
			prefetched[gr.repo] = f
			changed = append(changed, gr)
		}
	}
	if more {
		if more, err = check(changed, prefetched); err != nil {
			return rep, err
		}
	}
	if more {
		if _, err = check(p.fresh, nil); err != nil {
			return rep, err
		}
	}
	if err := g.expire(ctx, rows, now, &rep); err != nil {
		return rep, err
	}
	rep.Shipped = shipped(rows, grs)
	sort.Strings(rep.New)
	sort.Strings(rep.Changed)
	sort.Strings(rep.Dropped)
	return rep, nil
}

// expire stops shipping entries that no check confirmed for twice
// RecheckAfter: their sources kept failing (a deleted or private
// repository answers 401 or 403, not 404), and an entry nobody can check
// is not trusted for ever.
func (g *Generator) expire(ctx context.Context, rows map[string]store.Candidate, now time.Time, rep *Report) error {
	images := make([]string, 0, len(rows))
	for img := range rows {
		images = append(images, img)
	}
	sort.Strings(images)
	limit := now.Add(-2 * store.RecheckAfter)
	for _, img := range images {
		c := rows[img]
		if c.Status != store.CandidateShipped || !c.CheckedAt.Before(limit) {
			continue
		}
		last := c.CheckedAt
		c.Status, c.FailedCheck, c.EntryYAML, c.CheckedAt, c.ShippedAt = StatusFailed, CheckStale, "", now, time.Time{}
		if err := g.UpsertCandidate(ctx, c); err != nil {
			return err
		}
		rows[img] = c
		rep.Dropped = append(rep.Dropped, img)
		rep.Failed[img] = CheckStale
		rep.Reasons[img] = "not confirmed by a check since " + last.Format(time.DateOnly)
	}
	return nil
}

// fetched is a release list read in this build.
type fetched struct {
	rels []Release
	etag string
	ok   bool
}

// probe asks whether the release list of a shipped entry changed since its
// last check, with the ETag of that check. A repository without a stored
// ETag is not probed; its entry waits for RecheckAfter. Only a store error
// is returned: a source that does not answer means no change for now.
func (g *Generator) probe(ctx context.Context, repo string) (fetched, bool, error) {
	st, err := g.SourceState(ctx, releasesSource, repo)
	if err != nil {
		return fetched{}, false, err
	}
	if st.ETag == "" {
		return fetched{}, false, nil
	}
	rels, etag, notModified, askErr := g.GitHub.Releases(ctx, repo, st.ETag)
	if changed := askErr == nil && !notModified; !changed {
		return fetched{}, false, nil
	}
	return fetched{rels: rels, etag: etag, ok: true}, true, nil
}

// checkAndRecord checks a group and stores the outcome for each image.
func (g *Generator) checkAndRecord(ctx context.Context, gr *group, reviewed *catalog.Catalog, rows map[string]store.Candidate, f fetched, now time.Time, rep *Report) error {
	o, err := g.checkGroup(ctx, gr, reviewed, f, now)
	if err != nil {
		var se storeError
		if errors.As(err, &se) {
			return se.err
		}
		for _, img := range gr.images() {
			rep.Skipped[img] = err.Error()
		}
		return nil
	}
	if err := g.record(ctx, gr, rows, o, now, rep); err != nil {
		return err
	}
	// The ETag only after the outcome is stored: kept before, a store
	// error in record would leave the project behind a "not modified"
	// probe with part of its images recorded.
	if o.etag != "" {
		st := store.SourceState{Source: releasesSource, Key: gr.repo, ETag: o.etag, LastAttempt: now, LastSuccess: now}
		if err := g.PutSourceState(ctx, st); err != nil {
			return err
		}
	}
	return nil
}

// record stores the outcome of a group for each of its images.
func (g *Generator) record(ctx context.Context, gr *group, rows map[string]store.Candidate, o outcome, now time.Time, rep *Report) error {
	for _, e := range gr.entries {
		prev, ok := rows[e.Image]
		if !ok {
			prev = store.Candidate{Image: e.Image}
		}
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

// shipped returns one entry per project of the index whose images all
// shipped the same entry, sorted by name. A project that gained an image
// since its last check is left out until it is checked with that image:
// its old entry would take the derived entry the new image gets.
func shipped(rows map[string]store.Candidate, grs map[string]*group) []catalog.Entry {
	out := make([]catalog.Entry, 0, len(grs))
	for repo, gr := range grs {
		data := ""
		for _, e := range gr.entries {
			c := rows[e.Image]
			if c.Status != store.CandidateShipped || c.EntryYAML == "" || (data != "" && c.EntryYAML != data) {
				data = ""
				break
			}
			data = c.EntryYAML
		}
		if data == "" {
			continue
		}
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

// checkGroup runs C1 to C6 on the entry for a project. A failed check is
// an outcome; an error means a source did not answer.
func (g *Generator) checkGroup(ctx context.Context, gr *group, reviewed *catalog.Catalog, f fetched, now time.Time) (o outcome, err error) {
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
		tags, err := g.tags(ctx, img)
		if err != nil {
			return verdict(err)
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
	newestDigest := make([]string, len(images))
	for i, img := range images {
		d, err := g.checkStream(ctx, img, streams[i])
		if err != nil {
			return verdict(err)
		}
		newestDigest[i] = d
		fmt.Fprintf(h, "newest %s %s\n", img, streams[i].newest)
	}
	for _, s := range streams {
		if err := checkVersion(tpl.Scheme, s.newestVersion, rels); err != nil {
			return verdict(err)
		}
	}

	cpe, err := g.cpe(ctx, gr.repo, now)
	if err != nil {
		return verdict(err)
	}
	fmt.Fprintf(h, "cpe %s\n", cpe)

	data, err := entryYAML(id, gr.repo, images, tpl, cpe, now.UTC().Format(time.DateOnly))
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

	var newest []TagDigest
	for i, img := range images {
		known := map[string]string{streams[i].newest: newestDigest[i]}
		tds, err := g.newestTags(ctx, app, img, tagLists[i], known)
		if err != nil {
			return verdict(err)
		}
		for _, td := range tds {
			fmt.Fprintf(h, "digest %s %s %s\n", img, td.Tag, td.Digest)
		}
		newest = append(newest, tds...)
	}
	derived, err := derivedEntry(gr, id)
	if err != nil {
		return o, err
	}
	entry := catalog.Entry{Name: id + ".yaml", Data: string(data)}
	if err := checkNoRegression(entry, derived, cpe, newest, g.EvalCases); err != nil {
		return verdict(err)
	}
	o.yaml = string(data)
	return o, nil
}

// nvdSource is the source state key under which NVD's answer for a
// repository is kept: ETag holds the CPE that passed C5 (empty: none) and
// LastSuccess when NVD gave it. NVD allows 5 requests per 30 s without a
// key, so the answer is reused for RecheckAfter.
const nvdSource = "catgen-nvd"

// cpe finds the CPE of a repository and runs C5 on it, or reuses an answer
// younger than RecheckAfter.
func (g *Generator) cpe(ctx context.Context, repo string, now time.Time) (string, error) {
	if g.NVD == nil {
		return "", nil
	}
	st, err := g.SourceState(ctx, nvdSource, repo)
	if err != nil {
		return "", storeError{err}
	}
	if !st.LastSuccess.IsZero() && now.Sub(st.LastSuccess) < store.RecheckAfter {
		return st.ETag, nil
	}
	cpe, err := g.findCPE(ctx, repo)
	if err != nil {
		return "", err
	}
	if cpe != "" {
		if err := g.checkCPE(ctx, cpe, []string{repo}); err != nil {
			return "", err
		}
	}
	st = store.SourceState{Source: nvdSource, Key: repo, ETag: cpe, LastAttempt: now, LastSuccess: now}
	if err := g.PutSourceState(ctx, st); err != nil {
		return "", storeError{err}
	}
	return cpe, nil
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
	Label string `yaml:"label,omitempty"`
	Tag   string `yaml:"tag,omitempty"`
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
		OCISource: []string{"https://github.com/" + repo},
		// The image's version label first, as in the derived entry's
		// chain (identify's default): the template only replaces the
		// derived entry's tag pattern, so an image whose tag floats keeps
		// the version its label states.
		Version:     versionDoc{Scheme: string(tpl.Scheme), Sources: []sourceDoc{{Label: identify.LabelOCIVer}, {Tag: tpl.Pattern}}},
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
	checks += ", C6 (findings change only through the version and the checked CPE)"
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
