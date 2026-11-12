// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/version"
)

// The checks. A generated entry ships only when every one passes; a
// candidate is recorded with the first that failed.
const (
	// CheckSchema (C1): the entry is valid and claims nothing a reviewed
	// entry claims (ID, alias, image, source, repository).
	CheckSchema = "C1"
	// CheckEvidence (C2): the index ties every image to the repository by
	// confirmed first-party evidence.
	CheckEvidence = "C2"
	// CheckTags (C3): the tag rule matches at least three tags that are
	// GitHub releases and no floating tag, and the newest resolves.
	CheckTags = "C3"
	// CheckVersion (C4): the newest tag is on the line of the newest
	// GitHub release (same major.minor; equal for date versions).
	CheckVersion = "C4"
	// CheckCPE (C5): the CPE exists in NVD and NVD ties it to the
	// repository.
	CheckCPE = "C5"
	// CheckStale marks a shipped entry that no check could confirm for
	// twice RecheckAfter (its sources kept failing): it stops shipping.
	CheckStale = "stale"
	// CheckUnchecked marks a Problem that is no verdict: a source could
	// not be asked, so the entry is to be checked again.
	CheckUnchecked = "unchecked"
)

// Problem is a check a reviewed entry fails, with a proposed tag rule when
// a template fits the image's tags.
type Problem struct {
	Check, Detail string
	Fix           *catalog.VersionSource
}

// failure is a failed check of a candidate.
type failure struct{ check, detail string }

func (f *failure) Error() string { return f.check + ": " + f.detail }

func fail(check, format string, args ...any) error {
	return &failure{check: check, detail: fmt.Sprintf(format, args...)}
}

// evidenceKinds are the kinds of first-party evidence (the index's kinds
// and an image's own source label), as catalog.BasisIndex counts them.
var evidenceKinds = map[string]bool{"readme": true, "hub": true, "ghcr": true, "label": true}

// checkEvidence is C2: the same rule that confirms a derived entry of the
// index (two kinds of first-party evidence), for every image.
func checkEvidence(rows []applists.Entry) error {
	for _, e := range rows {
		kinds := map[string]bool{}
		for _, k := range e.Lists {
			if evidenceKinds[k] {
				kinds[k] = true
			}
		}
		if len(kinds) < 2 {
			return fail(CheckEvidence, "%s rests on %s alone", e.Image, strings.Join(e.Lists, ","))
		}
	}
	return nil
}

// precheck is C1's claims and C2, which need no network: they run on every
// project each build, whatever the budget. ids counts the repositories per
// derived ID; two repositories that derive one ID both fail, as nothing
// could tell their findings apart.
func precheck(reviewed *catalog.Catalog, gr *group, ids map[string]int) error {
	owner, name, _ := strings.Cut(gr.repo, "/")
	id := catalog.DerivedID(owner, name)
	if ids[id] > 1 {
		return fail(CheckSchema, "id %s is derived by %d repositories", id, ids[id])
	}
	if err := checkClaims(reviewed, id, gr.repo, gr.images()); err != nil {
		return err
	}
	return checkEvidence(gr.entries)
}

// checkClaims is the collision part of C1: a reviewed entry wins every key,
// so an entry that would compete with one is not generated at all.
func checkClaims(reviewed *catalog.Catalog, id, repo string, images []string) error {
	if a, ok := reviewed.App(id); ok {
		return fail(CheckSchema, "id %s is taken by reviewed entry %s", id, a.ID)
	}
	for _, img := range images {
		if a, ok := reviewed.ByImage(img); ok {
			return fail(CheckSchema, "image %s is matched by reviewed entry %s", img, a.ID)
		}
	}
	if a, ok := reviewed.ByOCISource("https://github.com/" + repo); ok {
		return fail(CheckSchema, "source github.com/%s is claimed by reviewed entry %s", repo, a.ID)
	}
	if a, ok := reviewed.ByGitHubRepo(repo); ok {
		return fail(CheckSchema, "repository %s is read by reviewed entry %s", repo, a.ID)
	}
	return nil
}

// newestRelease is the highest version among the published releases that
// are not pre-releases, read under scheme.
func newestRelease(scheme version.Scheme, rels []Release) (version.Version, bool) {
	var best version.Version
	for _, r := range rels {
		if r.Draft || r.Prerelease {
			continue
		}
		v, err := version.Parse(scheme, stripV(r.Tag))
		if err != nil || v.Prerelease() {
			continue
		}
		if c, _ := v.Compare(best); best.IsZero() || c > 0 {
			best = v
		}
	}
	return best, !best.IsZero()
}

// checkVersion is C4.
func checkVersion(scheme version.Scheme, newest version.Version, rels []Release) error {
	rel, ok := newestRelease(scheme, rels)
	if !ok {
		return fail(CheckVersion, "no published release reads as a %s version", scheme)
	}
	if scheme == version.CalVer {
		if c, ok := newest.Compare(rel); !ok || c != 0 {
			return fail(CheckVersion, "newest tag %s is not the newest release %s", newest, rel)
		}
		return nil
	}
	if majorMinor(newest) != majorMinor(rel) {
		return fail(CheckVersion, "newest tag %s is not on the line of the newest release %s", newest, rel)
	}
	return nil
}

func majorMinor(v version.Version) string {
	core, _, _ := strings.Cut(v.String(), "-")
	parts := strings.Split(core, ".")
	for len(parts) < 2 {
		parts = append(parts, "0")
	}
	return parts[0] + "." + parts[1]
}

// references reports whether NVD's references of a product name one of
// the repositories ("owner/name") or a page inside it.
func references(p CPEProduct, repos []string) bool {
	for _, ref := range p.Refs {
		r := strings.ToLower(strings.TrimSpace(ref))
		r = strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "http://")
		r = strings.TrimPrefix(r, "www.")
		r = strings.TrimSuffix(strings.TrimSuffix(r, "/"), ".git")
		for _, repo := range repos {
			u := "github.com/" + strings.ToLower(repo)
			if r == u || strings.HasPrefix(r, u+"/") || strings.HasPrefix(r, u+"#") || strings.HasPrefix(r, u+"?") {
				return true
			}
		}
	}
	return false
}

// cpePrefix is the vendor and product part of an application CPE, the form
// catalog entries carry. Names with escaped characters are left out.
var cpePrefix = regexp.MustCompile(`^cpe:2\.3:a:[a-z0-9._~-]+:[a-z0-9._~-]+$`)

func vendorProduct(name string) (string, bool) {
	parts := strings.SplitN(name, ":", 6)
	if len(parts) < 5 {
		return "", false
	}
	p := strings.Join(parts[:5], ":")
	return p, cpePrefix.MatchString(p)
}

// findCPE looks for the CPE of a repository: the one vendor and product
// pair among NVD's products named like the repository whose references
// point to the repository. Several pairs are no answer.
func (g *Generator) findCPE(ctx context.Context, repo string) (string, error) {
	_, name, _ := strings.Cut(repo, "/")
	products, err := g.NVD.SearchProducts(ctx, name)
	if errors.Is(err, ErrTruncated) {
		// Some products were not returned; one of them could tie another
		// pair to the repository.
		return "", nil
	}
	if err != nil {
		return "", err
	}
	found := ""
	for _, p := range products {
		if p.Deprecated || !references(p, []string{repo}) {
			continue
		}
		vp, ok := vendorProduct(p.Name)
		if !ok {
			continue
		}
		if found != "" && found != vp {
			return "", nil
		}
		found = vp
	}
	return found, nil
}

// checkCPE is C5. Without repositories only existence is checked.
func (g *Generator) checkCPE(ctx context.Context, cpe string, repos []string) error {
	products, err := g.NVD.Products(ctx, cpe)
	if err != nil {
		if errors.Is(err, ErrTruncated) {
			return fail(CheckCPE, "NVD lists more products for %s than it returned", cpe)
		}
		if notFound(err) {
			return fail(CheckCPE, "%s is not in NVD", cpe)
		}
		return err
	}
	live := 0
	for _, p := range products {
		if p.Deprecated {
			continue
		}
		live++
		if len(repos) == 0 || references(p, repos) {
			return nil
		}
	}
	if live == 0 {
		return fail(CheckCPE, "%s is not in NVD", cpe)
	}
	return fail(CheckCPE, "NVD does not tie %s to %s", cpe, strings.Join(repos, ", "))
}

// derivedForm is the shape of a derived entry's ID.
var derivedForm = regexp.MustCompile(`^gh-`)

// CheckReviewed runs C1, C3, C4 and C5 on a reviewed entry. A failure does
// not drop the entry (a person wrote it); the problems go to the
// maintainer, with a tag rule from the templates where one fits.
func (g *Generator) CheckReviewed(ctx context.Context, app *catalog.App) []Problem {
	var out []Problem
	add := func(err error) {
		var f *failure
		if errors.As(err, &f) {
			out = append(out, Problem{Check: f.check, Detail: app.ID + ": " + f.detail})
			return
		}
		out = append(out, Problem{Check: CheckUnchecked, Detail: app.ID + ": " + err.Error()})
	}
	repos := reviewedRepos(app)

	// C1: the catalog validated the entry when it loaded. What is left is
	// the ID space of derived entries: an ID or alias in that form that is
	// not the derived ID of the entry's own repository would take over
	// another project's stored findings.
	own := map[string]bool{}
	for _, r := range repos {
		o, n, _ := strings.Cut(strings.ToLower(r), "/")
		own[catalog.DerivedID(o, n)] = true
	}
	for _, id := range append([]string{app.ID}, app.Aliases...) {
		if derivedForm.MatchString(id) && !own[id] {
			add(fail(CheckSchema, "%s has the form of a derived ID of another repository", id))
		}
	}

	if len(repos) > 0 && len(app.Images) > 0 {
		out = append(out, g.checkReviewedTags(ctx, app, repos[0])...)
	}
	for _, cpe := range app.Advisories.CPE {
		if err := g.checkCPE(ctx, cpe, repos); err != nil {
			add(err)
		}
	}
	return out
}

// checkReviewedTags is C3 and C4 of a reviewed entry, per image.
func (g *Generator) checkReviewedTags(ctx context.Context, app *catalog.App, repo string) []Problem {
	var out []Problem
	rels, _, _, err := g.GitHub.Releases(ctx, repo, "")
	if err != nil {
		if notFound(err) {
			return []Problem{{Check: CheckTags, Detail: app.ID + ": " + repo + " has no GitHub releases to compare tags with"}}
		}
		return []Problem{{Check: CheckUnchecked, Detail: app.ID + ": " + err.Error()}}
	}
	releases := releaseSet(rels)
	var rules []*regexp.Regexp
	for _, s := range app.Version.Sources {
		if re := s.TagRegexp(); re != nil {
			rules = append(rules, re)
		}
	}
	scheme := app.Version.Scheme
	for _, img := range app.Images {
		image, err := imageref.NormaliseRepository(img.Match)
		if err != nil {
			continue
		}
		tags, err := g.tags(ctx, image)
		if err != nil {
			var f *failure
			if errors.As(err, &f) {
				out = append(out, Problem{Check: f.check, Detail: app.ID + ": " + f.detail})
			} else {
				out = append(out, Problem{Check: CheckUnchecked, Detail: app.ID + ": " + err.Error()})
			}
			continue
		}
		var fix *catalog.VersionSource
		if t, _, ok := pickTemplate([][]string{tags}, releases); ok {
			fix = &catalog.VersionSource{Tag: t.Pattern}
		}
		if len(rules) == 0 {
			// Nothing to check; a template that fits is a proposal.
			if fix != nil {
				out = append(out, Problem{Check: CheckTags, Detail: fmt.Sprintf("%s: no tag rule; %s reads %s", app.ID, fix.Tag, image), Fix: fix})
			}
			continue
		}
		s := evaluate(rules, scheme, tags, releases)
		if err := g.checkStream(ctx, image, s); err != nil {
			var f *failure
			if !errors.As(err, &f) {
				out = append(out, Problem{Check: CheckUnchecked, Detail: app.ID + ": " + err.Error()})
				continue
			}
			p := Problem{Check: f.check, Detail: app.ID + ": " + f.detail}
			if fix != nil && fix.Tag != ruleText(app) {
				p.Fix = fix
			}
			out = append(out, p)
			continue
		}
		if err := checkVersion(scheme, s.newestVersion, rels); err != nil {
			var f *failure
			errors.As(err, &f)
			out = append(out, Problem{Check: f.check, Detail: fmt.Sprintf("%s: %s: %s", app.ID, image, f.detail)})
		}
	}
	return out
}

func ruleText(app *catalog.App) string {
	for _, s := range app.Version.Sources {
		if s.Tag != "" {
			return s.Tag
		}
	}
	return ""
}

// tags reads the whole tag list of an image for C3. A missing or cut list
// fails the check: a rule proved on part of the tags proves nothing.
func (g *Generator) tags(ctx context.Context, image string) ([]string, error) {
	tags, complete, err := g.Registry.AllTags(ctx, image)
	switch {
	case err != nil && notFound(err):
		return nil, fail(CheckTags, "image %s has no tag list", image)
	case err != nil:
		return nil, err
	case !complete:
		return nil, fail(CheckTags, "the registry cut the tag list of %s", image)
	}
	return tags, nil
}

// checkStream is C3 on one image's stream: the tag part, then the digest
// of the newest tag.
func (g *Generator) checkStream(ctx context.Context, image string, s stream) error {
	switch {
	case len(s.floating) > 0:
		return fail(CheckTags, "the tag rule matches floating tags of %s (%s)", image, strings.Join(first(s.floating, 5), ", "))
	case s.released < minReleaseTags:
		return fail(CheckTags, "the tag rule matches %d GitHub release versions in the tags of %s, fewer than %d", s.released, image, minReleaseTags)
	case s.newest == "":
		return fail(CheckTags, "no tag of %s matched by the rule reads as a version", image)
	}
	d, err := g.Registry.Digest(ctx, image, s.newest)
	if err != nil {
		if notFound(err) {
			return fail(CheckTags, "newest tag %s:%s does not resolve", image, s.newest)
		}
		return err
	}
	if !strings.HasPrefix(d, "sha256:") {
		return fail(CheckTags, "newest tag %s:%s resolves to no digest", image, s.newest)
	}
	return nil
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// reviewedRepos are the GitHub repositories of a reviewed entry: those it
// reads advisories from, else its GitHub source.
func reviewedRepos(app *catalog.App) []string {
	if len(app.Advisories.GitHubRepos) > 0 {
		return app.Advisories.GitHubRepos
	}
	for _, s := range app.OCISource {
		if rest, ok := strings.CutPrefix(strings.ToLower(s), "https://github.com/"); ok && strings.Count(rest, "/") == 1 {
			return []string{rest}
		}
	}
	return nil
}
