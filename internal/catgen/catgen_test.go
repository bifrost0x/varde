// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/version"
)

// fakeRegistry serves tag lists and digests from maps; a tag without a
// digest does not resolve.
type fakeRegistry struct {
	tags    map[string][]string
	digests map[string]string // image + ":" + tag
	calls   []string
}

func (f *fakeRegistry) Tags(_ context.Context, repository string) ([]string, error) {
	f.calls = append(f.calls, "tags "+repository)
	t, ok := f.tags[repository]
	if !ok {
		return nil, fmt.Errorf("tags of %s: %w", repository, ErrNotFound)
	}
	return t, nil
}

func (f *fakeRegistry) Digest(_ context.Context, repository, tag string) (string, error) {
	f.calls = append(f.calls, "digest "+repository+":"+tag)
	if d, ok := f.digests[repository+":"+tag]; ok {
		return d, nil
	}
	return "", fmt.Errorf("digest of %s:%s: %w", repository, tag, ErrNotFound)
}

// fakeGitHub serves release lists; the ETag of a list is its length, so a
// changed list gets a new one.
type fakeGitHub struct {
	releases map[string][]Release
	calls    []string
}

func (f *fakeGitHub) Releases(_ context.Context, repo, etag string) ([]Release, string, bool, error) {
	f.calls = append(f.calls, repo+" "+etag)
	rels, ok := f.releases[repo]
	if !ok {
		return nil, "", false, fmt.Errorf("releases of %s: %w", repo, ErrNotFound)
	}
	cur := fmt.Sprintf(`"%d"`, len(rels))
	if etag == cur {
		return nil, cur, true, nil
	}
	return rels, cur, false, nil
}

type fakeNVD struct {
	search map[string][]CPEProduct
	byCPE  map[string][]CPEProduct
}

func (f *fakeNVD) SearchProducts(_ context.Context, keyword string) ([]CPEProduct, error) {
	return f.search[keyword], nil
}

func (f *fakeNVD) Products(_ context.Context, cpe string) ([]CPEProduct, error) {
	return f.byCPE[cpe], nil
}

type fakeHub struct{ pulls map[string]int64 }

func (f *fakeHub) PullCount(_ context.Context, repository string) (int64, error) {
	n, ok := f.pulls[repository]
	if !ok {
		return 0, ErrNotFound
	}
	return n, nil
}

var day0 = time.Date(2026, 11, 12, 2, 17, 0, 0, time.UTC)

type env struct {
	g     *Generator
	st    *store.Store
	reg   *fakeRegistry
	gh    *fakeGitHub
	nvd   *fakeNVD
	hub   *fakeHub
	now   time.Time
	index []string // "image<TAB>repo<TAB>kinds" lines
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "builder.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &env{st: st, now: day0,
		reg: &fakeRegistry{tags: map[string][]string{}, digests: map[string]string{}},
		gh:  &fakeGitHub{releases: map[string][]Release{}},
		nvd: &fakeNVD{search: map[string][]CPEProduct{}, byCPE: map[string][]CPEProduct{}},
		hub: &fakeHub{pulls: map[string]int64{}},
	}
	e.g = &Generator{Store: st, Registry: e.reg, GitHub: e.gh, NVD: e.nvd, Hub: e.hub, Now: func() time.Time { return e.now }}
	return e
}

// app adds an index row for an image of a repository whose tags and
// releases pass every check: v1.0.0 to v1.2.0 as releases and tags,
// latest beside them, the newest tag resolving.
func (e *env) app(image, repo, kinds string) {
	e.index = append(e.index, image+"\tgithub.com/"+repo+"\t"+kinds)
	e.reg.tags[image] = []string{"latest", "v1.0.0", "v1.1.0", "v1.2.0"}
	e.reg.digests[image+":v1.2.0"] = "sha256:" + strings.Repeat("a", 64)
	e.gh.releases[repo] = []Release{{Tag: "v1.2.0"}, {Tag: "v1.1.0"}, {Tag: "v1.0.0"}}
}

func (e *env) table(t *testing.T) *applists.Table {
	t.Helper()
	lines := append([]string(nil), e.index...)
	sort.Strings(lines)
	tbl, err := applists.Unmarshal([]byte(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func reviewedCatalog(t *testing.T, entries ...string) *catalog.Catalog {
	t.Helper()
	var es []catalog.Entry
	for i, d := range entries {
		es = append(es, catalog.Entry{Name: fmt.Sprintf("e%d.yaml", i), Data: d})
	}
	c, err := catalog.Build(es, catalog.OriginBuiltin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) run(t *testing.T, reviewed *catalog.Catalog) Report {
	t.Helper()
	if reviewed == nil {
		reviewed = reviewedCatalog(t)
	}
	r, err := e.g.Run(t.Context(), e.table(t), reviewed)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func parseShipped(t *testing.T, r Report) []*catalog.App {
	t.Helper()
	var out []*catalog.App
	for _, s := range r.Shipped {
		a, err := catalog.Parse(s.Name, []byte(s.Data))
		if err != nil {
			t.Fatalf("shipped entry does not parse: %v\n%s", err, s.Data)
		}
		out = append(out, a)
	}
	return out
}

func TestTemplatePicksNarrowest(t *testing.T) {
	rels := releaseSet([]Release{{Tag: "v1.2.3"}, {Tag: "v1.2.4"}, {Tag: "v1.3.0"}})
	// Both "v?X.Y.Z" and "X.Y.Z" pass; the second matches fewer tags.
	tags := []string{"v1.2.3", "v1.2.4", "v1.3.0", "1.2.3", "1.2.4", "1.3.0", "latest"}
	tpl, s, ok := pickTemplate([][]string{tags}, rels)
	if !ok || tpl.Pattern != Templates()[1].Pattern || len(s[0].matched) != 3 || s[0].newest != "1.3.0" {
		t.Fatalf("picked %q %+v %v", tpl.Pattern, s, ok)
	}
	// Variant tags are matched by the tail copied from the reviewed entries.
	if v, ok := Templates()[0].Version("v1.2.3-alpine3.20"); !ok || v != "1.2.3" {
		t.Errorf("variant tail: %q %v", v, ok)
	}
	if _, ok := Templates()[0].Version("v1.2.3-ls12"); ok {
		t.Error("an unknown suffix matched")
	}
	// Fewer than three tags that are releases: no template.
	if _, _, ok := pickTemplate([][]string{{"1.2.3", "1.2.4", "1.9.9"}}, rels); ok {
		t.Error("a template passed with two release tags")
	}
	// Date tags take the calver template.
	dates := releaseSet([]Release{{Tag: "2026.01.05"}, {Tag: "2026.02.10"}, {Tag: "2026.3.1"}})
	tpl, _, ok = pickTemplate([][]string{{"2026.01.05", "2026.02.10", "2026.3.1", "nightly"}}, dates)
	if !ok || tpl.Scheme != version.CalVer {
		t.Errorf("date tags: %q %v", tpl.Pattern, ok)
	}
	if len(Templates()) != 4 {
		t.Errorf("%d templates", len(Templates()))
	}
	for _, tp := range Templates() {
		if !strings.HasPrefix(tp.Pattern, "^") || !strings.HasSuffix(tp.Pattern, "$") {
			t.Errorf("template %q not anchored", tp.Pattern)
		}
	}
}

func TestFloatingTagsRejectRule(t *testing.T) {
	for tag, want := range map[string]bool{
		"latest": true, "stable": true, "edge": true, "nightly": true, "dev": true, "develop": true,
		"main": true, "master": true, "beta": true, "alpha": true, "rc": true, "testing": true, "unstable": true,
		"3f2a9c1": true, "sha-3f2a9c1": true, "1.2.3-rc.1": true, "1.2.3-beta2": true, "1.2.3-alpha": true,
		"1.2.3-dev": true, "Latest": true,
		"1.2.3": false, "v1.2.3-alpine": false, "2026.11.12": false, "release": false,
	} {
		if got := Floating(tag); got != want {
			t.Errorf("Floating(%q) = %v", tag, got)
		}
	}
	// A reviewed rule that also matches release candidates fails C3, with
	// the narrowest template as the proposed fix.
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.reg.tags["ghcr.io/acme/widget"] = append(e.reg.tags["ghcr.io/acme/widget"], "v1.3.0-rc.1")
	app := reviewedCatalog(t, reviewedYAML("widget", `'^v?(?P<v>\d+\.\d+\.\d+(?:-rc\.\d+)?)$'`, "")).Apps()[0]
	probs := e.g.CheckReviewed(t.Context(), app)
	if len(probs) != 1 || probs[0].Check != CheckTags || probs[0].Fix == nil || probs[0].Fix.Tag != Templates()[0].Pattern {
		t.Fatalf("problems %+v", probs)
	}
	// The same entry with a rule that leaves the candidate out passes.
	app = reviewedCatalog(t, reviewedYAML("widget", `'^v?(?P<v>\d+\.\d+\.\d+)$'`, "")).Apps()[0]
	if probs := e.g.CheckReviewed(t.Context(), app); len(probs) != 0 {
		t.Errorf("problems %+v", probs)
	}
}

func reviewedYAML(id, tagRule, extra string) string {
	return `id: ` + id + `
name: Widget
homepage: https://example.org/
images:
  - match: ghcr.io/acme/widget
oci_source:
  - https://github.com/acme/widget
version:
  scheme: semver
  sources:
    - tag: ` + tagRule + `
advisories:
  coverage: partial
  github_repos: [acme/widget]
` + extra + `maintainers_of_entry: [bifrost0x]
verified: 2026-11-01
`
}

func TestC4MajorMinor(t *testing.T) {
	for _, c := range []struct {
		scheme  version.Scheme
		newest  string
		rels    []Release
		wantErr bool
	}{
		{version.SemVer, "1.4.2", []Release{{Tag: "v1.4.0"}, {Tag: "v1.3.9"}}, false},
		{version.SemVer, "1.4.2", []Release{{Tag: "v1.5.0"}}, true},
		{version.SemVer, "2.0.1", []Release{{Tag: "1.9.0"}}, true},
		// A pre-release or draft is not the newest release.
		{version.SemVer, "1.4.2", []Release{{Tag: "v2.0.0-rc.1", Prerelease: true}, {Tag: "v3.0.0", Draft: true}, {Tag: "v1.4.1"}}, false},
		{version.SemVer, "1.4.2", nil, true},
		{version.CalVer, "2026.11.1", []Release{{Tag: "2026.11.1"}}, false},
		{version.CalVer, "2026.11.1", []Release{{Tag: "2026.11.2"}}, true},
	} {
		err := checkVersion(c.scheme, version.MustParse(c.scheme, c.newest), c.rels)
		if (err != nil) != c.wantErr {
			t.Errorf("%s against %+v: %v", c.newest, c.rels, err)
		}
	}
	// In a run: the tag stream is a major line behind the releases.
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.gh.releases["acme/widget"] = append([]Release{{Tag: "v2.0.0"}}, e.gh.releases["acme/widget"]...)
	r := e.run(t, nil)
	if len(r.Shipped) != 0 || r.Failed["ghcr.io/acme/widget"] != CheckVersion {
		t.Fatalf("report %+v", r)
	}
}

func TestCPEOnlyWithRepoReference(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.app("ghcr.io/acme/gadget", "acme/gadget", "ghcr,readme")
	// widget: NVD knows a product whose references name the repository.
	widget := CPEProduct{Name: "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*", Refs: []string{"https://github.com/Acme/Widget/releases"}}
	e.nvd.search["widget"] = []CPEProduct{widget, {Name: "cpe:2.3:a:other:widget:1.0:*:*:*:*:*:*:*", Refs: []string{"https://other.example/"}}}
	e.nvd.byCPE["cpe:2.3:a:acme:widget"] = []CPEProduct{widget}
	// gadget: a product of the same name, but nothing ties it to the repository.
	e.nvd.search["gadget"] = []CPEProduct{{Name: "cpe:2.3:a:acme:gadget:2.0:*:*:*:*:*:*:*", Refs: []string{"https://github.com/acme/gadget-pro"}}}
	r := e.run(t, nil)
	apps := parseShipped(t, r)
	if len(apps) != 2 {
		t.Fatalf("report %+v", r)
	}
	cpes := map[string][]string{}
	for _, a := range apps {
		cpes[a.ID] = a.Advisories.CPE
	}
	if got := cpes["gh-acme-widget"]; len(got) != 1 || got[0] != "cpe:2.3:a:acme:widget" {
		t.Errorf("widget cpe %v", got)
	}
	if got := cpes["gh-acme-gadget"]; len(got) != 0 {
		t.Errorf("gadget cpe %v", got)
	}
	if !strings.Contains(r.Shipped[1].Data, "C5") || strings.Contains(r.Shipped[0].Data, "C5") {
		t.Errorf("notes do not say which checks passed:\n%s\n%s", r.Shipped[0].Data, r.Shipped[1].Data)
	}
	// A reviewed CPE NVD does not tie to the repository is a C5 problem.
	app := reviewedCatalog(t, reviewedYAML("widget", `'^v?(?P<v>\d+\.\d+\.\d+)$'`, "  cpe: [cpe:2.3:a:acme:widget_server]\n")).Apps()[0]
	e.nvd.byCPE["cpe:2.3:a:acme:widget_server"] = []CPEProduct{{Name: "cpe:2.3:a:acme:widget_server:1:*:*:*:*:*:*:*", Refs: []string{"https://acme.example/"}}}
	if probs := e.g.CheckReviewed(t.Context(), app); len(probs) != 1 || probs[0].Check != CheckCPE {
		t.Errorf("problems %+v", probs)
	}
}

func TestCollisionWithReviewedAlias(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.app("ghcr.io/acme/gizmo", "acme/gizmo", "ghcr,readme")
	// A reviewed entry took over the derived app of acme/widget under its
	// old ID; the generated entry must not compete with it.
	reviewed := reviewedCatalog(t, `id: widget-app
aliases: [gh-acme-widget]
name: Widget
homepage: https://example.org/
images:
  - match: docker.io/acme/widget-other
maintainers_of_entry: [bifrost0x]
version: {scheme: semver}
advisories: {coverage: partial}
verified: 2026-11-01
`)
	r := e.run(t, reviewed)
	if r.Failed["ghcr.io/acme/widget"] != CheckSchema {
		t.Fatalf("collision not caught: %+v", r)
	}
	if len(r.Shipped) != 1 || !strings.Contains(r.Shipped[0].Data, "id: gh-acme-gizmo") {
		t.Fatalf("shipped %+v", r.Shipped)
	}
	// What ships loads beneath the reviewed entries without a drop.
	c, err := catalog.BuildLayered([]catalog.Entry{{Name: "w.yaml", Data: reviewedYAMLPlain()}}, catalog.OriginFeed, r.Shipped, nil)
	if err != nil || len(c.DroppedGenerated()) != 0 {
		t.Fatalf("layered: %v %v", err, c.DroppedGenerated())
	}
	if a, ok := c.ByImage("ghcr.io/acme/gizmo"); !ok || a.Origin != catalog.OriginGenerated {
		t.Errorf("generated entry not in the catalog")
	}
}

func reviewedYAMLPlain() string {
	return `id: other
name: Other
homepage: https://example.org/
images:
  - match: docker.io/acme/other
maintainers_of_entry: [bifrost0x]
version: {scheme: semver}
advisories: {coverage: partial}
verified: 2026-11-01
`
}

func TestDerivedIDStable(t *testing.T) {
	e := newEnv(t)
	e.app("docker.io/someone/my.app", "some-one/my.app", "hub,readme")
	e.hub.pulls["someone/my.app"] = 10
	r := e.run(t, nil)
	apps := parseShipped(t, r)
	if len(apps) != 1 {
		t.Fatalf("report %+v", r)
	}
	derived, ok := catalog.DeriveFor("github.com/some-one/my.app", "docker.io/someone/my.app", catalog.Derivation{Basis: catalog.BasisIndex})
	if !ok || apps[0].ID != derived.ID || apps[0].ID != catalog.DerivedID("some-one", "my.app") {
		t.Fatalf("generated ID %q, derived %q", apps[0].ID, derived.ID)
	}
	// Two images of one project make one entry, under the same ID.
	e = newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.app("docker.io/acme/widget", "acme/widget", "hub,readme")
	e.hub.pulls["acme/widget"] = 5
	r = e.run(t, nil)
	apps = parseShipped(t, r)
	if len(apps) != 1 || apps[0].ID != "gh-acme-widget" || len(apps[0].Images) != 2 {
		t.Fatalf("shipped %+v", r.Shipped)
	}
	// One image of the project without confirmed evidence fails the
	// entry: shipping the other alone would take its derived entry's ID.
	e = newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.app("docker.io/acme/widget", "acme/widget", "hub")
	e.hub.pulls["acme/widget"] = 5
	r = e.run(t, nil)
	if len(r.Shipped) != 0 || r.Failed["ghcr.io/acme/widget"] != CheckEvidence || r.Failed["docker.io/acme/widget"] != CheckEvidence {
		t.Fatalf("report %+v", r)
	}
}

func TestBudget150(t *testing.T) {
	e := newEnv(t)
	for i := range 200 {
		img := fmt.Sprintf("docker.io/acme/app%03d", i)
		e.app(img, fmt.Sprintf("acme/app%03d", i), "hub,readme")
		e.hub.pulls[fmt.Sprintf("acme/app%03d", i)] = int64(i)
	}
	r := e.run(t, nil)
	if len(r.Shipped) != 150 || len(r.New) != 150 {
		t.Fatalf("first build shipped %d, new %d", len(r.Shipped), len(r.New))
	}
	// The heaviest go first.
	for _, s := range r.Shipped {
		if a, _ := catalog.Parse(s.Name, []byte(s.Data)); a.ID < "gh-acme-app050" {
			t.Errorf("light candidate %s checked before heavier ones", a.ID)
		}
	}
	r = e.run(t, nil)
	if len(r.Shipped) != 200 || len(r.New) != 50 {
		t.Fatalf("second build shipped %d, new %d", len(r.Shipped), len(r.New))
	}
	e.g.Budget = 10
	e.app("docker.io/acme/late", "acme/late", "hub,readme")
	e.hub.pulls["acme/late"] = 1
	if r = e.run(t, nil); len(r.New) != 1 || len(r.Shipped) != 201 {
		t.Fatalf("third build new %v", r.New)
	}
}

func TestRecheckAfter30Days(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	r := e.run(t, nil)
	if len(r.Shipped) != 1 || !strings.Contains(r.Shipped[0].Data, "verified: \"2026-11-12\"") && !strings.Contains(r.Shipped[0].Data, "verified: 2026-11-12") {
		t.Fatalf("report %+v", r)
	}
	// Ten days later nothing changed: the entry ships unchanged and the
	// registry is not asked.
	e.now = day0.Add(10 * 24 * time.Hour)
	e.reg.calls = nil
	r = e.run(t, nil)
	if len(r.Shipped) != 1 || len(e.reg.calls) != 0 || len(r.Changed)+len(r.New)+len(r.Dropped) != 0 {
		t.Fatalf("checked again too early: %v %+v", e.reg.calls, r)
	}
	// After 30 days it is checked again and verified anew.
	e.now = day0.Add(31 * 24 * time.Hour)
	r = e.run(t, nil)
	if len(e.reg.calls) == 0 || len(r.Shipped) != 1 || !strings.Contains(r.Shipped[0].Data, "2026-12-13") {
		t.Fatalf("not checked again: %v %+v", e.reg.calls, r)
	}
	if len(r.Changed)+len(r.New)+len(r.Dropped) != 0 {
		t.Errorf("a new verified date counted as a change: %+v", r)
	}
	// A new release changes the inputs: checked again the next day.
	e.now = e.now.Add(24 * time.Hour)
	e.reg.calls = nil
	e.gh.releases["acme/widget"] = append([]Release{{Tag: "v1.3.0"}}, e.gh.releases["acme/widget"]...)
	e.reg.tags["ghcr.io/acme/widget"] = append(e.reg.tags["ghcr.io/acme/widget"], "v1.3.0")
	e.reg.digests["ghcr.io/acme/widget:v1.3.0"] = "sha256:" + strings.Repeat("b", 64)
	r = e.run(t, nil)
	if len(e.reg.calls) == 0 || len(r.Shipped) != 1 {
		t.Fatalf("input change not checked: %v %+v", e.reg.calls, r)
	}
}

func TestFailedRecheckDrops(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	if r := e.run(t, nil); len(r.Shipped) != 1 {
		t.Fatalf("report %+v", r)
	}
	// The project stops tagging releases: the newest tag no longer resolves.
	delete(e.reg.digests, "ghcr.io/acme/widget:v1.2.0")
	e.now = day0.Add(31 * 24 * time.Hour)
	r := e.run(t, nil)
	if len(r.Shipped) != 0 || len(r.Dropped) != 1 || r.Dropped[0] != "ghcr.io/acme/widget" || r.Failed["ghcr.io/acme/widget"] != CheckTags {
		t.Fatalf("report %+v", r)
	}
	// An image that leaves the index is dropped too.
	e = newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.app("ghcr.io/acme/gizmo", "acme/gizmo", "ghcr,readme")
	e.run(t, nil)
	e.index = e.index[1:]
	if r := e.run(t, nil); len(r.Shipped) != 1 || len(r.Dropped) != 1 || r.Dropped[0] != "ghcr.io/acme/widget" {
		t.Fatalf("report %+v", r)
	}
	// A network error is no verdict: the shipped entry stays.
	e = newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.run(t, nil)
	e.now = day0.Add(31 * 24 * time.Hour)
	e.g.Registry = errRegistry{}
	if r := e.run(t, nil); len(r.Shipped) != 1 || len(r.Dropped) != 0 || len(r.Skipped) != 1 {
		t.Fatalf("report %+v", r)
	}
}

type errRegistry struct{}

func (errRegistry) Tags(context.Context, string) ([]string, error) {
	return nil, fmt.Errorf("connection reset")
}

func (errRegistry) Digest(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("connection reset")
}

func TestCoverageNeverFull(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	widget := CPEProduct{Name: "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*", Refs: []string{"https://github.com/acme/widget"}}
	e.nvd.search["widget"] = []CPEProduct{widget}
	e.nvd.byCPE["cpe:2.3:a:acme:widget"] = []CPEProduct{widget}
	r := e.run(t, nil)
	apps := parseShipped(t, r)
	if len(apps) != 1 {
		t.Fatalf("report %+v", r)
	}
	a := apps[0]
	if a.Advisories.Coverage != catalog.CoveragePartial {
		t.Errorf("coverage %q", a.Advisories.Coverage)
	}
	if len(a.Maintainers) != 1 || a.Maintainers[0] != "generator" || a.Verified != "2026-11-12" {
		t.Errorf("maintainers %v verified %q", a.Maintainers, a.Verified)
	}
	if !strings.Contains(a.Advisories.Notes, "Generated") || !strings.Contains(a.Advisories.Notes, "C1") {
		t.Errorf("notes %q", a.Advisories.Notes)
	}
	if len(a.Version.Sources) != 1 || a.Version.Sources[0].Tag != Templates()[0].Pattern {
		t.Errorf("tag rule %+v", a.Version.Sources)
	}
	// The rule extracts the version of the newest release tag.
	re := a.Version.Sources[0].TagRegexp()
	if m := re.FindStringSubmatch("v1.2.0"); m == nil || m[re.SubexpIndex("v")] != "1.2.0" {
		t.Errorf("rule does not read v1.2.0")
	}
	if !regexp.MustCompile(`(?m)^  coverage: partial$`).MatchString(r.Shipped[0].Data) {
		t.Errorf("entry text:\n%s", r.Shipped[0].Data)
	}
}
