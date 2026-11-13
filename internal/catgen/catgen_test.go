// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/eval"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/version"
)

// fakeRegistry serves tag lists and digests from maps; a tag without a
// digest does not resolve.
type fakeRegistry struct {
	tags    map[string][]string
	digests map[string]string // image + ":" + tag
	cut     map[string]bool   // tag lists the registry cut at its page cap
	calls   []string
}

func (f *fakeRegistry) AllTags(_ context.Context, repository string) ([]string, bool, error) {
	f.calls = append(f.calls, "tags "+repository)
	t, ok := f.tags[repository]
	if !ok {
		return nil, false, fmt.Errorf("tags of %s: %w", repository, ErrNotFound)
	}
	return t, !f.cut[repository], nil
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
	onCall   func(etag string)
}

func (f *fakeGitHub) Releases(_ context.Context, repo, etag string) ([]Release, string, bool, error) {
	f.calls = append(f.calls, repo+" "+etag)
	if f.onCall != nil {
		f.onCall(etag)
	}
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
	search    map[string][]CPEProduct
	byCPE     map[string][]CPEProduct
	truncated bool
	calls     int
}

func (f *fakeNVD) SearchProducts(_ context.Context, keyword string) ([]CPEProduct, error) {
	f.calls++
	if f.truncated {
		return f.search[keyword], fmt.Errorf("search %s: %w", keyword, ErrTruncated)
	}
	return f.search[keyword], nil
}

func (f *fakeNVD) Products(_ context.Context, cpe string) ([]CPEProduct, error) {
	f.calls++
	return f.byCPE[cpe], nil
}

type fakeHub struct {
	pulls map[string]int64
	err   error
	calls int
}

func (f *fakeHub) PullCount(_ context.Context, repository string) (int64, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
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
		reg: &fakeRegistry{tags: map[string][]string{}, digests: map[string]string{}, cut: map[string]bool{}},
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
	// But not for ever: an entry no check could confirm for twice
	// RecheckAfter stops shipping.
	e.now = day0.Add(59 * 24 * time.Hour)
	if r := e.run(t, nil); len(r.Shipped) != 1 {
		t.Fatalf("expired within the grace period: %+v", r)
	}
	e.now = day0.Add(61 * 24 * time.Hour)
	r = e.run(t, nil)
	if len(r.Shipped) != 0 || len(r.Dropped) != 1 || r.Failed["ghcr.io/acme/widget"] != CheckStale {
		t.Fatalf("stale entry still ships: %+v", r)
	}
	if r = e.run(t, nil); len(r.Shipped) != 0 || len(r.Dropped) != 0 {
		t.Fatalf("stale entry dropped twice: %+v", r)
	}
}

type errRegistry struct{}

func (errRegistry) AllTags(context.Context, string) ([]string, bool, error) {
	return nil, false, fmt.Errorf("connection reset")
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
	// The derived entry's chain with the template for its tag pattern:
	// the image's version label, then the tag rule.
	if len(a.Version.Sources) != 2 || a.Version.Sources[0].Label != "org.opencontainers.image.version" || a.Version.Sources[1].Tag != Templates()[0].Pattern {
		t.Fatalf("tag rule %+v", a.Version.Sources)
	}
	// The rule extracts the version of the newest release tag.
	re := a.Version.Sources[1].TagRegexp()
	if m := re.FindStringSubmatch("v1.2.0"); m == nil || m[re.SubexpIndex("v")] != "1.2.0" {
		t.Errorf("rule does not read v1.2.0")
	}
	if !regexp.MustCompile(`(?m)^  coverage: partial$`).MatchString(r.Shipped[0].Data) {
		t.Errorf("entry text:\n%s", r.Shipped[0].Data)
	}
}

func TestNewImageHoldsEntryBack(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	if r := e.run(t, nil); len(r.Shipped) != 1 {
		t.Fatalf("report %+v", r)
	}
	// The project gains an image whose weight cannot be read: the old
	// entry, which lacks the image, does not ship meanwhile (it would take
	// the derived entry the new image gets).
	e.now = day0.Add(24 * time.Hour)
	e.app("docker.io/acme/widget", "acme/widget", "hub,readme")
	e.hub.err = fmt.Errorf("connection reset")
	if r := e.run(t, nil); len(r.Shipped) != 0 || r.Skipped["docker.io/acme/widget"] == "" {
		t.Fatalf("old entry shipped without the new image: %+v", r)
	}
	// Once the image is a candidate the project is checked again, outside
	// the budget of new candidates, which a heavier project uses up.
	e.hub.err = nil
	e.hub.pulls["acme/widget"] = 1
	e.app("docker.io/acme/heavy", "acme/heavy", "hub,readme")
	e.hub.pulls["acme/heavy"] = 1000
	e.g.Budget = 1
	r := e.run(t, nil)
	apps := parseShipped(t, r)
	if len(apps) != 2 || apps[1].ID != "gh-acme-widget" || len(apps[1].Images) != 2 {
		t.Fatalf("shipped %+v", r)
	}
}

type refusingRegistry struct{ calls int }

func (l *refusingRegistry) AllTags(context.Context, string) ([]string, bool, error) {
	l.calls++
	return nil, false, &httpx.StatusError{Status: http.StatusTooManyRequests}
}

func (l *refusingRegistry) Digest(context.Context, string, string) (string, error) {
	l.calls++
	return "", &httpx.StatusError{Status: http.StatusTooManyRequests}
}

func TestRateLimitStopsSource(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.app("ghcr.io/acme/gizmo", "acme/gizmo", "ghcr,readme")
	lr := &refusingRegistry{}
	e.g.Registry = lr
	r := e.run(t, nil)
	if lr.calls != 1 || len(r.Stopped) != 1 || r.Stopped[0] != "registry" || len(r.Skipped) != 2 || len(r.Failed) != 0 {
		t.Fatalf("calls %d, report %+v", lr.calls, r)
	}
	// Docker Hub: one rate-limited answer, no further lookups; the images
	// wait for the next build.
	e = newEnv(t)
	e.app("docker.io/acme/widget", "acme/widget", "hub,readme")
	e.app("docker.io/acme/gizmo", "acme/gizmo", "hub,readme")
	e.hub.err = &httpx.StatusError{Status: http.StatusTooManyRequests}
	r = e.run(t, nil)
	if e.hub.calls != 1 || len(r.Stopped) != 1 || r.Stopped[0] != "hub" || len(r.Shipped) != 0 {
		t.Fatalf("calls %d, report %+v", e.hub.calls, r)
	}
}

func TestDeadlineAndNVDCache(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	widget := CPEProduct{Name: "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*", Refs: []string{"https://github.com/acme/widget"}}
	e.nvd.search["widget"] = []CPEProduct{widget}
	e.nvd.byCPE["cpe:2.3:a:acme:widget"] = []CPEProduct{widget}
	if r := e.run(t, nil); len(r.Shipped) != 1 || e.nvd.calls != 2 {
		t.Fatalf("nvd calls %d, report %+v", e.nvd.calls, r)
	}
	// A new release two days later: checked again, NVD's answer reused.
	e.now = day0.Add(2 * 24 * time.Hour)
	e.gh.releases["acme/widget"] = append([]Release{{Tag: "v1.2.1"}}, e.gh.releases["acme/widget"]...)
	r := e.run(t, nil)
	if apps := parseShipped(t, r); len(apps) != 1 || len(apps[0].Advisories.CPE) != 1 || e.nvd.calls != 2 || len(e.reg.calls) == 0 {
		t.Fatalf("nvd calls %d, report %+v", e.nvd.calls, r)
	}
	// Past the deadline no group starts; what shipped before still ships.
	e.app("ghcr.io/acme/gizmo", "acme/gizmo", "ghcr,readme")
	e.g.Deadline = e.now.Add(-time.Minute)
	e.reg.calls = nil
	r = e.run(t, nil)
	if len(r.Shipped) != 1 || len(e.reg.calls) != 0 || len(r.Stopped) != 1 || r.Stopped[0] != "deadline" {
		t.Fatalf("calls %v, report %+v", e.reg.calls, r)
	}
	e.g.Deadline = time.Time{}
	if r = e.run(t, nil); len(r.Shipped) != 2 {
		t.Fatalf("report %+v", r)
	}
}

func TestReleaseVersionsCountOnce(t *testing.T) {
	rels := releaseSet([]Release{{Tag: "v1.0.0"}, {Tag: "v1.1.0"}})
	// Three tags, but only two release versions.
	if _, _, ok := pickTemplate([][]string{{"v1.0.0", "v1.0.0-alpine", "v1.0.0-slim", "v1.1.0"}}, rels); ok {
		t.Error("variants of one release counted as several releases")
	}
}

func TestCutListsFailClosed(t *testing.T) {
	// A tag list cut at the registry's page cap fails C3.
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.reg.cut["ghcr.io/acme/widget"] = true
	if r := e.run(t, nil); len(r.Shipped) != 0 || r.Failed["ghcr.io/acme/widget"] != CheckTags {
		t.Fatalf("report %+v", r)
	}
	// A cut NVD search gives no CPE.
	e = newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	widget := CPEProduct{Name: "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*", Refs: []string{"https://github.com/acme/widget"}}
	e.nvd.search["widget"] = []CPEProduct{widget}
	e.nvd.byCPE["cpe:2.3:a:acme:widget"] = []CPEProduct{widget}
	e.nvd.truncated = true
	if apps := parseShipped(t, e.run(t, nil)); len(apps) != 1 || len(apps[0].Advisories.CPE) != 0 {
		t.Fatalf("cpe from a cut list: %+v", apps)
	}
}

func TestClaimsCheckedEveryBuild(t *testing.T) {
	e := newEnv(t)
	e.g.Budget = 1
	e.app("docker.io/acme/heavy", "acme/heavy", "hub,readme")
	e.hub.pulls["acme/heavy"] = 1000
	e.app("ghcr.io/acme/weak", "acme/weak", "readme")
	// Two repositories that derive one ID: neither may ship.
	e.app("ghcr.io/a-b/c", "a-b/c", "ghcr,readme")
	e.app("ghcr.io/a/b-c", "a/b-c", "ghcr,readme")
	r := e.run(t, nil)
	if len(r.Shipped) != 1 || r.Failed["ghcr.io/acme/weak"] != CheckEvidence ||
		r.Failed["ghcr.io/a-b/c"] != CheckSchema || r.Failed["ghcr.io/a/b-c"] != CheckSchema {
		t.Fatalf("report %+v", r)
	}
	// When the evidence becomes enough, the image is a candidate again.
	e.index = e.index[:0]
	e.app("docker.io/acme/heavy", "acme/heavy", "hub,readme")
	e.app("ghcr.io/acme/weak", "acme/weak", "ghcr,readme")
	if r = e.run(t, nil); len(r.Shipped) != 2 {
		t.Fatalf("report %+v", r)
	}
}

// widgetEntry is the generated entry of acme/widget on ghcr.io as Run
// writes it, with a CPE when cpe is set.
func widgetEntry(t *testing.T, cpe string) catalog.Entry {
	t.Helper()
	data, err := entryYAML("gh-acme-widget", "acme/widget", []string{"ghcr.io/acme/widget"}, Templates()[0], cpe, "2026-11-12")
	if err != nil {
		t.Fatal(err)
	}
	return catalog.Entry{Name: "gh-acme-widget.yaml", Data: string(data)}
}

// widgetDerived is the entry an installation derives for the image from
// the index.
func widgetDerived(t *testing.T) *catalog.App {
	t.Helper()
	d, ok := catalog.DeriveFor("github.com/acme/widget", "ghcr.io/acme/widget", catalog.Derivation{Basis: catalog.BasisIndex, Evidence: []string{"ghcr", "readme"}, Confirmed: true})
	if !ok {
		t.Fatal("not derived")
	}
	return d
}

func failedCheck(err error) string {
	var f *failure
	if errors.As(err, &f) {
		return f.check
	}
	return ""
}

func TestC6VersionMismatchFails(t *testing.T) {
	// v1.2.1 re-tags the image of v1.2.0. A container running v1.2.0 reads
	// 1.2.0 from its tag, while the resolver gives its digest the newest
	// tag, v1.2.1: the two would disagree on every such container.
	tags := []TagDigest{
		{Image: "ghcr.io/acme/widget", Tag: "v1.2.1", Digest: "sha256:a"},
		{Image: "ghcr.io/acme/widget", Tag: "v1.2.0", Digest: "sha256:a"},
		{Image: "ghcr.io/acme/widget", Tag: "v1.1.0", Digest: "sha256:b"},
	}
	if err := checkNoRegression(widgetEntry(t, ""), widgetDerived(t), "", tags, nil); failedCheck(err) != CheckNoRegression {
		t.Fatalf("got %v", err)
	}
	if err := checkNoRegression(widgetEntry(t, ""), widgetDerived(t), "", []TagDigest{tags[0], tags[2]}, nil); err != nil {
		t.Fatalf("distinct digests: %v", err)
	}

	// In a run: the shared digest is found among the newest tags.
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	img := "ghcr.io/acme/widget"
	e.reg.tags[img] = append(e.reg.tags[img], "v1.2.1")
	e.reg.digests[img+":v1.2.1"] = e.reg.digests[img+":v1.2.0"]
	r := e.run(t, nil)
	if len(r.Shipped) != 0 || r.Failed[img] != CheckNoRegression || !strings.Contains(r.Reasons[img], "v1.2.1") {
		t.Fatalf("report %+v", r)
	}
	// Once v1.2.1 is its own image, the entry ships.
	e.reg.digests[img+":v1.2.1"] = "sha256:" + strings.Repeat("c", 64)
	e.now = e.now.Add(31 * 24 * time.Hour)
	if r := e.run(t, nil); len(r.Shipped) != 1 {
		t.Fatalf("report %+v", r)
	}
}

func TestC6ExtraSourceFails(t *testing.T) {
	cpe := "cpe:2.3:a:acme:widget"
	plain, withCPE := widgetEntry(t, ""), widgetEntry(t, cpe)
	edit := func(e catalog.Entry, old, repl string) catalog.Entry {
		if !strings.Contains(e.Data, old) {
			t.Fatalf("%q not in\n%s", old, e.Data)
		}
		e.Data = strings.Replace(e.Data, old, repl, 1)
		return e
	}
	for _, c := range []struct {
		name  string
		entry catalog.Entry
		cpe   string
		fails bool
	}{
		{"as derived", plain, "", false},
		{"the checked CPE", withCPE, cpe, false},
		{"a CPE that did not pass C5", withCPE, "", true},
		{"another CPE than the checked one", withCPE, "cpe:2.3:a:acme:widget_server", true},
		{"two CPEs", edit(withCPE, "cpe: ['cpe:2.3:a:acme:widget']", "cpe: ['cpe:2.3:a:acme:widget', 'cpe:2.3:a:acme:gadget']"), cpe, true},
		{"another repository", edit(plain, "github_repos: [acme/widget]", "github_repos: [acme/widget, acme/gadget]"), "", true},
		{"an OSV package", edit(plain, "  github_repos:", "  osv_packages: [{ecosystem: npm, name: widget}]\n  github_repos:"), "", true},
		{"a package matcher", edit(plain, "oci_source:", "packages: [{manager: dpkg, name: widget, versioning: upstream}]\noci_source:"), "", true},
		{"an image the derived entry lacks", edit(plain, "  - match: ghcr.io/acme/widget\n", "  - match: ghcr.io/acme/widget\n  - match: docker.io/acme/widget\n"), "", true},
		{"another source", edit(plain, "  - https://github.com/acme/widget\n", "  - https://github.com/acme/widget-base\n"), "", true},
	} {
		err := checkNoRegression(c.entry, widgetDerived(t), c.cpe, nil, nil)
		if got := failedCheck(err) == CheckNoRegression; got != c.fails || (!c.fails && err != nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// An image the derived entry has but does not confirm would alert
	// through the generated one.
	weak, _ := catalog.DeriveFor("github.com/acme/widget", "ghcr.io/acme/widget", catalog.Derivation{Basis: catalog.BasisIndex, Evidence: []string{"readme"}})
	if err := checkNoRegression(plain, weak, "", nil, nil); failedCheck(err) != CheckNoRegression {
		t.Errorf("unconfirmed derived image: %v", err)
	}
	if err := checkNoRegression(plain, nil, "", nil, nil); failedCheck(err) != CheckNoRegression {
		t.Errorf("no derived entry: %v", err)
	}
}

// widgetCase is an eval case of acme/widget's image.
func widgetCase(name, ref, version string) eval.ContainerCase {
	return eval.ContainerCase{Name: name, Image: ref, Truth: eval.Truth{App: "gh-acme-widget", Version: version, Basis: "tag"}}
}

func TestC6EvalWorseFails(t *testing.T) {
	// The derived entry's default pattern reads a four-part version; the
	// generated rule reads none from it.
	worse := widgetCase("four parts", "ghcr.io/acme/widget:1.2.0.7", "1.2.0.7")
	if err := checkNoRegression(widgetEntry(t, ""), widgetDerived(t), "", nil, []eval.ContainerCase{worse}); failedCheck(err) != CheckNoRegression {
		t.Fatalf("got %v", err)
	}
	// A variant tag: the derived entry reads "1.2.0-alpine", the generated
	// rule the release. Better is no regression, and neither is a case
	// of another image.
	better := widgetCase("variant", "ghcr.io/acme/widget:v1.2.0-alpine", "1.2.0")
	other := eval.ContainerCase{Name: "other", Image: "ghcr.io/acme/gadget:1.2.0.7", Truth: eval.Truth{App: "gh-acme-gadget", Version: "1.2.0.7"}}
	if err := checkNoRegression(widgetEntry(t, ""), widgetDerived(t), "", nil, []eval.ContainerCase{better, other}); err != nil {
		t.Fatalf("better: %v", err)
	}
	// Per case: what the variant case gains does not make up for the
	// four-part case (in sum both entries get three right, and the
	// generated one fewer wrong).
	if err := checkNoRegression(widgetEntry(t, ""), widgetDerived(t), "", nil, []eval.ContainerCase{worse, better}); failedCheck(err) != CheckNoRegression || !strings.Contains(err.Error(), "four parts") {
		t.Fatalf("worse and better: %v", err)
	}
	// An image with the project's source label only counts too.
	labelled := worse
	labelled.Image = "docker.io/acme/widget-worker:1.2.0.7"
	labelled.ImageLabels = map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widget"}
	if err := checkNoRegression(widgetEntry(t, ""), widgetDerived(t), "", nil, []eval.ContainerCase{labelled}); err != nil {
		t.Fatalf("label-only image read as derived: %v", err)
	}

	// In a run, with the corpus cases the builder loads.
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.g.EvalCases = []eval.ContainerCase{worse}
	if r := e.run(t, nil); len(r.Shipped) != 0 || r.Failed["ghcr.io/acme/widget"] != CheckNoRegression {
		t.Fatalf("report %+v", r)
	}
}

func TestC6PassesWithCPE(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	img := "ghcr.io/acme/widget"
	// Every tag resolves, two of them to one image under one version.
	e.reg.tags[img] = append(e.reg.tags[img], "v1.2.0-alpine")
	e.reg.digests[img+":v1.1.0"] = "sha256:" + strings.Repeat("b", 64)
	e.reg.digests[img+":v1.0.0"] = "sha256:" + strings.Repeat("c", 64)
	e.reg.digests[img+":v1.2.0-alpine"] = e.reg.digests[img+":v1.2.0"]
	widget := CPEProduct{Name: "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*", Refs: []string{"https://github.com/acme/widget"}}
	e.nvd.search["widget"] = []CPEProduct{widget}
	e.nvd.byCPE["cpe:2.3:a:acme:widget"] = []CPEProduct{widget}
	e.g.EvalCases = []eval.ContainerCase{
		widgetCase("tag", img+":v1.1.0", "1.1.0"),
		widgetCase("variant", img+":v1.2.0-alpine", "1.2.0"),
		{Name: "floating", Image: img + ":latest", RegistryTag: "v1.2.0", Truth: eval.Truth{App: "gh-acme-widget", Version: "1.2.0", Basis: "tag"}},
	}
	r := e.run(t, nil)
	apps := parseShipped(t, r)
	if len(apps) != 1 || len(r.Failed) != 0 || len(apps[0].Advisories.CPE) != 1 || apps[0].Advisories.CPE[0] != "cpe:2.3:a:acme:widget" {
		t.Fatalf("report %+v", r)
	}
	if !strings.Contains(r.Shipped[0].Data, "C6") {
		t.Errorf("notes do not name C6:\n%s", r.Shipped[0].Data)
	}
	// The newest tags were asked once each, the rule's order kept.
	var heads []string
	for _, c := range e.reg.calls {
		if strings.HasPrefix(c, "digest ") {
			heads = append(heads, strings.TrimPrefix(c, "digest "+img+":"))
		}
	}
	if strings.Join(heads, ",") != "v1.2.0,v1.2.0-alpine,v1.1.0,v1.0.0" {
		t.Errorf("digests asked: %v", heads)
	}
}

// failingStore fails UpsertCandidate after n successful calls.
type failingStore struct {
	*store.Store
	n int
}

func (f *failingStore) UpsertCandidate(ctx context.Context, c store.Candidate) error {
	if f.n == 0 {
		return errors.New("disk full")
	}
	f.n--
	return f.Store.UpsertCandidate(ctx, c)
}

func TestReleaseETagAfterRecord(t *testing.T) {
	// The store fails while the outcome of a two-image project is
	// recorded. Its release ETag must not be kept: the next build's probe
	// would answer "not modified" and the project would wait for
	// RecheckAfter with one image recorded.
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.app("docker.io/acme/widget", "acme/widget", "hub,readme")
	e.hub.pulls["acme/widget"] = 5
	// Two candidate rows, then one image of the outcome.
	e.g.Store = &failingStore{Store: e.st, n: 3}
	if _, err := e.g.Run(t.Context(), e.table(t), reviewedCatalog(t)); err == nil {
		t.Fatal("no store error")
	}
	st, err := e.st.SourceState(t.Context(), releasesSource, "acme/widget")
	if err != nil || st.ETag != "" {
		t.Fatalf("etag %q kept after a failed record: %v", st.ETag, err)
	}
	e.g.Store = e.st
	if r := e.run(t, nil); len(r.Shipped) != 1 {
		t.Fatalf("report %+v", r)
	}
	if st, _ := e.st.SourceState(t.Context(), releasesSource, "acme/widget"); st.ETag == "" {
		t.Error("etag not kept after the record")
	}
}

func TestDueChecksBeforeProbes(t *testing.T) {
	e := newEnv(t)
	e.app("ghcr.io/acme/widget", "acme/widget", "ghcr,readme")
	e.run(t, nil)
	e.now = day0.Add(20 * 24 * time.Hour)
	e.app("ghcr.io/acme/gizmo", "acme/gizmo", "ghcr,readme")
	e.app("ghcr.io/acme/gadget", "acme/gadget", "ghcr,readme")
	if r := e.run(t, nil); len(r.Shipped) != 3 {
		t.Fatalf("report %+v", r)
	}
	// Day 31: widget is due, gizmo and gadget only probed. The first
	// probe uses up the time; the due re-check must have run before it.
	e.now = day0.Add(31 * 24 * time.Hour)
	checkAt := e.now
	e.g.Deadline = e.now.Add(30 * time.Minute)
	e.gh.onCall = func(etag string) {
		if etag != "" {
			e.now = e.now.Add(time.Hour)
		}
	}
	r := e.run(t, nil)
	rows, err := e.st.AllCandidates(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rows {
		if c.Image == "ghcr.io/acme/widget" && !c.CheckedAt.Equal(checkAt) {
			t.Fatalf("due re-check did not run (checked %v), report %+v", c.CheckedAt, r)
		}
	}
	if len(r.Stopped) != 1 || r.Stopped[0] != "deadline" {
		t.Errorf("stopped %v", r.Stopped)
	}
}
