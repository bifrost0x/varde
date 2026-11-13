// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/catgen"
	"github.com/bifrost0x/varde/internal/httpx"
)

// fakeRegistry serves one tag list for every image; every tag resolves.
// perImage, when it names an image, replaces the list for it.
type fakeRegistry struct {
	tags     []string
	perImage map[string][]string
	err      error
	calls    int
}

func (f *fakeRegistry) AllTags(_ context.Context, repository string) ([]string, bool, error) {
	f.calls++
	if f.err != nil {
		return nil, false, f.err
	}
	if t, ok := f.perImage[repository]; ok {
		return t, true, nil
	}
	return f.tags, true, nil
}

func (f *fakeRegistry) Digest(_ context.Context, repository, tag string) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return fmt.Sprintf("sha256:%064x", len(repository)+len(tag)), nil
}

type fakeGitHub struct{ releases map[string][]catgen.Release }

func (f *fakeGitHub) Releases(_ context.Context, repo, _ string) ([]catgen.Release, string, bool, error) {
	rels, ok := f.releases[strings.ToLower(repo)]
	if !ok {
		return nil, "", false, fmt.Errorf("releases of %s: %w", repo, catgen.ErrNotFound)
	}
	return rels, "", false, nil
}

// fakeNVD knows every CPE, with a reference to the repository repo.
type fakeNVD struct{ repo string }

func (f *fakeNVD) SearchProducts(context.Context, string) ([]catgen.CPEProduct, error) {
	return nil, nil
}

func (f *fakeNVD) Products(_ context.Context, cpe string) ([]catgen.CPEProduct, error) {
	return []catgen.CPEProduct{{Name: cpe + ":1.0:*:*:*:*:*:*:*", Refs: []string{"https://github.com/" + f.repo}}}, nil
}

var today = time.Date(2026, 11, 16, 3, 41, 0, 0, time.UTC)

// generator answers like the live sources for a project acme/widget whose
// image tags carry the versions of its GitHub releases.
func generator(tags ...string) (*catgen.Generator, *fakeRegistry) {
	if len(tags) == 0 {
		tags = []string{"v1.0.0", "v1.1.0", "v1.2.0", "v1.2.0-alpine", "latest"}
	}
	reg := &fakeRegistry{tags: tags}
	rels := []catgen.Release{{Tag: "v1.2.0"}, {Tag: "v1.1.0"}, {Tag: "v1.0.0"}}
	return &catgen.Generator{
		Registry: reg,
		GitHub:   &fakeGitHub{releases: map[string][]catgen.Release{"acme/widget": rels, "gchq/cyberchef": rels}},
		NVD:      &fakeNVD{repo: "acme/widget"},
	}, reg
}

const semverRule = `'^v?(?P<v>\d+\.\d+\.\d+)(?:-(?:alpine|bookworm|bullseye|trixie|noble|jammy|focal|oraclelinux|oracle|debian|slim|ubi|nanoserver|windowsservercore)[a-z0-9.]*)*$'`

// widget is a reviewed entry with the given tag rule and a comment the
// tool must keep.
func widget(rule string) string {
	return `# SPDX-License-Identifier: Apache-2.0
id: widget
name: Widget
homepage: https://example.org/
images:
  - match: ghcr.io/acme/widget
oci_source:
  - https://github.com/acme/widget
version:
  scheme: semver
  sources:
    # The project tags its images like its releases.
    - tag: ` + rule + `
advisories:
  coverage: partial
  github_repos:
    - acme/widget
  cpe:
    - cpe:2.3:a:acme:widget
  notes: >-
    Widget publishes advisories on its repository.
maintainers_of_entry: [bifrost0x]
verified: 2026-11-01
`
}

// cyberchefShape is one of the entries written on 2026-11-12 without a
// look at the live sources, as catalog/apps/cyberchef.yaml has it.
const cyberchefShape = `# SPDX-License-Identifier: Apache-2.0
id: cyberchef
name: CyberChef
homepage: https://gchq.github.io/CyberChef/
tags: [tools]
images:
  - match: mpepping/cyberchef
    note: community image that serves the released web app
  - match: ghcr.io/gchq/cyberchef
oci_source:
  - https://github.com/gchq/CyberChef
version:
  scheme: semver
  sources:
    - tag: ` + semverRule + `
advisories:
  coverage: partial
  github_repos:
    - gchq/CyberChef
  notes: >-
    CyberChef is a web app that runs in the browser; the container only serves its files. Advisories
    are published on the repository (gchq/CyberChef). Release tags are v-prefixed (v10.19.4); latest
    is floating. Written on 2026-11-12 from the project's public facts without a fresh look at the
    live sources; the CPE, the advisory repository and the tag forms are to be confirmed on the next
    review of this entry.
exposure_hints:
  default_ports: [8000]
  typical: internal
maintainers_of_entry: [bifrost0x]
verified: 2026-11-12
`

// postgresShape has no GitHub repository: the weekly check cannot look at
// its tags, so it must not mark it verified.
const postgresShape = `# SPDX-License-Identifier: Apache-2.0
id: postgresql
name: PostgreSQL
homepage: https://www.postgresql.org
images:
  - match: library/postgres
version:
  scheme: semver
  sources:
    - tag: '^(?P<v>\d+\.\d+)$'
advisories:
  coverage: limited
  cpe:
    - cpe:2.3:a:postgresql:postgresql
  notes: >-
    Versions have two numbers. Written on 2026-11-12 from the project's public facts without a
    fresh look at the live sources; the CPE, the advisory repository and the tag forms are to be
    confirmed on the next review of this entry.
eol: postgresql
maintainers_of_entry: [bifrost0x]
verified: 2026-11-12
`

func writeCatalog(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func check(t *testing.T, g *catgen.Generator, files map[string]string) (out string, res result) {
	t.Helper()
	out = filepath.Join(t.TempDir(), "out")
	res, err := run(t.Context(), g, writeCatalog(t, files), out, today)
	if err != nil {
		t.Fatal(err)
	}
	return out, res
}

func outputs(t *testing.T, out string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == out {
				return filepath.SkipDir
			}
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(out, p)
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// changedLines lists the lines that differ between two texts of the same
// length in lines; texts of different length are reported as such.
func changedLines(a, b string) []string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	if len(al) != len(bl) {
		return []string{fmt.Sprintf("%d lines became %d", len(al), len(bl))}
	}
	var out []string
	for i := range al {
		if al[i] != bl[i] {
			out = append(out, bl[i])
		}
	}
	return out
}

func TestNoChangesNoOutput(t *testing.T) {
	g, _ := generator()
	out, res := check(t, g, map[string]string{"widget.yaml": widget(semverRule)})
	if got := outputs(t, out); len(got) != 0 {
		t.Fatalf("outputs %v for an entry that passes every check", got)
	}
	if res.Changed != 0 || res.Reported || !res.Complete() {
		t.Errorf("result %+v", res)
	}
}

func TestTagFixWritten(t *testing.T) {
	g, _ := generator("v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0-rc.1", "latest")
	src := widget(`'^v?(?P<v>\d+\.\d+\.\d+(?:-rc\.\d+)?)$'`)
	out, res := check(t, g, map[string]string{"widget.yaml": src})
	if got := outputs(t, out); len(got) != 2 || got[0] != "apps/widget.yaml" || got[1] != "report.md" {
		t.Fatalf("outputs %v", got)
	}
	if res.Changed != 1 || !res.Reported || !res.Complete() {
		t.Errorf("result %+v", res)
	}
	fixed := read(t, filepath.Join(out, "apps", "widget.yaml"))
	want := "    - tag: '" + catgen.Templates()[0].Pattern + "'"
	if d := changedLines(src, fixed); len(d) != 1 || d[0] != want {
		t.Fatalf("changed lines %q, want only %q", d, want)
	}
	// The entry with the new rule is valid and reads its version with it.
	app, err := catalog.Parse("widget.yaml", []byte(fixed))
	if err != nil {
		t.Fatal(err)
	}
	if app.Version.Sources[0].Tag != catgen.Templates()[0].Pattern {
		t.Errorf("rule %q", app.Version.Sources[0].Tag)
	}
	report := read(t, filepath.Join(out, "report.md"))
	for _, s := range []string{"C3", "widget.yaml", "floating", catgen.Templates()[0].Pattern} {
		if !strings.Contains(report, s) {
			t.Errorf("report lacks %q:\n%s", s, report)
		}
	}
	// A rule the generator has no template for stays; the report says why.
	g, _ = generator("1", "2", "latest")
	out, res = check(t, g, map[string]string{"widget.yaml": src})
	if got := outputs(t, out); len(got) != 1 || got[0] != "report.md" || res.Changed != 0 {
		t.Fatalf("outputs %v, result %+v", got, res)
	}
}

func TestUnverifiedEntryVerifiedWhenPassing(t *testing.T) {
	g, _ := generator("v10.19.2", "v10.19.3", "v10.19.4", "v10.19.4-alpine", "latest")
	g.GitHub = &fakeGitHub{releases: map[string][]catgen.Release{"gchq/cyberchef": {{Tag: "v10.19.4"}, {Tag: "v10.19.3"}, {Tag: "v10.19.2"}}}}
	out, res := check(t, g, map[string]string{"cyberchef.yaml": cyberchefShape})
	if res.Changed != 1 {
		t.Fatalf("result %+v, outputs %v", res, outputs(t, out))
	}
	fixed := read(t, filepath.Join(out, "apps", "cyberchef.yaml"))
	app, err := catalog.Parse("cyberchef.yaml", []byte(fixed))
	if err != nil {
		t.Fatal(err)
	}
	orig, err := catalog.Parse("cyberchef.yaml", []byte(cyberchefShape))
	if err != nil {
		t.Fatal(err)
	}
	wantNotes, _, _ := strings.Cut(orig.Advisories.Notes, " Written on")
	if app.Advisories.Notes != wantNotes {
		t.Errorf("notes\n%q\nwant\n%q", app.Advisories.Notes, wantNotes)
	}
	if !strings.Contains(fixed, "\nverified: 2026-11-16\n") {
		t.Errorf("verified not set to the day of the check:\n%s", fixed)
	}
	// Everything before the notes' last lines is untouched, and the
	// rewrapped lines keep the indentation and width of the block.
	before, _, _ := strings.Cut(cyberchefShape, "    is floating.")
	if !strings.HasPrefix(fixed, before) {
		t.Errorf("text before the sentence changed:\n%s", fixed)
	}
	if !strings.Contains(fixed, "    is floating.\nexposure_hints:\n") {
		t.Errorf("notes not closed where the sentence was:\n%s", fixed)
	}
	for _, l := range strings.Split(fixed, "\n") {
		if strings.HasPrefix(l, "    ") && !strings.HasPrefix(l, "    -") && len(l) > 100 {
			t.Errorf("line longer than 100: %q", l)
		}
	}
	report := read(t, filepath.Join(out, "report.md"))
	if !strings.Contains(report, "cyberchef.yaml") || !strings.Contains(report, "verified") {
		t.Errorf("report does not name the verified entry:\n%s", report)
	}

	// An entry the check cannot look at fully (no GitHub repository, so
	// no tag check) passes what runs but stays unverified; the report
	// says a person has to look.
	g, _ = generator("16.3", "16.4", "latest")
	g.NVD = &fakeNVD{}
	out, res = check(t, g, map[string]string{"postgresql.yaml": postgresShape})
	if got := outputs(t, out); len(got) != 1 || got[0] != "report.md" || res.Changed != 0 {
		t.Fatalf("outputs %v, result %+v", got, res)
	}
	if report := read(t, filepath.Join(out, "report.md")); !strings.Contains(report, "postgresql.yaml") || !strings.Contains(report, "no GitHub repository") {
		t.Errorf("report:\n%s", report)
	}
}

func TestRateLimitStopsAsking(t *testing.T) {
	g, reg := generator()
	reg.err = &httpx.StatusError{Status: http.StatusTooManyRequests}
	files := map[string]string{"widget.yaml": widget(semverRule), "cyberchef.yaml": cyberchefShape}
	out, res := check(t, g, files)
	// The first refusal stops the registry for the run; nothing is
	// changed, the report says what was not checked, and the run is not
	// complete: the workflow leaves an earlier pull request alone.
	if reg.calls != 1 {
		t.Errorf("registry asked %d times after it refused", reg.calls)
	}
	if got := outputs(t, out); len(got) != 1 || got[0] != "report.md" || res.Changed != 0 {
		t.Fatalf("outputs %v, result %+v", got, res)
	}
	if len(res.Stopped) != 1 || res.Stopped[0] != "registry" || res.Unchecked == 0 || res.Complete() {
		t.Errorf("result %+v", res)
	}
	if r := read(t, filepath.Join(out, "report.md")); !strings.Contains(r, "rate limit: registry") {
		t.Errorf("report:\n%s", r)
	}
	status := filepath.Join(t.TempDir(), "status")
	if err := writeStatus(status, res); err != nil {
		t.Fatal(err)
	}
	if got := read(t, status); got != "corrected=false\ncomplete=false\n" {
		t.Errorf("status %q", got)
	}
}

func TestDifferentFixesLeftToAPerson(t *testing.T) {
	// The two images' tags fit different templates: no rule fits both,
	// so the rule is not written and a person decides.
	g, reg := generator()
	reg.perImage = map[string][]string{
		"ghcr.io/acme/widget":   {"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0-rc.1"},
		"docker.io/acme/widget": {"1.0.0", "1.1.0", "1.2.0", "1.3.0-rc.1"},
	}
	src := strings.Replace(widget(`'^v?(?P<v>\d+\.\d+\.\d+(?:-rc\.\d+)?)$'`),
		"  - match: ghcr.io/acme/widget\n", "  - match: ghcr.io/acme/widget\n  - match: acme/widget\n", 1)
	out, res := check(t, g, map[string]string{"widget.yaml": src})
	if got := outputs(t, out); len(got) != 1 || got[0] != "report.md" || res.Changed != 0 {
		t.Fatalf("outputs %v, result %+v", got, res)
	}
	if r := read(t, filepath.Join(out, "report.md")); !strings.Contains(r, "different templates") {
		t.Errorf("report:\n%s", r)
	}
}

func TestHoldsRejectsOtherChanges(t *testing.T) {
	before := widget(semverRule)
	rule := catgen.Templates()[1].Pattern
	after, err := setTagRule(before, rule)
	if err != nil {
		t.Fatal(err)
	}
	if err := (expected{tag: &rule}).holds(before, after); err != nil {
		t.Errorf("the rule change alone: %v", err)
	}
	// Anything beyond the three fields, or a field reading otherwise than
	// intended, refuses the correction.
	other := strings.Replace(after, "coverage: partial", "coverage: full", 1)
	if err := (expected{tag: &rule}).holds(before, other); err == nil {
		t.Error("a changed coverage passed")
	}
	wrong := catgen.Templates()[0].Pattern
	if err := (expected{tag: &wrong}).holds(before, after); err == nil {
		t.Error("a rule other than the intended one passed")
	}
	if err := (expected{}).holds(before, "id: [broken"); err == nil {
		t.Error("an invalid entry passed")
	}
}

func TestTagCommentSpacingKept(t *testing.T) {
	before := strings.Replace(widget(semverRule), semverRule, semverRule+"   # pinned forms only", 1)
	rule := catgen.Templates()[1].Pattern
	after, err := setTagRule(before, rule)
	if err != nil {
		t.Fatal(err)
	}
	want := "    - tag: '" + rule + "'   # pinned forms only"
	if d := changedLines(before, after); len(d) != 1 || d[0] != want {
		t.Errorf("changed lines %q, want %q", d, want)
	}
}

func TestUnverifiedSentenceVariants(t *testing.T) {
	// The sentence in the middle of the notes, wrapped differently: it
	// goes, the text after it stays.
	mid := strings.Replace(cyberchefShape, "    review of this entry.\n",
		"    review of this entry. Tags v10.19 and v10 are floating.\n", 1)
	s, notes, err := dropUnverified(mid)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(notes, "latest is floating. Tags v10.19 and v10 are floating.") {
		t.Errorf("notes %q", notes)
	}
	if err := (expected{notes: &notes}).holds(mid, s); err != nil {
		t.Error(err)
	}
	// A sentence worded otherwise (a period before its end) is not the
	// known one and stays.
	other := strings.Replace(cyberchefShape, "the advisory repository", "the advisory repo. and", 1)
	if _, _, err := dropUnverified(other); err == nil {
		t.Error("a different sentence was removed")
	}
}

func TestReportDetailsInert(t *testing.T) {
	r := report([]entryCheck{{file: "widget.yaml", problems: []catgen.Problem{
		{Check: "C5", Detail: "widget: ping @someone `rm -rf` [x](https://evil.example)\n## injected"},
	}}}, nil, "2026-11-16")
	want := "- `widget.yaml` C5: `widget: ping @someone 'rm -rf' [x](https://evil.example) ## injected`"
	if !strings.Contains(r, want+"\n") {
		t.Errorf("report:\n%s\nwant line %q", r, want)
	}
	if strings.Contains(r, "\n## injected") {
		t.Error("a detail started a heading")
	}
}
