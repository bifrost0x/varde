// SPDX-License-Identifier: Apache-2.0

// Command catalogcheck runs the generator's checks C1, C3, C4 and C5 on the
// reviewed catalog entries (catalog/apps) once a week, for the pull request
// "catalog: weekly check" (.github/workflows/catalog-check.yml, ADR 0040).
//
//	go run ./cmd/catalogcheck -catalog catalog/apps -out work/check
//
// It never changes an entry beyond two things a check proves: the tag rule,
// when the rule failed C3 and one of the generator's templates reads the
// image's tags, and, for an entry written without a look at the live
// sources, that note and the verified date once every check passed. The
// edits are textual and leave comments and formatting alone. Corrected
// files go to <out>/apps/<name>.yaml and the findings to <out>/report.md;
// with nothing to report, nothing is written. Sources that refuse because
// of their rate limit are not asked again in the run.
//
// With -status the run's outcome is appended to a file as key=value lines
// ($GITHUB_OUTPUT in the workflow): corrected (true when entries were
// corrected) and complete (true when every source answered for every
// entry). Only corrections lead to a pull request; problems without one
// stay in the run's summary and artifact.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/catgen"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/registry"
)

const (
	// registryTimeout bounds one registry request; tag lists are paged.
	registryTimeout = 2 * time.Minute
	// lineWidth is the width the catalog's folded notes are wrapped to.
	lineWidth = 100
	// maxReport keeps report.md within what GitHub takes as a pull
	// request body (65536 characters).
	maxReport = 60000
)

func main() { os.Exit(realMain()) }

func realMain() int {
	dir := flag.String("catalog", "catalog/apps", "directory of the reviewed catalog entries")
	out := flag.String("out", "", "directory for the corrected entries (apps/) and report.md")
	timeout := flag.Duration("timeout", 40*time.Minute, "time for the whole check")
	status := flag.String("status", "", "append corrected=... and complete=... to this file")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "catalogcheck: -out is required")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	hc := httpx.New(httpx.Options{})
	g := &catgen.Generator{
		Registry: registry.New(httpx.New(httpx.Options{Timeout: registryTimeout})),
		GitHub:   &catgen.GitHub{HTTP: hc, Token: os.Getenv("GITHUB_TOKEN")},
		NVD:      &catgen.NVD{HTTP: hc, APIKey: os.Getenv("NVD_API_KEY")},
	}
	res, err := run(ctx, g, *dir, *out, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalogcheck:", err)
		return 1
	}
	fmt.Printf("catalogcheck: %d entries checked, %d corrected, %d problems, %d not checked", res.Entries, res.Changed, res.Problems, res.Unchecked)
	if len(res.Stopped) > 0 {
		fmt.Printf(", stopped asking: %s", strings.Join(res.Stopped, ", "))
	}
	fmt.Println()
	if !res.Reported {
		fmt.Println("catalogcheck: nothing to report")
	}
	if *status != "" {
		if err := writeStatus(*status, res); err != nil {
			fmt.Fprintln(os.Stderr, "catalogcheck:", err)
			return 1
		}
	}
	return 0
}

// writeStatus appends the outcome for the workflow.
func writeStatus(path string, res result) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // path from the command line ($GITHUB_OUTPUT)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "corrected=%t\ncomplete=%t\n", res.Changed > 0, res.Complete())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// result sums up a run.
type result struct {
	Entries, Changed, Problems, Unchecked int
	// Reported is set when report.md was written.
	Reported bool
	// Stopped names the sources not asked again after a rate limit.
	Stopped []string
}

// Complete reports that every source answered for every entry. Only then
// does the absence of a correction say there is none: a source that did
// not answer may have hidden one.
func (r result) Complete() bool { return r.Unchecked == 0 && len(r.Stopped) == 0 }

// entryCheck is the outcome for one entry.
type entryCheck struct {
	file     string
	problems []catgen.Problem
	// fixed is the tag rule written in place of the old one.
	fixed string
	// verified is set when the note about the missing live check was
	// dropped.
	verified bool
	// notes say what a person has to do that the tool could not.
	notes []string
}

func run(ctx context.Context, g *catgen.Generator, dir, out string, now time.Time) (result, error) {
	var res result
	entries, err := catalog.ReadEntries(os.DirFS(dir))
	if err != nil {
		return res, fmt.Errorf("read %s: %w", dir, err)
	}
	// C1 starts with the catalog loading: an invalid entry or a claim two
	// entries share fails here, as it fails the build.
	cat, err := catalog.Build(entries, catalog.OriginBuiltin, nil)
	if err != nil {
		return res, fmt.Errorf("catalog: %w", err)
	}
	lg, stopped := g.WithRateLimits()
	today := now.Format(time.DateOnly)
	var checks []entryCheck
	changed := map[string]string{}
	for _, e := range entries {
		parsed, err := catalog.Parse(e.Name, []byte(e.Data))
		if err != nil {
			return res, err
		}
		app, ok := cat.App(parsed.ID)
		if !ok {
			return res, fmt.Errorf("%s: entry %s is not in the catalog", e.Name, parsed.ID)
		}
		res.Entries++
		c := entryCheck{file: e.Name, problems: lg.CheckReviewed(ctx, app)}
		if data, ok := correct(&c, e.Data, app, today); ok {
			changed[e.Name] = data
		}
		checks = append(checks, c)
	}
	res.Stopped = stopped()

	act := len(res.Stopped) > 0
	for _, c := range checks {
		for _, p := range c.problems {
			if p.Check == catgen.CheckUnchecked {
				res.Unchecked++
			} else {
				res.Problems++
			}
		}
		if len(c.problems) > 0 || len(c.notes) > 0 {
			act = true
		}
	}
	res.Changed = len(changed)
	if res.Changed == 0 && !act {
		return res, nil
	}
	if len(changed) > 0 {
		if err := os.MkdirAll(filepath.Join(out, "apps"), 0o750); err != nil {
			return res, err
		}
	} else if err := os.MkdirAll(out, 0o750); err != nil {
		return res, err
	}
	for name, data := range changed {
		if err := os.WriteFile(filepath.Join(out, "apps", name), []byte(data), 0o600); err != nil {
			return res, err
		}
	}
	if err := os.WriteFile(filepath.Join(out, "report.md"), []byte(report(checks, res.Stopped, today)), 0o600); err != nil {
		return res, err
	}
	res.Reported = true
	return res, nil
}

// unverified is the sentence the entries written without a look at the
// live sources carry in their notes (catalog/apps/postgresql.yaml and
// seven more, 2026-11-12), matched to its final period with the line
// breaks of the folded block anywhere. A sentence worded otherwise is not
// touched.
var unverified = regexp.MustCompile(`\s*Written\s+on\s+\d{4}-\d{2}-\d{2}\s+` + strings.Join(strings.Fields(regexp.QuoteMeta(
	"from the project's public facts without a fresh look at the live sources; the CPE, the advisory "+
		"repository and the tag forms are to be confirmed on the next review of this entry.")), `\s+`))

// correct makes the corrections the checks prove and records what is left
// for a person. It returns the corrected text, if any.
func correct(c *entryCheck, data string, app *catalog.App, today string) (string, bool) {
	out := data
	want := expected{}

	fixes := map[string]bool{}
	for _, p := range c.problems {
		if p.Fix != nil && p.Fix.Tag != "" {
			fixes[p.Fix.Tag] = true
		}
	}
	switch {
	case len(fixes) > 1:
		c.notes = append(c.notes, "the images' tags fit different templates; the rule needs a person")
	case len(fixes) == 1:
		var fix string
		for f := range fixes {
			fix = f
		}
		if s, err := setTagRule(out, fix); err != nil {
			c.notes = append(c.notes, "the proposed tag rule is not written: "+err.Error())
		} else {
			out, c.fixed, want.tag = s, fix, &fix
		}
	}

	if note := app.Advisories.Notes; unverified.MatchString(note) {
		switch {
		case len(c.problems) > 0:
			// The note stays until every check passes.
		case !tagsChecked(app):
			c.notes = append(c.notes, "every check that ran passed, but with no GitHub repository to compare the tags with "+
				"the tag forms were not checked; the note about the missing live check stays until a person confirms them")
		default:
			s, notes, err := dropUnverified(out)
			if err == nil {
				s, err = setVerified(s, today)
			}
			if err != nil {
				c.notes = append(c.notes, "every check passed, but the entry is not marked verified: "+err.Error())
				break
			}
			out, c.verified, want.notes, want.verified = s, true, &notes, &today
		}
	}

	if out == data {
		return "", false
	}
	if err := want.holds(data, out); err != nil {
		c.notes = append(c.notes, "the correction is not written: "+err.Error())
		c.fixed, c.verified = "", false
		return "", false
	}
	return out, true
}

// tagsChecked reports that CheckReviewed looks at the entry's tags (C3,
// C4): it needs a GitHub repository, an image and a tag rule.
func tagsChecked(app *catalog.App) bool {
	if len(catgen.ReviewedRepos(app)) == 0 || len(app.Images) == 0 {
		return false
	}
	for _, s := range app.Version.Sources {
		if s.TagRegexp() != nil {
			return true
		}
	}
	return false
}

// expected is what a corrected entry reads differently; everything else
// must decode as before.
type expected struct{ tag, notes, verified *string }

func (w expected) holds(before, after string) error {
	app, err := catalog.Parse("corrected", []byte(after))
	if err != nil {
		return err
	}
	if w.tag != nil && ruleText(app) != *w.tag {
		return fmt.Errorf("the rule reads %q", ruleText(app))
	}
	if w.notes != nil && app.Advisories.Notes != *w.notes {
		return fmt.Errorf("the notes read %q", app.Advisories.Notes)
	}
	if w.verified != nil && app.Verified != *w.verified {
		return fmt.Errorf("verified reads %q", app.Verified)
	}
	var a, b any
	if err := yaml.Unmarshal([]byte(before), &a); err != nil {
		return err
	}
	if err := yaml.Unmarshal([]byte(after), &b); err != nil {
		return err
	}
	for _, doc := range []any{a, b} {
		m, _ := doc.(map[string]any)
		delete(m, "verified")
		if adv, ok := m["advisories"].(map[string]any); ok {
			delete(adv, "notes")
		}
		if v, ok := m["version"].(map[string]any); ok {
			if srcs, ok := v["sources"].([]any); ok {
				for _, s := range srcs {
					if sm, ok := s.(map[string]any); ok {
						delete(sm, "tag")
					}
				}
			}
		}
	}
	if !reflect.DeepEqual(a, b) {
		return errors.New("more than the rule, the notes and the verified date changed")
	}
	return nil
}

func ruleText(app *catalog.App) string {
	for _, s := range app.Version.Sources {
		if s.Tag != "" {
			return s.Tag
		}
	}
	return ""
}

// document parses an entry's text for the positions of its values.
func document(data string) (*yaml.Node, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(data), &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("the entry is not one mapping")
	}
	return root.Content[0], nil
}

func value(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// replaceScalar puts text in place of the one-line scalar n, keeping what
// precedes it on the line and its comment.
func replaceScalar(data string, n *yaml.Node, text string) (string, error) {
	lines := strings.Split(data, "\n")
	i, col := n.Line-1, n.Column-1
	if i < 0 || i >= len(lines) || col < 0 || col > len(lines[i]) || !ascii(lines[i][:col]) {
		return "", errors.New("the value is not where the parser put it")
	}
	rest := lines[i][col:]
	var v string
	if err := yaml.Unmarshal([]byte(rest), &v); err != nil || v != n.Value {
		return "", errors.New("the value spans more than its line")
	}
	// What follows the value (the spacing and a line comment) stays.
	suffix := ""
	if n.LineComment != "" {
		at := strings.LastIndex(rest, n.LineComment)
		if at < 0 {
			return "", errors.New("the line comment is not where the parser put it")
		}
		suffix = rest[len(strings.TrimRight(rest[:at], " \t")):]
	}
	line := lines[i][:col] + text + suffix
	lines[i] = line
	return strings.Join(lines, "\n"), nil
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// setTagRule replaces the entry's one tag rule.
func setTagRule(data, rule string) (string, error) {
	doc, err := document(data)
	if err != nil {
		return "", err
	}
	var tag *yaml.Node
	if srcs := value(value(doc, "version"), "sources"); srcs != nil && srcs.Kind == yaml.SequenceNode {
		for _, s := range srcs.Content {
			if t := value(s, "tag"); t != nil {
				if tag != nil {
					return "", errors.New("the entry has more than one tag rule")
				}
				tag = t
			}
		}
	}
	if tag == nil {
		return "", errors.New("the entry has no tag rule to replace; add it by hand")
	}
	return replaceScalar(data, tag, "'"+strings.ReplaceAll(rule, "'", "''")+"'")
}

// setVerified sets the verified date.
func setVerified(data, day string) (string, error) {
	doc, err := document(data)
	if err != nil {
		return "", err
	}
	v := value(doc, "verified")
	if v == nil || v.Kind != yaml.ScalarNode {
		return "", errors.New("the entry has no verified date")
	}
	return replaceScalar(data, v, day)
}

// dropUnverified removes the note about the missing live check from the
// folded notes. The lines before the one the sentence starts on stay as
// they are; the rest is wrapped again at the block's indentation. It
// returns the text and the notes as they now read.
func dropUnverified(data string) (string, string, error) {
	doc, err := document(data)
	if err != nil {
		return "", "", err
	}
	n := value(value(doc, "advisories"), "notes")
	if n == nil || n.Kind != yaml.ScalarNode || n.Style != yaml.FoldedStyle {
		return "", "", errors.New("the notes are not a folded block (>-)")
	}
	loc := unverified.FindStringIndex(n.Value)
	if loc == nil {
		return "", "", errors.New("the notes do not carry the sentence")
	}
	notes := strings.TrimRight(n.Value[:loc[0]]+n.Value[loc[1]:], " ")
	if notes == "" {
		return "", "", errors.New("the notes would be empty")
	}

	// The block's lines: those after the indicator with its indentation.
	lines := strings.Split(data, "\n")
	start := n.Line // the line after the indicator, 0-based
	if start >= len(lines) {
		return "", "", errors.New("the notes have no lines")
	}
	indent := lines[start][:len(lines[start])-len(strings.TrimLeft(lines[start], " "))]
	if indent == "" {
		return "", "", errors.New("the notes have no lines")
	}
	end := start
	var offsets []int
	var joined strings.Builder
	for end < len(lines) && strings.HasPrefix(lines[end], indent) && strings.TrimSpace(lines[end]) != "" {
		if end > start {
			joined.WriteByte(' ')
		}
		offsets = append(offsets, joined.Len())
		joined.WriteString(strings.TrimPrefix(lines[end], indent))
		end++
	}
	// One paragraph of plain lines folds to the lines joined by spaces;
	// anything else (paragraphs, more indented lines) is left to a person.
	if joined.String() != n.Value {
		return "", "", errors.New("the notes are not one plain paragraph")
	}
	k := 0
	for k+1 < len(offsets) && offsets[k+1] <= loc[0] {
		k++
	}
	tail := strings.TrimRight(n.Value[offsets[k]:loc[0]]+n.Value[loc[1]:], " ")
	var block []string
	if tail != "" {
		block = wrap(tail, indent, lineWidth)
	}
	out := append(append(append([]string(nil), lines[:start+k]...), block...), lines[end:]...)
	return strings.Join(out, "\n"), notes, nil
}

// wrap breaks text at spaces into lines of at most width columns with the
// given indentation; a word longer than that gets a line of its own.
func wrap(text, indent string, width int) []string {
	var lines []string
	cur := ""
	for _, w := range strings.Split(text, " ") {
		switch {
		case cur == "":
			cur = w
		case len(indent)+len(cur)+1+len(w) > width:
			lines = append(lines, indent+cur)
			cur = w
		default:
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, indent+cur)
	}
	return lines
}

// report is the body of the pull request. Details come from registries,
// GitHub and NVD and are set as code, so nothing in them renders as a
// mention, a link or markup.
func report(checks []entryCheck, stopped []string, today string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Weekly check of the reviewed catalog entries in `catalog/apps` (checks C1, C3, C4 and C5 of ADR 0040), %s.\n\n", today)
	b.WriteString("Opened by the workflow `catalog-check`; it is never merged automatically. " +
		"Check each change against the live sources before merging.\n")

	var fixed, open, person, unchecked []string
	for _, c := range checks {
		name := code(c.file)
		if c.fixed != "" {
			fixed = append(fixed, fmt.Sprintf("- %s: tag rule replaced by the template %s.", name, code(c.fixed)))
		}
		if c.verified {
			fixed = append(fixed, fmt.Sprintf("- %s: every check passed; the note about the missing live check is removed and `verified` is %s.", name, today))
		}
		for _, p := range c.problems {
			line := fmt.Sprintf("- %s %s: %s", name, p.Check, code(p.Detail))
			if p.Fix != nil && p.Fix.Tag != "" && p.Fix.Tag != c.fixed {
				line += " Proposed rule: " + code(p.Fix.Tag)
			}
			if p.Check == catgen.CheckUnchecked {
				unchecked = append(unchecked, line)
			} else {
				open = append(open, line)
			}
		}
		for _, n := range c.notes {
			person = append(person, fmt.Sprintf("- %s: %s", name, n))
		}
	}
	section := func(title, intro string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n## %s\n\n", title)
		if intro != "" {
			b.WriteString(intro + "\n\n")
		}
		b.WriteString(strings.Join(lines, "\n") + "\n")
	}
	section("Corrections in this pull request", "", fixed)
	section("Problems", "Checks the entries fail. Where a correction above covers one, it is listed here as well.", open)
	section("For a person", "", person)
	if len(stopped) > 0 {
		unchecked = append([]string{fmt.Sprintf("- Sources not asked again after a rate limit: %s.", strings.Join(stopped, ", "))}, unchecked...)
	}
	section("Not checked this week", "A source did not answer; these entries are checked again next week.", unchecked)

	s := b.String()
	if len(s) > maxReport {
		cut := strings.LastIndexByte(s[:maxReport], '\n')
		s = s[:cut+1] + "\n(Cut here: the whole report is the artifact `catalog-check` of the workflow run.)\n"
	}
	return s
}

// code sets s as inline code: one line, without backticks.
func code(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return "`" + strings.ReplaceAll(s, "`", "'") + "`"
}
