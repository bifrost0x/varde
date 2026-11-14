// SPDX-License-Identifier: Apache-2.0

package releases

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

// fakeLister answers tag lists by repository and counts the requests.
type fakeLister struct {
	tags  map[string][]string
	cut   map[string]bool
	fail  map[string]bool
	asked []string
}

func (f *fakeLister) AllTags(_ context.Context, repository string) ([]string, bool, error) {
	f.asked = append(f.asked, repository)
	if f.fail[repository] {
		return nil, false, errors.New("registry refused")
	}
	return f.tags[repository], !f.cut[repository], nil
}

func newTagReader(t *testing.T, l *fakeLister) (*TagReader, *time.Time) {
	t.Helper()
	s, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "builder.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := now0
	return &TagReader{Store: s, Registry: l, Now: func() time.Time { return now }}, &now
}

func tagsOf(lines []feed.TagLine, image string) string {
	for _, l := range lines {
		if l.Image == image {
			return strings.Join(l.Tags, ",")
		}
	}
	return "-"
}

// Every image with a tag rule gets its release tags, newest first, without
// floating tags; an app that never reads a version from a tag is not
// asked, and an image without a release tag ships no line.
func TestTagListsOfTheCatalog(t *testing.T) {
	const a, b, c, d = regHost + "/x/a", regHost + "/x/b", regHost + "/x/c", regHost + "/x/d"
	l := &fakeLister{tags: map[string][]string{
		a: {"latest", "1.2.0", "v1.10.0", "1.9.0", "main", "sha-abc1234"},
		b: {"2.0.0", "1.0.0"},
		d: {"latest", "edge"},
	}}
	cat := newCatalog(t, []catalog.Entry{reviewedEntry("a", a), labelEntry("c", c), reviewedEntry("d", d)}, []catalog.Entry{generatedEntry("b", b)})
	r, _ := newTagReader(t, l)
	lines, st, err := r.Run(t.Context(), cat, Priority(cat, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := tagsOf(lines, a); got != "v1.10.0,1.9.0,1.2.0" {
		t.Errorf("a: %s", got)
	}
	if got := tagsOf(lines, b); got != "2.0.0,1.0.0" {
		t.Errorf("b: %s", got)
	}
	if len(lines) != 2 || st.Images != 3 || st.Read != 3 || st.NoRelease != 1 {
		t.Errorf("lines=%d stats=%+v", len(lines), st)
	}
	for _, asked := range l.asked {
		if asked == c {
			t.Error("an app without a tag rule was asked for")
		}
	}
	for _, line := range lines {
		if err := line.Validate(); err != nil {
			t.Error(err)
		}
	}
}

// A list stands for a day; one that cannot be read again, or is cut
// short, ships as stored until it is too old, and the deadline leaves the
// rest to a later build.
func TestTagListsAreKeptBetweenBuilds(t *testing.T) {
	const a, b = regHost + "/x/a", regHost + "/x/b"
	l := &fakeLister{tags: map[string][]string{a: {"1.0.0"}, b: {"1.0.0"}}, fail: map[string]bool{}, cut: map[string]bool{}}
	cat := newCatalog(t, []catalog.Entry{reviewedEntry("a", a), reviewedEntry("b", b)}, nil)
	r, now := newTagReader(t, l)
	run := func() ([]feed.TagLine, TagStats) {
		t.Helper()
		lines, st, err := r.Run(t.Context(), cat, Priority(cat, nil))
		if err != nil {
			t.Fatal(err)
		}
		return lines, st
	}
	run()

	// An hour later nothing is asked.
	*now = now.Add(time.Hour)
	l.asked = nil
	if lines, st := run(); len(l.asked) != 0 || st.Fresh != 2 || len(lines) != 2 {
		t.Fatalf("asked %v, stats %+v", l.asked, st)
	}

	// The next day a has a new release; b's registry fails, then cuts
	// its list short: b ships as read the day before.
	*now = now.Add(24 * time.Hour)
	l.tags[a] = []string{"1.0.0", "1.1.0"}
	l.fail[b] = true
	lines, st := run()
	if tagsOf(lines, a) != "1.1.0,1.0.0" || tagsOf(lines, b) != "1.0.0" || st.Read != 1 || st.Failed != 1 || st.Stale != 1 {
		t.Fatalf("a=%s b=%s stats=%+v", tagsOf(lines, a), tagsOf(lines, b), st)
	}
	l.fail[b], l.cut[b] = false, true
	l.tags[b] = []string{"1.0.0", "0.9.0"}
	*now = now.Add(24 * time.Hour)
	if lines, _ := run(); tagsOf(lines, b) != "1.0.0" {
		t.Fatalf("a list cut short replaced the stored one: %s", tagsOf(lines, b))
	}

	// Past the deadline nothing starts.
	*now = now.Add(24 * time.Hour)
	r.Deadline = now.Add(-time.Minute)
	l.asked = nil
	if lines, st := run(); len(l.asked) != 0 || st.NotStarted != 2 || len(lines) != 2 {
		t.Fatalf("asked %v, stats %+v, %d lines", l.asked, st, len(lines))
	}

	// A list no build could read for two weeks is no longer shipped.
	*now = now.Add(DefaultTagsKeep)
	if lines, _ := run(); len(lines) != 0 {
		t.Fatalf("old lists still ship: %+v", lines)
	}
}
