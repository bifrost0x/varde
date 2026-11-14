// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

func (f *fixture) snapshot() feed.Snapshot {
	f.t.Helper()
	snap, err := Snapshot(context.Background(), f.st, []catalog.Entry{{Name: "widget.yaml", Data: widgetEntry}}, f.index, f.repos, nil, false, f.now, 7*24*time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	return snap
}

func TestSnapshotBothIDs(t *testing.T) {
	f := newFixture(t)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	snap := f.snapshot()
	per := map[string]int{}
	for _, a := range snap.Advisories {
		per[a.AppID]++
	}
	if per["widget"] != 2 || per["gh-acme-widget"] != 2 || per["gh-other-tool"] != 1 || len(per) != 3 {
		t.Fatalf("advisories per app = %v", per)
	}
	if snap.Channel != feed.ChannelPackage || snap.Sequence != f.now.Unix() || !snap.ExpiresAt.Equal(f.now.Add(7*24*time.Hour)) {
		t.Fatalf("snapshot header: %+v", snap)
	}
	if len(snap.KEV) != 120 || snap.KEV[0].DateAdded != "2025-06-01" || len(snap.EPSS) != 3 {
		t.Fatalf("kev %d, epss %d", len(snap.KEV), len(snap.EPSS))
	}
	if !bytes.Equal(snap.Index, []byte(testIndex)) {
		t.Fatalf("index = %q", snap.Index)
	}
	// A score of a CVE that left the package stays behind.
	if err := f.st.UpsertEPSS(context.Background(), []store.EPSSEntry{{CVE: "CVE-2020-0001", Score: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if got := f.snapshot(); len(got.EPSS) != 3 {
		t.Fatalf("EPSS of a CVE outside the package was published: %d", len(got.EPSS))
	}
}

func TestSnapshotDeterministicAndVerifies(t *testing.T) {
	f := newFixture(t)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	rootKey, _ := feed.NewKey()
	feedKey, _ := feed.NewKey()
	root, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: f.now.Add(365 * 24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{feedKey.Public().(ed25519.PublicKey)},
		RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	var manifests [][]byte
	var dir string
	for range 2 {
		dir = t.TempDir()
		if err := feed.WriteRoot(dir, 1, root); err != nil {
			t.Fatal(err)
		}
		if _, err := feed.WriteSnapshot(dir, f.snapshot(), feedKey); err != nil {
			t.Fatal(err)
		}
		m, err := os.ReadFile(filepath.Join(dir, "v1", "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, m)
	}
	if !bytes.Equal(manifests[0], manifests[1]) {
		t.Fatal("two builds of the same store and clock differ")
	}
	// The real client installs it on the package channel.
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	fetch, err := feed.NewFetcher("file://"+filepath.ToSlash(dir), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	client := &feed.Client{Dir: filepath.Join(t.TempDir(), "feed"), Store: st, Catalog: catalog.NewLive(base), Log: slog.New(slog.DiscardHandler),
		Now: func() time.Time { return f.now }, AllowDevelopment: true,
		Pick: func() feed.Channel { return feed.Channel{Name: feed.ChannelPackage, Mirrors: []feed.Fetcher{fetch}} }}
	if _, err := client.Init(root); err != nil {
		t.Fatal(err)
	}
	res, err := client.Update(context.Background())
	if err != nil || !res.Applied {
		t.Fatalf("client: %+v, %v", res, err)
	}
	if _, ok := client.Index().Lookup("ghcr.io/acme/widget"); !ok {
		t.Fatal("index not in the installed package")
	}
	if recs, _ := st.Advisories(context.Background(), "widget"); len(recs) != 2 {
		t.Fatalf("advisories of the catalog app = %d", len(recs))
	}
}

func TestGuard(t *testing.T) {
	prev := Counts{Sequence: 100, Advisories: 100, KEV: 1000, EPSS: 500, Index: 200}
	ok := Counts{Sequence: 200, Advisories: 100, KEV: 1000, EPSS: 500, Index: 200}
	with := func(change func(*Counts)) Counts { c := ok; change(&c); return c }
	for _, tc := range []struct {
		name    string
		stats   Stats
		have    bool
		cur     Counts
		force   bool
		refused bool
	}{
		{"first build, no baseline", Stats{Repos: 100}, false, Counts{Sequence: 1}, false, false},
		{"first build, nothing at all", Stats{}, false, Counts{}, false, false},
		{"unchanged", Stats{Repos: 100}, true, ok, false, false},
		{"5 % failed", Stats{Repos: 100, Failed: 5}, true, ok, false, false},
		{"6 % failed", Stats{Repos: 100, Failed: 6}, true, ok, false, true},
		{"6 % failed, forced", Stats{Repos: 100, Failed: 6}, true, ok, true, true},
		{"6 % failed, first build", Stats{Repos: 100, Failed: 6}, false, ok, false, true},
		{"advisories to 90", Stats{Repos: 100}, true, with(func(c *Counts) { c.Advisories = 90 }), false, false},
		{"advisories to 89", Stats{Repos: 100}, true, with(func(c *Counts) { c.Advisories = 89 }), false, true},
		{"advisories to 89, forced", Stats{Repos: 100}, true, with(func(c *Counts) { c.Advisories = 89 }), true, false},
		{"KEV to 899", Stats{Repos: 100}, true, with(func(c *Counts) { c.KEV = 899 }), false, true},
		{"index to 179", Stats{Repos: 100}, true, with(func(c *Counts) { c.Index = 179 }), false, true},
		{"EPSS to 0", Stats{Repos: 100}, true, with(func(c *Counts) { c.EPSS = 0 }), false, false},
		{"sequence not above", Stats{Repos: 100}, true, with(func(c *Counts) { c.Sequence = 100 }), false, true},
		{"sequence not above, forced", Stats{Repos: 100}, true, with(func(c *Counts) { c.Sequence = 100 }), true, true},
	} {
		err := Guard(tc.stats, prev, tc.have, tc.cur, tc.force)
		if (err != nil) != tc.refused || (err != nil && !errors.Is(err, ErrRefused)) {
			t.Errorf("%s: err = %v, want refused = %v", tc.name, err, tc.refused)
		}
	}
}

func TestCountsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, have, err := ReadCounts(dir); err != nil || have {
		t.Fatalf("empty directory: have %v, %v", have, err)
	}
	if _, have, err := ReadCounts(""); err != nil || have {
		t.Fatalf("no directory: have %v, %v", have, err)
	}
	want := Counts{Sequence: 7, Advisories: 3, KEV: 2, EPSS: 1, Index: 9}
	if err := WriteCounts(dir, want); err != nil {
		t.Fatal(err)
	}
	if got, have, err := ReadCounts(dir); err != nil || !have || got != want {
		t.Fatalf("read back %+v, %v, %v", got, have, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stats.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCounts(dir); err == nil {
		t.Fatal("a broken baseline was read")
	}
}

// Records of the second sources ship under the catalog app that names the
// package or the CPE, marked with their origin: not when the repository
// already published the same record, not for a CPE the entry dropped, and
// the NVD's not for an app whose project publishes complete advisories.
func TestSnapshotSecondSources(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := Collect(ctx, f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	base := f.snapshot()
	var published string
	for _, a := range base.Advisories {
		if a.AppID == "widget" {
			published = a.OSV.ID
			break
		}
	}
	if published == "" {
		t.Fatal("fixture has no advisory for widget")
	}
	const cpe, dropped = "cpe:2.3:a:acme:widget", "cpe:2.3:a:acme:old"
	rec := func(source, id string, aliases ...string) store.AdvisoryRecord {
		return store.AdvisoryRecord{AppID: "widget", Source: source, CVSS: 7.5, SeverityLabel: "high",
			Vuln: advisory.Vulnerability{ID: id, Aliases: aliases, Modified: f.now}}
	}
	put := func(source string, recs ...store.AdvisoryRecord) {
		t.Helper()
		if err := f.st.ReplaceAdvisories(ctx, "widget", source, recs, f.now); err != nil {
			t.Fatal(err)
		}
	}
	put("osv", rec("osv", "GO-2026-0001", "CVE-2026-1111"), rec("osv", published))
	put("nvd:"+cpe, rec("nvd:"+cpe, "CVE-2026-2222"), rec("nvd:"+cpe, "GO-2026-0001"))
	put("nvd:"+dropped, rec("nvd:"+dropped, "CVE-2026-3333"))

	app := func(coverage string) *catalog.App {
		return &catalog.App{ID: "widget", Advisories: catalog.Advisories{Coverage: coverage, CPE: []string{cpe},
			OSVPackages: []catalog.OSVPackage{{Ecosystem: "Go", Name: "example.org/widget"}}}}
	}
	snap := func(a *catalog.App) map[string]string {
		t.Helper()
		s, err := Snapshot(ctx, f.st, []catalog.Entry{{Name: "widget.yaml", Data: widgetEntry}}, f.index, f.repos, []*catalog.App{a}, false, f.now, 7*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Advisories) < len(base.Advisories) {
			t.Fatalf("second sources removed advisories: %d < %d", len(s.Advisories), len(base.Advisories))
		}
		origins := map[string]string{}
		for _, l := range s.Advisories {
			if l.AppID != "widget" {
				continue
			}
			if _, twice := origins[l.OSV.ID]; twice {
				t.Fatalf("%s shipped twice under one app", l.OSV.ID)
			}
			origins[l.OSV.ID] = l.OSV.Origin()
		}
		return origins
	}

	got := snap(app(catalog.CoveragePartial))
	want := map[string]string{"GO-2026-0001": "osv", "CVE-2026-2222": "nvd:" + cpe, published: ""}
	for id, origin := range want {
		if o, ok := got[id]; !ok || o != origin {
			t.Errorf("%s: origin %q (shipped %v), want %q", id, o, ok, origin)
		}
	}
	if _, ok := got["CVE-2026-3333"]; ok {
		t.Error("a record of a CPE the entry no longer names was shipped")
	}
	// The stored record keeps its own database_specific.
	recs, err := f.st.Advisories(ctx, "widget")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Vuln.Origin() != "" {
			t.Fatalf("the store's record %s was changed", r.Vuln.ID)
		}
	}

	// For an app with complete advisories only the NVD records ship that
	// give an end to a project advisory which names none.
	var own []store.AdvisoryRecord
	derived, err := f.st.Advisories(ctx, "gh-acme-widget")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range derived {
		if r.Source == "github:acme/widget" {
			own = append(own, r)
		}
	}
	own = append(own, store.AdvisoryRecord{AppID: "gh-acme-widget", Source: "github:acme/widget", CVSS: 7, SeverityLabel: "high",
		Vuln: advisory.Vulnerability{ID: "GHSA-open-0001", Aliases: []string{"CVE-2026-4444"}, Modified: f.now,
			Affected: []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "2.8"}}}}}}}})
	if err := f.st.ReplaceAdvisories(ctx, "gh-acme-widget", "github:acme/widget", own, f.now); err != nil {
		t.Fatal(err)
	}
	closing := rec("nvd:"+cpe, "CVE-2026-4444")
	closing.Vuln.Affected = []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "2.8"}, {Fixed: "6.2.19"}}}}}}
	put("nvd:"+cpe, rec("nvd:"+cpe, "CVE-2026-2222"), closing)

	full := snap(app(catalog.CoverageFull))
	if _, ok := full["CVE-2026-2222"]; ok {
		t.Error("NVD records shipped for an app with complete advisories")
	}
	if full["CVE-2026-4444"] != "nvd:"+cpe {
		t.Errorf("the NVD record that completes an open project advisory was left out: %v", full)
	}
	if full["GO-2026-0001"] != "osv" {
		t.Error("OSV records left out for an app with complete advisories")
	}
}

// A second source that cannot be read does not stop the build.
func TestCollectSecondSourceFailureIsNotFatal(t *testing.T) {
	f := newFixture(t)
	o := f.opts
	o.OSV, o.NVD = true, true
	o.OSVURL, o.NVDURL = o.GitHubURL+"/no-such-osv", o.GitHubURL+"/no-such-nvd"
	o.Apps = []*catalog.App{{ID: "widget", Advisories: catalog.Advisories{Coverage: catalog.CoverageLimited, CPE: []string{"cpe:2.3:a:acme:widget"},
		OSVPackages: []catalog.OSVPackage{{Ecosystem: "Go", Name: "example.org/widget"}}}},
		{ID: "full", Advisories: catalog.Advisories{Coverage: catalog.CoverageFull, CPE: []string{"cpe:2.3:a:acme:full"}}}}
	st, err := Collect(context.Background(), f.repos, o)
	if err != nil {
		t.Fatal(err)
	}
	if st.OSVApps != 1 || st.NVDApps != 2 || st.OSVRequests == 0 || st.NVDRequests == 0 {
		t.Fatalf("stats: %+v", st)
	}
	if got := f.snapshot(); len(got.Advisories) == 0 {
		t.Fatal("the repositories' advisories were lost")
	}
}

// The security fixes named in release notes ship for repositories whose
// advisories are not complete, under every ID of the repository, marked
// with their origin; a note naming a published advisory is left out
// (ADR 0044).
func TestSnapshotReleaseNotes(t *testing.T) {
	f := newFixture(t)
	notes := `[{"tag_name":"v2.0.0","body":"- fixes CVE-2026-0003 and CVE-2026-0042","published_at":"2026-11-01T00:00:00Z"},
		{"tag_name":"v1.9.0","body":"- fix a path traversal","published_at":"2026-10-01T00:00:00Z"}]`
	f.up.releases["other/tool"] = notes
	f.up.releases["acme/widget"] = notes
	f.opts.ReleaseNotes = true
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	// widget's catalog entry has complete advisories: its notes are not read.
	if stats.NotesRepos != 1 || f.up.requests["releases:acme/widget"] != 0 || f.up.requests["releases:other/tool"] != 1 {
		t.Fatalf("notes read: %+v %v", stats, f.up.requests)
	}
	snap, err := Snapshot(context.Background(), f.st, []catalog.Entry{{Name: "widget.yaml", Data: widgetEntry}}, f.index, f.repos, nil, true, f.now, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var notesShipped []feed.AdvisoryLine
	for _, a := range snap.Advisories {
		if a.OSV.Origin() == advisory.OriginRelease {
			notesShipped = append(notesShipped, a)
		}
	}
	// other/tool published GHSA-bbbb-bbbb-0003 with CVE-2026-0003: the
	// note of CVE-2026-0042 and the one without an ID are new.
	aliases := map[string]bool{}
	for _, n := range notesShipped {
		if n.AppID != "gh-other-tool" {
			t.Fatalf("note under %s", n.AppID)
		}
		aliases[strings.Join(n.OSV.Aliases, ",")] = true
	}
	if len(notesShipped) != 2 || !aliases["CVE-2026-0042"] || !aliases[""] {
		t.Fatalf("notes shipped: %+v", notesShipped)
	}
	// Without -release-notes nothing stored earlier ships.
	if snap := f.snapshot(); len(snap.Advisories) != 5 {
		t.Fatalf("advisories without notes: %d", len(snap.Advisories))
	}
}

// A rate limit on the release notes does not stop the build; the summary
// says why the reads stopped.
func TestCollectReleaseNotesLimitIsNotFatal(t *testing.T) {
	f := newFixture(t)
	f.up.notesLimited = true
	f.opts.ReleaseNotes = true
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil || stats.NotesError == "" || stats.Failed != 0 {
		t.Fatalf("stats %+v, err %v", stats, err)
	}
	if f.up.kev != 1 {
		t.Fatal("the enrichment did not run after the notes stopped")
	}
}

// A repository whose release notes fail without a rate limit is counted,
// so the summary does not read as a complete collection.
func TestCollectReleaseNotesFailuresAreCounted(t *testing.T) {
	f := newFixture(t)
	f.up.releases["other/tool"] = "not json"
	f.opts.ReleaseNotes = true
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil || stats.NotesFailed != 1 || stats.NotesError != "" {
		t.Fatalf("stats %+v, err %v", stats, err)
	}
}
