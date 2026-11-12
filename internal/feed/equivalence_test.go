// SPDX-License-Identifier: Apache-2.0

package feed_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pipeline"
	"github.com/bifrost0x/varde/internal/store"
)

const entry = `id: immich
name: Immich
homepage: https://immich.app
images: [{match: ghcr.io/immich-app/immich-server}]
version: {scheme: semver}
advisories: {coverage: full, github_repos: [immich-app/immich]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`

// TestFeedModeMatchesDirectMode is the acceptance check of feed mode: the same
// advisory data, once stored by a direct source and once delivered as a
// signed feed over HTTPS, yields the same findings and priorities.
func TestFeedModeMatchesDirectMode(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	entries := []catalog.Entry{{Name: "immich.yaml", Data: entry}}
	cat, err := catalog.Build(entries, catalog.OriginBuiltin, nil)
	if err != nil {
		t.Fatal(err)
	}
	ranges, _, err := advisory.ParseGitHubRange("< 1.121.0", "1.121.0")
	if err != nil {
		t.Fatal(err)
	}
	vulns := []store.AdvisoryRecord{
		{AppID: "immich", CVSS: 9.1, SeverityLabel: "critical", Vuln: advisory.Vulnerability{SchemaVersion: "1.6.0", ID: "GHSA-aaaa-bbbb-cccc",
			Aliases: []string{"CVE-2026-1001"}, Modified: now, Affected: []advisory.Affected{{Package: advisory.Package{Name: "immich"}, Ranges: ranges}}}},
		{AppID: "immich", CVSS: 5.3, SeverityLabel: "medium", Vuln: advisory.Vulnerability{SchemaVersion: "1.6.0", ID: "GHSA-dddd-eeee-ffff",
			Aliases: []string{"CVE-2026-1002"}, Modified: now, Affected: []advisory.Affected{{Package: advisory.Package{Name: "immich"}, Ranges: ranges}}}},
	}
	kev := []store.KEVEntry{{CVE: "CVE-2026-1001", DateAdded: "2026-11-01"}}
	epss := []store.EPSSEntry{{CVE: "CVE-2026-1002", Score: 0.4, Percentile: 0.97, Date: "2026-11-08"}}

	analyse := func(t *testing.T, st *store.Store, live *catalog.Catalog) []string {
		t.Helper()
		if err := st.UpsertHost(ctx, inventory.Host{ID: "local", Name: "n", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
			{Kind: inventory.KindContainer, RuntimeID: "a", Name: "immich", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}},
			{Kind: inventory.KindContainer, RuntimeID: "b", Name: "immich-new", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.122.0"}},
		}, now); err != nil {
			t.Fatal(err)
		}
		if _, err := pipeline.New(live, st, slog.New(slog.DiscardHandler), pipeline.Options{}).Run(ctx); err != nil {
			t.Fatal(err)
		}
		fs, err := st.Findings(ctx, store.FindingFilter{})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range fs {
			out = append(out, fmt.Sprintf("%s %s %s %s %s %s", f.WorkloadID, f.AdvisoryID, f.MatchState, f.FixedIn, f.Priority, f.Exposure))
		}
		sort.Strings(out)
		return out
	}

	// Direct mode.
	direct, err := store.Open(ctx, filepath.Join(t.TempDir(), "direct.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = direct.Close() }()
	if err := direct.ReplaceAdvisories(ctx, "immich", "github:immich-app/immich", append([]store.AdvisoryRecord(nil), vulns...), now); err != nil {
		t.Fatal(err)
	}
	_ = direct.ReplaceKEV(ctx, kev)
	_ = direct.UpsertEPSS(ctx, epss)
	want := analyse(t, direct, cat)
	if len(want) != 2 {
		t.Fatalf("direct findings: %v", want)
	}

	// Feed mode: publish the same data, serve it over HTTPS, apply it.
	rootKey, _ := feed.NewKey()
	feedKey, _ := feed.NewKey()
	pubDir := t.TempDir()
	rootData, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: now.Add(time.Hour * 24), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{feedKey.Public().(ed25519.PublicKey)},
		RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := feed.WriteRoot(pubDir, 1, rootData); err != nil {
		t.Fatal(err)
	}
	var lines []feed.AdvisoryLine
	for _, v := range vulns {
		lines = append(lines, feed.AdvisoryLine{AppID: v.AppID, CVSS: v.CVSS, Severity: v.SeverityLabel, OSV: v.Vuln})
	}
	if _, err := feed.WriteSnapshot(pubDir, feed.Snapshot{Sequence: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Catalog: entries,
		Advisories: lines, KEV: []feed.KEVLine{{CVE: kev[0].CVE, DateAdded: kev[0].DateAdded}},
		EPSS: []feed.EPSSLine{{CVE: epss[0].CVE, Score: epss[0].Score, Percentile: epss[0].Percentile, Date: epss[0].Date}}}, feedKey); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.FileServer(http.Dir(pubDir)))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	fetch, err := feed.NewFetcher(srv.URL, httpx.New(httpx.Options{RootCAs: pool}), nil)
	if err != nil {
		t.Fatal(err)
	}

	fdb, err := store.Open(ctx, filepath.Join(t.TempDir(), "feed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fdb.Close() }()
	empty, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	live := catalog.NewLive(empty)
	client := &feed.Client{Mirrors: []feed.Fetcher{fetch}, Dir: filepath.Join(t.TempDir(), "feed"), Store: fdb,
		Catalog: live, Log: slog.New(slog.DiscardHandler), AllowDevelopment: true}
	if _, err := client.Init(rootData); err != nil {
		t.Fatal(err)
	}
	if res, err := client.Update(ctx); err != nil || !res.Applied {
		t.Fatalf("feed update: %+v %v", res, err)
	}
	got := analyse(t, fdb, live.Current())
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("feed mode differs from direct mode\nfeed:   %v\ndirect: %v", got, want)
	}
}
