// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/advisory/sources"
	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

const widgetEntry = `id: widget
name: Widget
homepage: https://widget.example
images: [{match: ghcr.io/acme/widget}]
version: {scheme: semver}
advisories: {coverage: full, github_repos: [Acme/Widget]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`

const testIndex = "docker.io/other/tool\tgithub.com/other/tool\thub,readme\nghcr.io/acme/widget\tgithub.com/acme/widget\tghcr,readme\n"

// upstream stands in for GitHub, CISA and FIRST.
type upstream struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	// advisories per "owner/name"; status overrides the answer.
	advisories map[string][]string
	status     map[string]int
	// limitAt refuses the n-th advisory request (1-based) once, naming a
	// reset this far ahead.
	limitAt    int
	limitReset time.Duration
	// lowWater answers this many advisory requests with a nearly used-up
	// quota (remaining 2) before the limit is refused.
	lowWater    int
	requests    map[string]int
	conditional int
	kev         int
	epssAsked   []string
	now         func() time.Time
}

func newUpstream(t *testing.T, now func() time.Time) *upstream {
	t.Helper()
	u := &upstream{t: t, advisories: map[string][]string{}, status: map[string]int{}, requests: map[string]int{}, now: now}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) client() *httpx.Client {
	pool := x509.NewCertPool()
	pool.AddCert(u.srv.Certificate())
	return httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second})
}

func (u *upstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case r.URL.Path == "/kev":
		u.kev++
		type v struct {
			CVEID      string `json:"cveID"`
			DateAdded  string `json:"dateAdded"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		}
		var doc struct {
			Vulnerabilities []v `json:"vulnerabilities"`
		}
		for i := range 120 {
			doc.Vulnerabilities = append(doc.Vulnerabilities, v{CVEID: fmt.Sprintf("CVE-2025-%04d", i), DateAdded: "2025-06-01", Ransomware: "Unknown"})
		}
		_ = json.NewEncoder(w).Encode(doc)
	case r.URL.Path == "/epss":
		type d struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		}
		var doc struct {
			Data []d `json:"data"`
		}
		for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
			u.epssAsked = append(u.epssAsked, cve)
			doc.Data = append(doc.Data, d{CVE: cve, EPSS: "0.42", Percentile: "0.97", Date: "2026-11-10"})
		}
		_ = json.NewEncoder(w).Encode(doc)
	case strings.HasPrefix(r.URL.Path, "/repos/"):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/repos/"), "/")
		repo := parts[0] + "/" + parts[1]
		n := 0
		for _, c := range u.requests {
			n += c
		}
		if u.limitAt > 0 && n+1 == u.limitAt {
			u.limitAt = 0
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(u.now().Add(u.limitReset).Unix(), 10))
			http.Error(w, "rate limit", http.StatusForbidden)
			return
		}
		u.requests[repo]++
		if s := u.status[repo]; s != 0 {
			http.Error(w, "nope", s)
			return
		}
		etag := fmt.Sprintf(`"%d"`, len(u.advisories[repo]))
		if r.Header.Get("If-None-Match") == etag {
			u.conditional++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		type item struct {
			GHSAID      string    `json:"ghsa_id"`
			CVEID       *string   `json:"cve_id"`
			Summary     string    `json:"summary"`
			Severity    string    `json:"severity"`
			PublishedAt time.Time `json:"published_at"`
			UpdatedAt   time.Time `json:"updated_at"`
		}
		items := []item{}
		for _, id := range u.advisories[repo] {
			cve := "CVE-2026-" + id[len(id)-4:]
			items = append(items, item{GHSAID: id, CVEID: &cve, Summary: "test", Severity: "high",
				PublishedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)})
		}
		w.Header().Set("ETag", etag)
		remaining := "900"
		if u.lowWater > 0 {
			u.lowWater--
			remaining = "2"
			if u.lowWater == 0 {
				u.limitAt = n + 2 // the next request is refused, with the reset
			}
		}
		w.Header().Set("X-RateLimit-Remaining", remaining)
		_ = json.NewEncoder(w).Encode(items)
	default:
		http.NotFound(w, r)
	}
}

type fixture struct {
	t     *testing.T
	st    *store.Store
	up    *upstream
	cat   *catalog.Catalog
	index *applists.Table
	repos []Repo
	now   time.Time
	slept []time.Duration
	opts  Options
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, now: time.Date(2026, 11, 11, 2, 17, 0, 0, time.UTC)}
	var err error
	if f.st, err = store.Open(context.Background(), filepath.Join(t.TempDir(), "builder.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.st.Close() })
	if f.cat, err = catalog.Load(fstest.MapFS{"widget.yaml": {Data: []byte(widgetEntry)}}, nil); err != nil {
		t.Fatal(err)
	}
	if f.index, err = applists.Unmarshal([]byte(testIndex)); err != nil {
		t.Fatal(err)
	}
	if f.repos, err = Repos(f.cat, f.index); err != nil {
		t.Fatal(err)
	}
	f.up = newUpstream(t, func() time.Time { return f.now })
	f.up.advisories["acme/widget"] = []string{"GHSA-aaaa-aaaa-0001", "GHSA-aaaa-aaaa-0002"}
	f.up.advisories["other/tool"] = []string{"GHSA-bbbb-bbbb-0003"}
	f.opts = Options{Store: f.st, HTTP: f.up.client(), Token: "t", GitHubURL: f.up.srv.URL, KEVURL: f.up.srv.URL + "/kev", EPSSURL: f.up.srv.URL + "/epss",
		Now: func() time.Time { return f.now },
		Sleep: func(_ context.Context, d time.Duration) error {
			f.slept = append(f.slept, d)
			f.now = f.now.Add(d)
			return nil
		}}
	return f
}

func (f *fixture) stored(appID string) int {
	f.t.Helper()
	recs, err := f.st.Advisories(context.Background(), appID)
	if err != nil {
		f.t.Fatal(err)
	}
	return len(recs)
}

func TestReposUnion(t *testing.T) {
	f := newFixture(t)
	if len(f.repos) != 2 || f.repos[0].Name != "acme/widget" || f.repos[1].Name != "other/tool" {
		t.Fatalf("repos = %+v", f.repos)
	}
	if got := f.repos[0]; len(got.CatalogIDs) != 1 || got.CatalogIDs[0] != "widget" || got.App.ID != "gh-acme-widget" {
		t.Fatalf("acme/widget = %+v (app %s)", got, got.App.ID)
	}
	if got := f.repos[1]; len(got.CatalogIDs) != 0 || got.App.ID != "gh-other-tool" {
		t.Fatalf("other/tool = %+v (app %s)", got, got.App.ID)
	}
}

func TestCollectOneRequestPerRepository(t *testing.T) {
	f := newFixture(t)
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Repos != 2 || stats.Failed != 0 || stats.Requests != 2 || stats.Waits != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if f.up.requests["acme/widget"] != 1 || f.up.requests["other/tool"] != 1 {
		t.Fatalf("requests = %v", f.up.requests)
	}
	if f.stored("gh-acme-widget") != 2 || f.stored("gh-other-tool") != 1 {
		t.Fatalf("stored: %d, %d", f.stored("gh-acme-widget"), f.stored("gh-other-tool"))
	}
}

func TestCollectConditional(t *testing.T) {
	f := newFixture(t)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(24 * time.Hour)
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if f.up.conditional != 2 || stats.Requests != 2 {
		t.Fatalf("conditional answers = %d, requests = %d", f.up.conditional, stats.Requests)
	}
	if f.stored("gh-acme-widget") != 2 {
		t.Fatal("advisories lost by an unchanged answer")
	}
}

func TestCollectFailuresAreCounted(t *testing.T) {
	f := newFixture(t)
	f.up.status["acme/widget"] = http.StatusInternalServerError
	f.up.status["other/tool"] = http.StatusNotFound
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	// A repository that does not exist has no advisories; that is an
	// answer, not a failure.
	if stats.Failed != 1 {
		t.Fatalf("failed = %d, want 1", stats.Failed)
	}
	// The failure is repeated with the next build and clears.
	delete(f.up.status, "acme/widget")
	f.now = f.now.Add(24 * time.Hour)
	if stats, err = Collect(context.Background(), f.repos, f.opts); err != nil || stats.Failed != 0 || f.stored("gh-acme-widget") != 2 {
		t.Fatalf("after recovery: %+v, %v, stored %d", stats, err, f.stored("gh-acme-widget"))
	}
}

func TestCollectWaitsForTheRateLimit(t *testing.T) {
	f := newFixture(t)
	f.up.limitAt, f.up.limitReset = 2, 40*time.Minute
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Waits != 1 || stats.Failed != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	var longest time.Duration
	for _, d := range f.slept {
		longest = max(longest, d)
	}
	if longest < 35*time.Minute || longest > 45*time.Minute {
		t.Fatalf("waited %s for a reset 40 minutes ahead (sleeps: %v)", longest, f.slept)
	}
	if f.stored("gh-acme-widget") != 2 || f.stored("gh-other-tool") != 1 {
		t.Fatal("not every repository was read after the wait")
	}
}

func TestCollectGivesUpAfterMaxWait(t *testing.T) {
	f := newFixture(t)
	f.up.limitAt, f.up.limitReset = 2, 40*time.Minute
	f.opts.MaxWait = 10 * time.Minute
	_, err := Collect(context.Background(), f.repos, f.opts)
	if !errors.Is(err, sources.ErrRateLimited) || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestCollectEnrichment(t *testing.T) {
	f := newFixture(t)
	if _, err := Collect(context.Background(), f.repos, f.opts); err != nil {
		t.Fatal(err)
	}
	kev, err := f.st.KEV(context.Background())
	if err != nil || len(kev) != 120 {
		t.Fatalf("kev = %d, %v", len(kev), err)
	}
	if len(f.up.epssAsked) != 3 {
		t.Fatalf("EPSS asked about %v, want the 3 CVEs of the stored advisories", f.up.epssAsked)
	}
	scores, err := f.st.EPSS(context.Background())
	if err != nil || scores["CVE-2026-0001"] != 0.42 {
		t.Fatalf("scores = %v, %v", scores, err)
	}
}

// GitHub's quota runs low before it runs out: the source stops early to
// leave a rest, without a reset time. The builder goes on until GitHub
// names the reset, waits, and still reads every repository.
func TestCollectLowWaterThenLimit(t *testing.T) {
	f := newFixture(t)
	f.up.advisories["third/one"] = []string{"GHSA-cccc-cccc-0005"}
	table, err := applists.Unmarshal([]byte(testIndex + "ghcr.io/third/one\tgithub.com/third/one\tghcr,readme\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f.repos, err = Repos(f.cat, table); err != nil {
		t.Fatal(err)
	}
	f.up.lowWater, f.up.limitReset = 1, 30*time.Minute
	stats, err := Collect(context.Background(), f.repos, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 0 || stats.Waits != 1 {
		t.Fatalf("stats = %+v (sleeps %v)", stats, f.slept)
	}
	for _, id := range []string{"gh-acme-widget", "gh-other-tool", "gh-third-one"} {
		if f.stored(id) == 0 {
			t.Errorf("%s was not read", id)
		}
	}
}
