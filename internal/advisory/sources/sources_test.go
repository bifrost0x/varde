// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

type upstream struct {
	srv    *httptest.Server
	client *httpx.Client
	mu     sync.Mutex
	hits   map[string]int
}

func newUpstream(t *testing.T, h func(u *upstream, w http.ResponseWriter, r *http.Request)) *upstream {
	t.Helper()
	u := &upstream{hits: map[string]int{}}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits[r.URL.Path]++
		u.mu.Unlock()
		h(u, w, r)
	}))
	t.Cleanup(u.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(u.srv.Certificate())
	u.client = httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second})
	return u
}

func (u *upstream) count(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[path]
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func deps(u *upstream, s *store.Store, now *time.Time) Deps {
	return Deps{HTTP: u.client, Store: s, Now: func() time.Time { return *now }, Sleep: func(context.Context, time.Duration) error { return nil }}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func appWith(id string, adv catalog.Advisories) *catalog.App {
	return &catalog.App{ID: id, Advisories: adv}
}

func TestGitHubPaginationConditionalAndConversion(t *testing.T) {
	page := fixture(t, "github_immich.json")
	var items []json.RawMessage
	if err := json.Unmarshal(page, &items); err != nil {
		t.Fatal(err)
	}
	u := newUpstream(t, func(u *upstream, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `W/"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("X-RateLimit-Remaining", "50")
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("ETag", `W/"v1"`)
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/immich-app/immich/security-advisories?after=p2>; rel="next"`, u.srv.URL))
			_, _ = w.Write([]byte("[" + string(items[0]) + "," + string(items[1]) + "]"))
			return
		}
		_, _ = w.Write([]byte("[" + string(items[2]) + "]"))
	})
	s := newStore(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	g := &GitHub{Deps: deps(u, s, &now), BaseURL: u.srv.URL}
	apps := []*catalog.App{appWith("immich", catalog.Advisories{GitHubRepos: []string{"immich-app/immich"}})}

	res, err := g.Refresh(t.Context(), apps)
	if err != nil || res.Updated != 1 || res.Requests != 2 {
		t.Fatalf("first refresh: %+v %v", res, err)
	}
	recs, _ := s.Advisories(t.Context(), "immich")
	if len(recs) != 3 {
		t.Fatalf("stored %d advisories", len(recs))
	}
	byID := map[string]store.AdvisoryRecord{}
	for _, r := range recs {
		byID[r.Vuln.ID] = r
		if r.Source != "github:immich-app/immich" {
			t.Errorf("source %q", r.Source)
		}
	}
	g4 := byID["GHSA-g4w3-c888-cr93"]
	if g4.CVSS != 3.5 || g4.SeverityLabel != "low" || len(g4.Vuln.Aliases) != 1 || g4.Vuln.URL() == "" {
		t.Errorf("GHSA-g4w3: %+v", g4)
	}
	if ev := g4.Vuln.Affected[0].Ranges[0].Events; ev[0].Introduced != "0" || ev[1].LastAffected != "3.1.0" || ev[2].Fixed != "3.2.0" {
		t.Errorf("GHSA-g4w3 ranges: %+v", ev)
	}
	q8 := byID["GHSA-q89f-h332-8q2h"].Vuln.Affected[0]
	if len(q8.Versions) != 1 || q8.Versions[0] != "3.2.2" || !q8.Ranges[0].Inferred() {
		t.Errorf("bare version advisory: %+v", q8)
	}

	// Within the minimum interval the repository is not checked again.
	if res, _ := g.Refresh(t.Context(), apps); res.Skipped != 1 || res.Requests != 0 {
		t.Fatalf("recheck within interval: %+v", res)
	}
	// Later: conditional request, nothing changes, one request.
	now = now.Add(2 * time.Hour)
	res, err = g.Refresh(t.Context(), apps)
	if err != nil || res.NotModified != 1 || res.Requests != 1 {
		t.Fatalf("conditional refresh: %+v %v", res, err)
	}
	if recs, _ := s.Advisories(t.Context(), "immich"); len(recs) != 3 {
		t.Fatal("304 dropped stored advisories")
	}
}

func TestGitHubRateLimitAndFailures(t *testing.T) {
	reset := time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/broken/"):
			w.WriteHeader(http.StatusBadGateway)
		case strings.Contains(r.URL.Path, "/garbage/"):
			_, _ = w.Write([]byte("{not json"))
		case strings.Contains(r.URL.Path, "/ok/"):
			w.Header().Set("X-RateLimit-Remaining", "40")
			_, _ = w.Write([]byte("[]"))
		default:
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(reset.Unix()))
			w.WriteHeader(http.StatusForbidden)
		}
	})
	s := newStore(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	g := &GitHub{Deps: deps(u, s, &now), BaseURL: u.srv.URL}
	apps := []*catalog.App{
		appWith("a", catalog.Advisories{GitHubRepos: []string{"org/broken", "org/garbage", "org/ok"}}),
		appWith("b", catalog.Advisories{GitHubRepos: []string{"org/limited", "org/after"}}),
	}
	res, err := g.Refresh(t.Context(), apps)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected rate limit, got %v (%+v)", err, res)
	}
	if res.Updated != 1 || res.Skipped != 2 {
		t.Errorf("result: %+v", res)
	}
	if u.count("/repos/org/after/security-advisories") != 0 {
		t.Error("continued after rate limit")
	}
	st, _ := s.SourceState(t.Context(), "github", "org/limited")
	if !st.NextRun.Equal(reset) || st.LastError == "" {
		t.Errorf("rate-limit state: %+v", st)
	}
	st, _ = s.SourceState(t.Context(), "github", "org/broken")
	if !strings.Contains(st.LastError, "502") {
		t.Errorf("failure state: %+v", st)
	}

	// Before the reset the limited repository is skipped without a request.
	before := u.count("/repos/org/limited/security-advisories")
	if _, err := g.Refresh(t.Context(), apps[1:]); err != nil && !errors.Is(err, ErrRateLimited) {
		t.Fatal(err)
	}
	if u.count("/repos/org/limited/security-advisories") != before {
		t.Error("rate-limited repository retried before reset")
	}
}

func TestGitHubRejectsForeignPaginationHost(t *testing.T) {
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<https://evil.example/next>; rel="next"`)
		_, _ = w.Write([]byte("[]"))
	})
	s := newStore(t)
	now := time.Now()
	g := &GitHub{Deps: deps(u, s, &now), BaseURL: u.srv.URL}
	res, err := g.Refresh(t.Context(), []*catalog.App{appWith("a", catalog.Advisories{GitHubRepos: []string{"o/r"}})})
	if err != nil || res.Skipped != 1 || res.Updated != 0 {
		t.Fatalf("foreign link: %+v %v", res, err)
	}
}

func kevDoc(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"catalogVersion":"x","vulnerabilities":[`)
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"cveID":"CVE-2026-%d","dateAdded":"2026-11-01","knownRansomwareCampaignUse":"Unknown"}`, 1000+i)
	}
	b.WriteString("]}")
	return []byte(b.String())
}

func TestKEV(t *testing.T) {
	small := false
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"k1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"k1"`)
		if small {
			_, _ = w.Write(kevDoc(3))
			return
		}
		_, _ = w.Write(kevDoc(150))
	})
	s := newStore(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	k := &KEV{Deps: deps(u, s, &now), URL: u.srv.URL + "/kev.json"}
	if res, err := k.Refresh(t.Context(), nil); err != nil || res.Updated != 1 {
		t.Fatalf("first: %+v %v", res, err)
	}
	kev, _ := s.KEV(t.Context())
	if len(kev) != 150 || !kev["CVE-2026-1000"] {
		t.Fatalf("kev: %d", len(kev))
	}
	// Not due again within a day.
	if res, _ := k.Refresh(t.Context(), nil); res.Skipped != 1 || res.Requests != 0 {
		t.Fatalf("not due: %+v", res)
	}
	now = now.Add(25 * time.Hour)
	if res, err := k.Refresh(t.Context(), nil); err != nil || res.NotModified != 1 {
		t.Fatalf("conditional: %+v %v", res, err)
	}
	// A truncated catalog does not wipe the stored one.
	now = now.Add(25 * time.Hour)
	small = true
	if err := s.PutSourceState(t.Context(), store.SourceState{Source: "kev", Key: "catalog"}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Refresh(t.Context(), nil); err == nil {
		t.Fatal("implausible catalog accepted")
	}
	if kev, _ := s.KEV(t.Context()); len(kev) != 150 {
		t.Fatalf("kev wiped: %d", len(kev))
	}
}

func TestEPSSBatches(t *testing.T) {
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		ids := strings.Split(r.URL.Query().Get("cve"), ",")
		if len(ids) > epssBatch {
			t.Errorf("batch of %d", len(ids))
		}
		var data []string
		for _, id := range ids {
			data = append(data, fmt.Sprintf(`{"cve":%q,"epss":"0.25","percentile":"0.9","date":"2026-11-08"}`, id))
		}
		data = append(data, `{"cve":"CVE-bogus","epss":"7","percentile":"x"}`)
		_, _ = w.Write([]byte(`{"data":[` + strings.Join(data, ",") + `]}`))
	})
	s := newStore(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	var recs []store.AdvisoryRecord
	for i := range 230 {
		recs = append(recs, store.AdvisoryRecord{Vuln: advisory.Vulnerability{ID: fmt.Sprintf("GHSA-%d", i), Aliases: []string{fmt.Sprintf("CVE-2026-%d", i)}, Modified: now}})
	}
	if err := s.ReplaceAdvisories(t.Context(), "app", "github:o/r", recs, now); err != nil {
		t.Fatal(err)
	}
	e := &EPSS{Deps: deps(u, s, &now), URL: u.srv.URL + "/epss"}
	res, err := e.Refresh(t.Context(), nil)
	if err != nil || res.Requests != 3 {
		t.Fatalf("epss: %+v %v", res, err)
	}
	scores, _ := s.EPSS(t.Context())
	if len(scores) != 230 || scores["CVE-2026-7"] != 0.25 {
		t.Fatalf("scores: %d", len(scores))
	}
}

func TestOSVIncrementalAndPackageFilter(t *testing.T) {
	modified := "2026-10-01T00:00:00Z"
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = fmt.Fprintf(w, `{"results":[{"vulns":[{"id":"GHSA-osv1","modified":%q}]}]}`, modified)
		case "/v1/vulns/GHSA-osv1":
			_, _ = fmt.Fprintf(w, `{"id":"GHSA-osv1","modified":%q,"aliases":["CVE-2026-55"],
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
				"affected":[
				  {"package":{"ecosystem":"npm","name":"n8n"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]},
				  {"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}
				]}`, modified)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := newStore(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	o := &OSV{Deps: deps(u, s, &now), BaseURL: u.srv.URL}
	apps := []*catalog.App{appWith("n8n", catalog.Advisories{OSVPackages: []catalog.OSVPackage{{Ecosystem: "npm", Name: "n8n"}}})}
	if res, err := o.Refresh(t.Context(), apps); err != nil || res.Updated != 1 {
		t.Fatalf("first: %+v %v", res, err)
	}
	recs, _ := s.Advisories(t.Context(), "n8n")
	if len(recs) != 1 || len(recs[0].Vuln.Affected) != 1 || recs[0].Vuln.Affected[0].Package.Name != "n8n" || recs[0].CVSS != 9.8 {
		t.Fatalf("stored: %+v", recs)
	}
	// Unchanged modified time: no record fetch.
	if res, err := o.Refresh(t.Context(), apps); err != nil || res.NotModified != 1 || u.count("/v1/vulns/GHSA-osv1") != 1 {
		t.Fatalf("incremental: %+v %v fetches=%d", res, err, u.count("/v1/vulns/GHSA-osv1"))
	}
	modified = "2026-11-01T00:00:00Z"
	if res, err := o.Refresh(t.Context(), apps); err != nil || res.Updated != 1 || u.count("/v1/vulns/GHSA-osv1") != 2 {
		t.Fatalf("modified: %+v %v", res, err)
	}
}

func TestNVDConversion(t *testing.T) {
	body := fixture(t, "nvd_mosquitto.json")
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Query().Get("virtualMatchString"), "cpe:2.3:a:eclipse:mosquitto:") {
			t.Errorf("query %s", r.URL.RawQuery)
		}
		if r.Header.Get("apiKey") != "k" {
			t.Errorf("api key header missing")
		}
		_, _ = w.Write(body)
	})
	s := newStore(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	n := &NVD{Deps: deps(u, s, &now), BaseURL: u.srv.URL, APIKey: "k"}
	var doc nvdResponse
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	recs := []store.AdvisoryRecord{}
	for _, v := range doc.Vulnerabilities {
		if r, ok := convertNVD(v.CVE, "a:eclipse:mosquitto"); ok {
			recs = append(recs, r)
		}
	}
	if len(recs) != 3 {
		t.Fatalf("converted %d", len(recs))
	}
	r0 := recs[0].Vuln
	if r0.ID != "CVE-2017-9868" || r0.Affected[0].Ranges[0].Events[1].LastAffected != "1.4.12" || recs[0].CVSS == 0 || r0.Summary == "" {
		t.Errorf("CVE-2017-9868: %+v cvss=%v", r0, recs[0].CVSS)
	}
	if _, ok := convertNVD(doc.Vulnerabilities[0].CVE, "a:other:product"); ok {
		t.Error("CVE without a matching CPE kept")
	}
	res, err := n.Refresh(t.Context(), []*catalog.App{appWith("mosquitto", catalog.Advisories{CPE: []string{"cpe:2.3:a:eclipse:mosquitto"}})})
	// The fixture announces 26 results in pages of 3; the fake serves the
	// same page each time, so paging stops after ceil(26/3) requests and
	// repeated records collapse into the 3 distinct CVEs.
	if err != nil || res.Updated != 1 || res.Requests != 9 {
		t.Fatalf("refresh: %+v %v", res, err)
	}
	stored, _ := s.Advisories(t.Context(), "mosquitto")
	if len(stored) != 3 || stored[0].Source != "nvd:cpe:2.3:a:eclipse:mosquitto" {
		t.Fatalf("stored: %d", len(stored))
	}
	st, _ := s.SourceState(t.Context(), "nvd", "cpe:2.3:a:eclipse:mosquitto")
	if !st.NextRun.Equal(now.Add(dailyInterval)) {
		t.Errorf("next run: %v", st.NextRun)
	}
}

func TestNVDPageCap(t *testing.T) {
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, _ *http.Request) {
		// Claims endless results with one record per page.
		_, _ = w.Write([]byte(`{"totalResults":1000000,"vulnerabilities":[{"cve":{"id":"CVE-2026-1","vulnStatus":"Analyzed"}}]}`))
	})
	s := newStore(t)
	now := time.Now()
	n := &NVD{Deps: deps(u, s, &now), BaseURL: u.srv.URL}
	res, err := n.Refresh(t.Context(), []*catalog.App{appWith("x", catalog.Advisories{CPE: []string{"cpe:2.3:a:v:p"}})})
	if err != nil || res.Skipped != 1 || res.Requests != nvdMaxPages {
		t.Fatalf("page cap: %+v %v", res, err)
	}
}

// A derived entry may guess a repository that does not exist; that is no
// failing source. A reviewed entry's missing repository still is.
func TestGitHubDerivedRepositoryMissing(t *testing.T) {
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	s := newStore(t)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	g := &GitHub{Deps: deps(u, s, &now), BaseURL: u.srv.URL}
	derived := appWith("gh-org-guess", catalog.Advisories{GitHubRepos: []string{"org/guess"}})
	derived.Origin = catalog.OriginDerived
	reviewed := appWith("r", catalog.Advisories{GitHubRepos: []string{"org/typo"}})
	if _, err := g.Refresh(t.Context(), []*catalog.App{derived, reviewed}); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.SourceState(t.Context(), "github", "org/guess"); st.LastError != "" || st.LastSuccess.IsZero() {
		t.Errorf("derived: %+v", st)
	}
	if st, _ := s.SourceState(t.Context(), "github", "org/typo"); !strings.Contains(st.LastError, "404") {
		t.Errorf("reviewed: %+v", st)
	}
}

// DSM builds in NVD records ("7.2.1-69057", or the build in the CPE's
// update field) take the dotted form the Synology integration records;
// a dash would make the build a pre-release and invert the order.
func TestNVDApplianceVersions(t *testing.T) {
	raw := `{"id":"CVE-2024-0001","vulnStatus":"Analyzed","configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:o:synology:diskstation_manager:7.2.1:69057:*:*:*:*:*:*"},
		{"vulnerable":true,"criteria":"cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*","versionStartIncluding":"7.2","versionEndExcluding":"7.2.1-69057-5"}]}]}]}`
	var c nvdCVE
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	rec, ok := convertNVD(c, "o:synology:diskstation_manager")
	if !ok {
		t.Fatal("not converted")
	}
	aff := rec.Vuln.Affected[0]
	if len(aff.Versions) != 1 || aff.Versions[0] != "7.2.1.69057" {
		t.Errorf("exact versions %v", aff.Versions)
	}
	if ev := aff.Ranges[0].Events; ev[0].Introduced != "7.2" || ev[1].Fixed != "7.2.1.69057.5" {
		t.Errorf("range %+v", ev)
	}
	tc, _ := convertNVD(mustNVD(t, `{"id":"CVE-2024-0002","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:ixsystems:truenas_core:*:*:*:*:*:*:*:*","versionEndExcluding":"13.0-U6.2"}]}]}]}`), "o:ixsystems:truenas_core")
	if fixed := tc.Vuln.Affected[0].Ranges[0].Events[1].Fixed; fixed != "13.0.6.2" {
		t.Errorf("TrueNAS CORE fixed %q", fixed)
	}
}

func mustNVD(t *testing.T, raw string) nvdCVE {
	t.Helper()
	var c nvdCVE
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

type countingSource struct {
	name  string
	calls int
	res   Result
	err   error
}

func (c *countingSource) Name() string { return c.name }
func (c *countingSource) Refresh(context.Context, []*catalog.App) (Result, error) {
	c.calls++
	return c.res, c.err
}

func TestRefresherFollowsPick(t *testing.T) {
	a := &countingSource{name: "a", err: errors.New("down")}
	b := &countingSource{name: "b", res: Result{Updated: 1}}
	c := &countingSource{name: "c"}
	uplink := false
	changed := 0
	r := NewRefresher(Refresher{
		Sources: []Source{c},
		Pick: func() []Source {
			if uplink {
				return []Source{c}
			}
			return []Source{a, b}
		},
		Apps:     func(context.Context) ([]*catalog.App, error) { return nil, nil },
		OnChange: func(context.Context) { changed++ },
		Log:      slog.New(slog.DiscardHandler),
	})
	r.RunOnce(context.Background())
	// A failing source does not stop the next one; Pick wins over Sources.
	if a.calls != 1 || b.calls != 1 || c.calls != 0 || changed != 1 {
		t.Fatalf("direct run: a=%d b=%d c=%d changed=%d", a.calls, b.calls, c.calls, changed)
	}
	uplink = true
	r.RunOnce(context.Background())
	if a.calls != 1 || b.calls != 1 || c.calls != 1 || changed != 1 {
		t.Fatalf("uplink run: a=%d b=%d c=%d changed=%d", a.calls, b.calls, c.calls, changed)
	}
}
