// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/vulndb"
)

const debianTracker = `{
  "openssl": {
    "CVE-2026-1": {"description": "Heap overflow in the TLS handshake.", "releases": {
      "trixie": {"status": "resolved", "fixed_version": "3.5.1-1+deb13u1", "urgency": "not yet assigned"}}},
    "CVE-2026-2": {"description": "Old issue.", "releases": {
      "trixie": {"status": "resolved", "fixed_version": "0", "urgency": "low"}}}
  },
  "bash": {
    "CVE-2026-3": {"releases": {"trixie": {"status": "open", "urgency": "low"}}}
  }
}`

// The complete datasets: each file is fetched once and then only when it
// changed (conditional requests), the records of the packages present are
// stored per package with the CVE's rating, packages that go lose their
// records, and a dataset that cannot be fetched leaves the stored records
// of its ecosystem as they are.
func TestVulnDBRefresh(t *testing.T) {
	cve, err := os.ReadFile(filepath.Join("..", "..", "vulndb", "testdata", "ubuntu.cve.oval.xml.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	alpineDown := true
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		down := alpineDown
		mu.Unlock()
		switch r.URL.Path {
		case "/tracker/data/json":
			if r.Header.Get("If-None-Match") == `"deb1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"deb1"`)
			w.Header().Set("Last-Modified", "Sat, 28 Nov 2026 06:04:03 GMT")
			_, _ = w.Write([]byte(debianTracker))
		case "/oval/com.ubuntu.noble.cve.oval.xml.bz2":
			_, _ = w.Write(cve)
		case "/v3.22/main.json", "/v3.22/community.json":
			if down {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"packages":[{"pkg":{"name":"musl","secfixes":{"1.2.5-r1":["CVE-2025-3000"]}}}]}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := newStore(t)
	now := time.Date(2026, 11, 28, 7, 0, 0, 0, time.UTC)
	present := []distro.Package{
		{Ecosystem: "Debian:13", Name: "openssl", Version: "3.5.1-1"},
		{Ecosystem: "Debian:13", Name: "bash", Version: "5.2.37-2"},
		{Ecosystem: "Alpine:v3.22", Name: "musl", Version: "1.2.5-r0"},
		// No complete dataset: left to the other sources.
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
	}
	var pmu sync.Mutex
	dir := filepath.Join(t.TempDir(), "vulndb")
	v := &VulnDB{Deps: deps(u, s, &now), Dir: dir,
		Stored: func(ctx context.Context) ([]string, error) { return s.AdvisoryApps(ctx, SourceVulnDB) },
		Apps: func(context.Context) (map[string][]distro.Package, error) {
			// nginx installed from Debian's archive, a catalog app.
			return map[string][]distro.Package{"nginx": {{Ecosystem: "Debian:13", Name: "openssl", Version: "3.5.1-1"}}}, nil
		},
		Packages: func(context.Context) ([]distro.Package, error) {
			pmu.Lock()
			defer pmu.Unlock()
			return append([]distro.Package(nil), present...), nil
		},
		URL: func(d vulndb.Dataset) string { return strings.Replace(d.URL, "https://"+d.Host, u.srv.URL, 1) },
	}
	// A download a crash interrupted is cleaned up.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(dir, ".download-123")
	if err := os.WriteFile(leftover, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := v.Refresh(t.Context(), nil)
	if _, statErr := os.Stat(leftover); !os.IsNotExist(statErr) {
		t.Error("the leftover of an interrupted download stays")
	}
	if err == nil || !strings.Contains(err.Error(), "Alpine secdb") {
		t.Fatalf("a dataset that cannot be fetched must be reported: %v", err)
	}
	if res.Requests != 4 {
		t.Errorf("requests %d, want 4 (Debian, CVE ratings, two Alpine files)", res.Requests)
	}
	recs := records(t, s, "os:Debian:13/openssl")
	if len(recs) != 1 || recs[0].Vuln.ID != "DEBIAN-CVE-2026-1" || recs[0].Source != SourceVulnDB {
		t.Fatalf("openssl records %+v", recs)
	}
	if !recs[0].Vuln.Modified.Equal(time.Date(2026, 11, 28, 6, 4, 3, 0, time.UTC)) {
		t.Errorf("modified %s: the file's Last-Modified", recs[0].Vuln.Modified)
	}
	if got := records(t, s, "os:Debian:13/bash"); len(got) != 1 {
		t.Errorf("bash records %+v", got)
	}
	// A catalog app's distribution package gets the same records, under
	// the app.
	if got := records(t, s, "nginx"); len(got) != 1 || got[0].Vuln.ID != "DEBIAN-CVE-2026-1" || got[0].Vuln.Affected[0].Package.Name != "openssl" {
		t.Errorf("app records %+v", got)
	}
	if got := records(t, s, "os:Alpine:v3.22/musl"); len(got) != 0 {
		t.Errorf("no Alpine data yet, no records: %+v", got)
	}
	st, err := s.SourceState(t.Context(), SourceVulnDB, "alpine:v3.22:main")
	if err != nil || st.LastError == "" || !st.NextRun.Equal(now.Add(vulnDBRetry)) {
		t.Errorf("failed dataset state %+v %v", st, err)
	}
	// A refresh before the retry time leaves the failed dataset alone,
	// although it was never fetched.
	alpineHits := u.count("/v3.22/main.json")
	now = now.Add(10 * time.Minute)
	if _, err := v.Refresh(t.Context(), nil); err != nil {
		t.Fatalf("refresh during the backoff: %v", err)
	}
	if u.count("/v3.22/main.json") != alpineHits {
		t.Error("a failed dataset is asked again before its retry time")
	}

	// Later: Debian has not changed, Alpine is back. The rating of the
	// CVE reaches the Alpine record, which has none of its own.
	mu.Lock()
	alpineDown = false
	mu.Unlock()
	now = now.Add(25 * time.Hour)
	if _, err := v.Refresh(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if n := u.count("/tracker/data/json"); n != 2 {
		t.Errorf("Debian fetched %d times, want 2 (the second conditional)", n)
	}
	musl := records(t, s, "os:Alpine:v3.22/musl")
	if len(musl) != 1 || musl[0].Vuln.ID != "ALPINE-CVE-2025-3000" || musl[0].CVSS != 9.8 || musl[0].SeverityLabel != "critical" ||
		musl[0].Vuln.RatedBy() == "" {
		t.Fatalf("musl records %+v", musl)
	}

	// bash is gone from every system: its records go; nothing is
	// downloaded again within the day.
	pmu.Lock()
	present = present[:1]
	present = append(present, distro.Package{Ecosystem: "Alpine:v3.22", Name: "musl", Version: "1.2.5-r0"})
	pmu.Unlock()
	hits := u.count("/tracker/data/json")
	if _, err := v.Refresh(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if got := records(t, s, "os:Debian:13/bash"); len(got) != 0 {
		t.Errorf("bash records kept: %+v", got)
	}
	if u.count("/tracker/data/json") != hits {
		t.Error("a dataset was downloaded again before it was due")
	}
	if got := records(t, s, "os:Debian:13/openssl"); len(got) != 1 {
		t.Errorf("openssl records %+v", got)
	}
}

// The osv.dev source does not ask about what the datasets cover.
func TestSystemPackagesSkip(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			asked = append(asked, string(body))
			mu.Unlock()
			_, _ = w.Write([]byte(`{"results":[{}]}`))
			return
		}
		t.Errorf("unexpected request %s", r.URL.Path)
	})
	s := newStore(t)
	now := time.Date(2026, 11, 28, 7, 0, 0, 0, time.UTC)
	sp := &SystemPackages{Deps: deps(u, s, &now), BaseURL: u.srv.URL, Stored: s.SystemAdvisoryApps,
		Packages: func(context.Context) ([]distro.Package, error) {
			return []distro.Package{{Ecosystem: "Debian:13", Name: "curl", Version: "8.0"}, {Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}}, nil
		},
		Skip: vulndb.Handles}
	if _, err := sp.Refresh(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || strings.Contains(asked[0], "curl") || !strings.Contains(asked[0], "lodash") {
		t.Errorf("asked %v", asked)
	}
}

func records(t *testing.T, s *store.Store, app string) []store.AdvisoryRecord {
	t.Helper()
	recs, err := s.Advisories(t.Context(), app)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}
