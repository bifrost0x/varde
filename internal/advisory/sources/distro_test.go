// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/match"
)

func TestDistroRefresh(t *testing.T) {
	var mu sync.Mutex
	modified := "2026-10-01T00:00:00Z"
	var queries []string
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		mod := modified
		mu.Unlock()
		switch r.URL.Path {
		case "/v1/querybatch":
			body, _ := io.ReadAll(r.Body)
			var q struct {
				Queries []struct {
					Package struct{ Ecosystem, Name string } `json:"package"`
				} `json:"queries"`
			}
			_ = json.Unmarshal(body, &q)
			var results []string
			for _, x := range q.Queries {
				mu.Lock()
				queries = append(queries, x.Package.Ecosystem+"/"+x.Package.Name)
				mu.Unlock()
				// The per-CVE record and a notice for the same CVE.
				results = append(results, fmt.Sprintf(`{"vulns":[{"id":"DEBIAN-CVE-2026-1","modified":%q},{"id":"DSA-6131-1","modified":%q}]}`, mod, mod))
			}
			_, _ = fmt.Fprintf(w, `{"results":[%s]}`, join(results))
		case "/v1/vulns/DEBIAN-CVE-2026-1":
			_, _ = fmt.Fprintf(w, `{"id":"DEBIAN-CVE-2026-1","modified":%q,"upstream":["CVE-2026-1"],"affected":[
			  {"package":{"ecosystem":"Debian:12","name":"nginx"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.22.1-9+deb12u8"}]}]},
			  {"package":{"ecosystem":"Debian:13","name":"nginx"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.26.3-3+deb13u2"}]}]},
			  {"package":{"ecosystem":"Debian:11","name":"nginx"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}
			]}`, mod)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := newStore(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	present := map[string][]distro.Package{"nginx": {
		{Ecosystem: "Debian:12", Name: "nginx", Version: "1.22.1-9+deb12u7"},
		{Ecosystem: "Debian:12", Name: "nginx", Version: "1.22.1-9+deb12u8"},
		{Ecosystem: "Fedora:42", Name: "nginx", Version: "1"},
	}}
	d := &Distro{Deps: deps(u, s, &now), BaseURL: u.srv.URL, Packages: func(context.Context) (map[string][]distro.Package, error) {
		return present, nil
	}}
	apps := []*catalog.App{appWith("nginx", catalog.Advisories{}), appWith("other", catalog.Advisories{})}
	if res, err := d.Refresh(t.Context(), apps); err != nil || res.Updated != 1 {
		t.Fatalf("first: %+v %v", res, err)
	}
	// One query per release and package, unsupported releases left out;
	// the notice is not fetched.
	if len(queries) != 1 || queries[0] != "Debian:12/nginx" || u.count("/v1/vulns/DSA-6131-1") != 0 {
		t.Fatalf("queries %v", queries)
	}
	recs, _ := s.Advisories(t.Context(), "nginx")
	if len(recs) != 1 || recs[0].Source != match.SourceDistro || len(recs[0].Vuln.Affected) != 1 || recs[0].Vuln.Affected[0].Package.Ecosystem != "Debian:12" || recs[0].Vuln.Upstream[0] != "CVE-2026-1" {
		t.Fatalf("stored: %+v", recs)
	}
	// Unchanged: no fetch.
	if res, err := d.Refresh(t.Context(), apps); err != nil || res.NotModified != 1 || u.count("/v1/vulns/DEBIAN-CVE-2026-1") != 1 {
		t.Fatalf("incremental: %+v %v", res, err)
	}
	// A host on another release: the record is fetched again for it.
	present["nginx"] = append(present["nginx"], distro.Package{Ecosystem: "Debian:13", Name: "nginx", Version: "1.26.3-3+deb13u1"})
	if res, err := d.Refresh(t.Context(), apps); err != nil || res.Updated != 1 || u.count("/v1/vulns/DEBIAN-CVE-2026-1") != 2 {
		t.Fatalf("new release: %+v %v", res, err)
	}
	recs, _ = s.Advisories(t.Context(), "nginx")
	if len(recs) != 1 || len(recs[0].Vuln.Affected) != 2 {
		t.Fatalf("both releases kept: %+v", recs)
	}
	// Modified upstream: fetched again.
	mu.Lock()
	modified = "2026-11-01T00:00:00Z"
	mu.Unlock()
	if res, err := d.Refresh(t.Context(), apps); err != nil || res.Updated != 1 || u.count("/v1/vulns/DEBIAN-CVE-2026-1") != 3 {
		t.Fatalf("modified: %+v %v", res, err)
	}
	// The package is gone: its records go too.
	delete(present, "nginx")
	present["nginx"] = nil
	if res, err := d.Refresh(t.Context(), apps); err != nil {
		t.Fatalf("gone: %+v %v", res, err)
	}
	if recs, _ := s.Advisories(t.Context(), "nginx"); len(recs) != 0 {
		t.Errorf("records of a removed package kept: %d", len(recs))
	}
}

// Records beyond one answer are read page by page; a page token that does
// not advance is refused rather than looped on.
func TestDistroPagination(t *testing.T) {
	loop := false
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"DEBIAN-CVE-2026-1","modified":"2026-10-01T00:00:00Z"}],"next_page_token":"p2"}]}`))
		case "/v1/query":
			if loop {
				_, _ = w.Write([]byte(`{"vulns":[],"next_page_token":"p2"}`))
				return
			}
			_, _ = w.Write([]byte(`{"vulns":[{"id":"DEBIAN-CVE-2026-2","modified":"2026-10-01T00:00:00Z"}]}`))
		default:
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			_, _ = fmt.Fprintf(w, `{"id":%q,"modified":"2026-10-01T00:00:00Z","upstream":["CVE-x"],"affected":[{"package":{"ecosystem":"Debian:12","name":"nginx"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`, id)
		}
	})
	s := newStore(t)
	now := time.Now()
	d := &Distro{Deps: deps(u, s, &now), BaseURL: u.srv.URL, Packages: func(context.Context) (map[string][]distro.Package, error) {
		return map[string][]distro.Package{"nginx": {{Ecosystem: "Debian:12", Name: "nginx", Version: "1"}}}, nil
	}}
	if res, err := d.Refresh(t.Context(), []*catalog.App{appWith("nginx", catalog.Advisories{})}); err != nil || res.Updated != 1 {
		t.Fatalf("paginated: %+v %v", res, err)
	}
	if recs, _ := s.Advisories(t.Context(), "nginx"); len(recs) != 2 {
		t.Errorf("records of both pages: %d", len(recs))
	}
	loop = true
	s2 := newStore(t)
	d.Store = s2
	if res, err := d.Refresh(t.Context(), []*catalog.App{appWith("nginx", catalog.Advisories{})}); err != nil || res.Skipped != 1 {
		t.Fatalf("looping token: %+v %v", res, err)
	}
	if st, _ := s2.SourceState(t.Context(), match.SourceDistro, "nginx"); st.LastError == "" {
		t.Error("failure not recorded")
	}
}

func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}
