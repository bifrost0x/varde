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

	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/match"
)

// System packages: one batch query with versions, only the records osv.dev
// names as affecting them are fetched, follow-up pages are asked for,
// Debian's "unimportant" entries are dropped, unchanged records are not
// fetched again, and records of packages no longer present go.
func TestSystemPackagesRefresh(t *testing.T) {
	var mu sync.Mutex
	var batches []string
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			body, _ := io.ReadAll(r.Body)
			var q struct {
				Queries []struct {
					Package   struct{ Ecosystem, Name string } `json:"package"`
					Version   string                           `json:"version"`
					PageToken string                           `json:"page_token"`
				} `json:"queries"`
			}
			_ = json.Unmarshal(body, &q)
			var results []string
			for _, x := range q.Queries {
				mu.Lock()
				batches = append(batches, x.Package.Ecosystem+"/"+x.Package.Name+"@"+x.Version+"#"+x.PageToken)
				mu.Unlock()
				switch {
				case x.Package.Name == "openssl" && x.PageToken == "":
					results = append(results, `{"vulns":[{"id":"DEBIAN-CVE-2026-1","modified":"2026-10-01T00:00:00Z"},{"id":"DSA-6000-1","modified":"2026-10-01T00:00:00Z"}],"next_page_token":"p2"}`)
				case x.Package.Name == "openssl":
					results = append(results, `{"vulns":[{"id":"DEBIAN-CVE-2026-2","modified":"2026-10-01T00:00:00Z"}]}`)
				default:
					results = append(results, `{}`)
				}
			}
			_, _ = fmt.Fprintf(w, `{"results":[%s]}`, strings.Join(results, ","))
		case "/v1/vulns/DEBIAN-CVE-2026-1":
			_, _ = io.WriteString(w, `{"id":"DEBIAN-CVE-2026-1","modified":"2026-10-01T00:00:00Z","upstream":["CVE-2026-1"],"affected":[
			  {"package":{"ecosystem":"Debian:13","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.5.1-1+deb13u1"}]}],"ecosystem_specific":{"urgency":"medium"}},
			  {"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`)
		case "/v1/vulns/CVE-2026-1":
			_, _ = io.WriteString(w, `{"id":"CVE-2026-1","modified":"2026-10-01T00:00:00Z","summary":"Heap overflow in the TLS handshake",
			  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`)
		case "/v1/vulns/DEBIAN-CVE-2026-2":
			_, _ = io.WriteString(w, `{"id":"DEBIAN-CVE-2026-2","modified":"2026-10-01T00:00:00Z","upstream":["CVE-2026-2"],"affected":[
			  {"package":{"ecosystem":"Debian:13","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"ecosystem_specific":{"urgency":"unimportant"}}]}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := newStore(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	present := []distro.Package{
		{Ecosystem: "Debian:13", Name: "openssl", Version: "3.5.1-1"},
		{Ecosystem: "Debian:13", Name: "bash", Version: "5.2.37-2"},
		{Ecosystem: "Fedora:42", Name: "bash", Version: "5.2"},
	}
	sp := &SystemPackages{Deps: deps(u, s, &now), BaseURL: u.srv.URL, Stored: s.SystemAdvisoryApps,
		Packages: func(context.Context) ([]distro.Package, error) { return present, nil }}
	if res, err := sp.Refresh(t.Context(), nil); err != nil || res.Updated != 1 {
		t.Fatalf("first: %+v %v", res, err)
	}
	mu.Lock()
	got := strings.Join(batches, " ")
	mu.Unlock()
	if !strings.Contains(got, "Debian:13/openssl@3.5.1-1#") || !strings.Contains(got, "Debian:13/openssl@3.5.1-1#p2") || strings.Contains(got, "Fedora") {
		t.Fatalf("queries: %s", got)
	}
	if u.count("/v1/vulns/DSA-6000-1") != 0 {
		t.Fatal("a notice was fetched")
	}
	recs, _ := s.Advisories(t.Context(), distro.SystemAppID("Debian:13", "openssl"))
	if len(recs) != 1 || recs[0].Vuln.ID != "DEBIAN-CVE-2026-1" || recs[0].Source != match.SourceDistro ||
		len(recs[0].Vuln.Affected) != 1 || recs[0].Vuln.Affected[0].Package.Ecosystem != "Debian:13" {
		t.Fatalf("stored: %+v", recs)
	}
	// The severity comes from the CVE record: Debian's record has none.
	if recs[0].CVSS != 9.8 || len(recs[0].Vuln.Severity) != 1 || recs[0].Vuln.Summary != "Heap overflow in the TLS handshake" {
		t.Fatalf("severity not taken over: %v %+v %q", recs[0].CVSS, recs[0].Vuln.Severity, recs[0].Vuln.Summary)
	}

	// Unchanged: nothing is fetched again.
	before := u.count("/v1/vulns/DEBIAN-CVE-2026-1")
	if _, err := sp.Refresh(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if u.count("/v1/vulns/DEBIAN-CVE-2026-1") != before {
		t.Fatal("unchanged record fetched again")
	}

	// openssl is updated away everywhere: its records go.
	present = []distro.Package{{Ecosystem: "Debian:13", Name: "bash", Version: "5.2.37-2"}}
	if _, err := sp.Refresh(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if recs, _ := s.Advisories(t.Context(), distro.SystemAppID("Debian:13", "openssl")); len(recs) != 0 {
		t.Fatalf("records of a removed package kept: %d", len(recs))
	}
}

// App dependencies: a Go module's advisories come as GO- records and as
// GitHub advisories (some never reviewed into a GO- record), npm's as GHSA
// records.
func TestSystemPackagesLanguages(t *testing.T) {
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = io.WriteString(w, `{"results":[
			  {"vulns":[{"id":"GHSA-4v7x-pqxf-cx7m","modified":"2026-09-10T00:00:00Z"},{"id":"GO-2024-2687","modified":"2026-02-04T00:00:00Z"}]},
			  {"vulns":[{"id":"GHSA-rv95-896h-c2vc","modified":"2026-03-01T00:00:00Z"}]}]}`)
		case "/v1/vulns/GO-2024-2687":
			_, _ = io.WriteString(w, `{"id":"GO-2024-2687","modified":"2026-02-04T00:00:00Z","aliases":["CVE-2023-45288","GHSA-4v7x-pqxf-cx7m"],
			  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
			  "affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.23.0"}]}]}]}`)
		case "/v1/vulns/CVE-2023-45288":
			w.WriteHeader(http.StatusNotFound)
		case "/v1/vulns/GHSA-4v7x-pqxf-cx7m":
			_, _ = io.WriteString(w, `{"id":"GHSA-4v7x-pqxf-cx7m","modified":"2026-09-10T00:00:00Z","aliases":["CVE-2023-45288"],
			  "affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.23.0"}]}]}]}`)
		case "/v1/vulns/GHSA-rv95-896h-c2vc":
			_, _ = io.WriteString(w, `{"id":"GHSA-rv95-896h-c2vc","modified":"2026-03-01T00:00:00Z","aliases":["CVE-2024-29041"],
			  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}],
			  "affected":[{"package":{"ecosystem":"npm","name":"express"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.19.2"}]}]}]}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := newStore(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	sp := &SystemPackages{Deps: deps(u, s, &now), BaseURL: u.srv.URL, Stored: s.SystemAdvisoryApps,
		Packages: func(context.Context) ([]distro.Package, error) {
			return []distro.Package{{Ecosystem: "Go", Name: "golang.org/x/net", Version: "0.20.0"}, {Ecosystem: "npm", Name: "express", Version: "4.18.2"}}, nil
		}}
	if _, err := sp.Refresh(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	// Both records of the flaw are kept; the matcher merges them by alias.
	gorecs, _ := s.Advisories(t.Context(), distro.SystemAppID("Go", "golang.org/x/net"))
	npmrecs, _ := s.Advisories(t.Context(), distro.SystemAppID("npm", "express"))
	if len(gorecs) != 2 || len(npmrecs) != 1 || npmrecs[0].Vuln.ID != "GHSA-rv95-896h-c2vc" {
		t.Fatalf("stored: %+v / %+v", gorecs, npmrecs)
	}
}
