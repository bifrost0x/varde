// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
)

func TestSecurityMentions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		text  string
		lines int
		ids   []string
	}{
		{"cve", "- Fix upload handling (CVE-2026-12345)", 1, []string{"CVE-2026-12345"}},
		{"ghsa", "Fixes GHSA-4f8q-xw2v-9j7h reported by someone", 1, []string{"GHSA-4f8q-xw2v-9j7h"}},
		{"wording", "* fix a path traversal in the file API", 1, nil},
		{"xss", "Fixed stored XSS in comments", 1, nil},
		{"security fix", "This is a security release, please update.", 1, nil},
		{"section", "## Features\n- dark mode\n### Security\n- Restrict uploads to admins\n- Tighten session cookies\n## Fixes\n- typo", 3, nil},
		{"section with ids", "### Security\n- CVE-2026-0001 and CVE-2026-0002", 2, []string{"CVE-2026-0001", "CVE-2026-0002"}},
		{"nothing", "## Features\n- dark mode\n- faster search", 0, nil},
		{"bare security word", "Improve the security settings page layout", 0, nil},
		{"dependency bump", "- Bump golang.org/x/net from 0.1.0 to 0.2.0 to fix CVE-2026-9999", 0, nil},
		{"deps scope", "chore(deps): update module github.com/x/y to v2 (security)", 0, nil},
		{"bot line", "* build: update foo for vulnerability by @dependabot in #12", 0, nil},
		{"force is not rce", "Force a refresh of the source list", 0, nil},
		{"other heading ends section", "### Security\n- lock down admin\n### Other\n- new theme", 2, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := SecurityMentions(tc.text)
			if len(m.Lines) != tc.lines || strings.Join(m.IDs, ",") != strings.Join(tc.ids, ",") {
				t.Errorf("SecurityMentions(%q) = %+v", tc.text, m)
			}
		})
	}
}

func TestSecurityMentionsBounds(t *testing.T) {
	m := SecurityMentions(strings.Repeat("- fix a vulnerability "+strings.Repeat("x", 400)+"\n", 20))
	if len(m.Lines) != maxMentionLines {
		t.Fatalf("lines = %d", len(m.Lines))
	}
	for _, l := range m.Lines {
		if len(l) > maxMentionLine+len("…") {
			t.Fatalf("line of %d bytes", len(l))
		}
	}
}

func TestReleaseVersion(t *testing.T) {
	for tag, want := range map[string]string{"v1.4.2": "1.4.2", "1.4.2": "1.4.2", "V2.0": "2.0", "2024.10.1": "2024.10.1",
		"v1.4.2-rc1": "", "release-1.2": "", "webssh-1.0": "", "latest": "", "": ""} {
		got, ok := ReleaseVersion(tag)
		if got != want || ok != (want != "") {
			t.Errorf("ReleaseVersion(%q) = %q, %v", tag, got, ok)
		}
	}
}

func TestReleaseRecords(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rels := []ghRelease{
		{TagName: "v1.5.0", Body: "- fix XSS in the editor (CVE-2026-0001)\n- fix CVE-2026-0002 too", HTMLURL: "https://github.com/acme/app/releases/tag/v1.5.0", PublishedAt: at},
		{TagName: "v1.4.1", Name: "Security release", Body: "- harden the login", HTMLURL: "https://evil.example/x", PublishedAt: at},
		{TagName: "v1.4.0", Body: "- new theme"},
		{TagName: "v1.6.0-rc1", Body: "fixes a vulnerability", Prerelease: true},
		{TagName: "v1.6.0", Body: "fixes a vulnerability", Draft: true},
		{TagName: "nightly", Body: "fixes a vulnerability"},
	}
	recs := releaseRecords("acme/app", rels)
	if len(recs) != 3 {
		t.Fatalf("records = %d: %+v", len(recs), recs)
	}
	byAlias := map[string]advisory.Vulnerability{}
	for _, r := range recs {
		v := r.Vuln
		key := ""
		if len(v.Aliases) > 0 {
			key = v.Aliases[0]
		}
		byAlias[key] = v
		if !strings.HasPrefix(v.ID, "VARDE-REL-") || len(v.Affected) != 1 {
			t.Fatalf("record %+v", v)
		}
		rg := v.Affected[0].Ranges[0]
		if !rg.Inferred() || rg.Events[0].Introduced != "0" {
			t.Errorf("range of %s: %+v", v.ID, rg)
		}
	}
	one, two, plain := byAlias["CVE-2026-0001"], byAlias["CVE-2026-0002"], byAlias[""]
	if one.ID == two.ID || one.Affected[0].Ranges[0].Events[1].Fixed != "1.5.0" || one.URL() != "https://github.com/acme/app/releases/tag/v1.5.0" {
		t.Errorf("per-ID records: %+v %+v", one, two)
	}
	if plain.Affected[0].Ranges[0].Events[1].Fixed != "1.4.1" || plain.URL() != "" || !strings.Contains(plain.Details, "Security release") {
		t.Errorf("release without an ID: %+v", plain)
	}
	// The IDs are stable: a finding keeps its identity between builds.
	if again := releaseRecords("acme/app", rels); again[0].Vuln.ID != recs[0].Vuln.ID {
		t.Errorf("IDs changed: %s, %s", again[0].Vuln.ID, recs[0].Vuln.ID)
	}
}

func TestReleaseNotesRefresh(t *testing.T) {
	limited := false
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		switch {
		case limited:
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "4102444800")
			http.Error(w, "rate limit", http.StatusForbidden)
		case strings.HasPrefix(r.URL.Path, "/repos/gone/"):
			http.NotFound(w, r)
		case r.Header.Get("If-None-Match") == `"r1"`:
			w.WriteHeader(http.StatusNotModified)
		default:
			if r.URL.Query().Get("per_page") != "50" {
				t.Errorf("query %q", r.URL.RawQuery)
			}
			w.Header().Set("ETag", `"r1"`)
			w.Header().Set("X-RateLimit-Remaining", "500")
			_ = json.NewEncoder(w).Encode([]ghRelease{{TagName: "v2.1.0", Body: "Fixes a path traversal", PublishedAt: time.Now().UTC()}})
		}
	})
	s := newStore(t)
	now := time.Date(2026, 11, 14, 2, 0, 0, 0, time.UTC)
	n := &ReleaseNotes{Deps: deps(u, s, &now), BaseURL: u.srv.URL}
	apps := []*catalog.App{
		appWith("gh-acme-app", catalog.Advisories{GitHubRepos: []string{"acme/app"}}),
		appWith("gh-gone-app", catalog.Advisories{GitHubRepos: []string{"gone/app"}}),
	}
	res, err := n.Refresh(t.Context(), apps)
	if err != nil || res.Updated != 1 || res.NotModified != 1 {
		t.Fatalf("first refresh: %+v %v", res, err)
	}
	recs, _ := s.Advisories(t.Context(), "gh-acme-app")
	if len(recs) != 1 || recs[0].Source != "release:acme/app" {
		t.Fatalf("stored %+v", recs)
	}
	// Within the interval nothing is asked; later a conditional request.
	if res, _ := n.Refresh(t.Context(), apps); res.Requests != 0 {
		t.Fatalf("recheck within interval: %+v", res)
	}
	now = now.Add(13 * time.Hour)
	if res, err := n.Refresh(t.Context(), apps[:1]); err != nil || res.NotModified != 1 {
		t.Fatalf("conditional: %+v %v", res, err)
	}
	// A rate limit stops the reads and keeps what is stored.
	now = now.Add(13 * time.Hour)
	limited = true
	if _, err := n.Refresh(t.Context(), apps[:1]); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate limit: %v", err)
	}
	if recs, _ := s.Advisories(t.Context(), "gh-acme-app"); len(recs) != 1 {
		t.Fatal("a rate limit dropped the stored records")
	}
}

func FuzzSecurityMentions(f *testing.F) {
	f.Add("### Security\n- CVE-2026-0001 fixed\n- Bump x")
	f.Add("fix XSS GHSA-4f8q-xw2v-9j7h")
	f.Fuzz(func(t *testing.T, s string) {
		m := SecurityMentions(s)
		if len(m.Lines) > maxMentionLines {
			t.Fatalf("%d lines", len(m.Lines))
		}
		for _, id := range m.IDs {
			if !cveMention.MatchString(id) && !ghsaMention.MatchString(id) {
				t.Fatalf("id %q", id)
			}
		}
	})
}
