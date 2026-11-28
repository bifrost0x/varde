// SPDX-License-Identifier: Apache-2.0

package vulndb

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/distro"
)

var stamp = time.Date(2026, 11, 28, 6, 0, 0, 0, time.UTC)

func collect(t *testing.T, parse func(emit func(Record) error) error) map[string]Record {
	t.Helper()
	out := map[string]Record{}
	if err := parse(func(r Record) error {
		if _, dup := out[r.Vuln.ID]; dup {
			t.Fatalf("record %s emitted twice", r.Vuln.ID)
		}
		out[r.Vuln.ID] = r
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func events(a advisory.Affected) string {
	var parts []string
	for _, r := range a.Ranges {
		for _, e := range r.Events {
			switch {
			case e.Introduced != "":
				parts = append(parts, "i:"+e.Introduced)
			case e.Fixed != "":
				parts = append(parts, "f:"+e.Fixed)
			}
		}
	}
	return strings.Join(parts, ",")
}

func TestDatasets(t *testing.T) {
	cases := []struct {
		eco  string
		keys []string
	}{
		{"Debian:12", []string{"debian"}},
		{"Debian:13", []string{"debian"}},
		// Debian 11 left the tracker with its long-term support.
		{"Debian:11", nil},
		{"Ubuntu:24.04:LTS", []string{"ubuntu:noble"}},
		{"Ubuntu:25.10", []string{"ubuntu:questing"}},
		{"Ubuntu:99.04:LTS", nil},
		{"Alpine:v3.22", []string{"alpine:v3.22:main", "alpine:v3.22:community"}},
		{"Alpine:edge", nil},
		{"Wolfi", []string{"wolfi"}},
		{"Chainguard", []string{"chainguard"}},
		{"Go", []string{"osv:Go"}},
		{"PyPI", []string{"osv:PyPI"}},
		{"AlmaLinux:9", []string{"osv:AlmaLinux"}},
		{"Red Hat:enterprise_linux:9", []string{"osv:Red Hat"}},
		// npm's export is too large to download daily.
		{"npm", nil},
		{"Fedora:40", nil},
	}
	for _, c := range cases {
		ds := Datasets(c.eco)
		var keys []string
		for _, d := range ds {
			keys = append(keys, d.Key)
			if !strings.HasPrefix(d.URL, "https://"+d.Host+"/") || d.MaxBytes <= 0 || d.Title == "" {
				t.Errorf("%s: dataset %+v incomplete", c.eco, d)
			}
		}
		if strings.Join(keys, ",") != strings.Join(c.keys, ",") {
			t.Errorf("Datasets(%q) = %v, want %v", c.eco, keys, c.keys)
		}
		if Covered(c.eco) != (len(c.keys) > 0) {
			t.Errorf("Covered(%q) = %v", c.eco, Covered(c.eco))
		}
	}
	if got := Datasets("Rocky Linux:9")[0].URL; got != "https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip" {
		t.Errorf("Rocky Linux URL %s", got)
	}
}

func TestCanonicalName(t *testing.T) {
	cases := map[[2]string]string{
		{"PyPI", "PyYAML"}:                 "pyyaml",
		{"PyPI", "zope.interface"}:         "zope-interface",
		{"PyPI", "typing__Extensions"}:     "typing-extensions",
		{"NuGet", "Newtonsoft.Json"}:       "newtonsoft.json",
		{"crates.io", "Serde_JSON"}:        "serde-json",
		{"Go", "github.com/BurntSushi/x"}:  "github.com/BurntSushi/x",
		{"Debian:12", "OpenSSL"}:           "OpenSSL",
		{"Maven", "org.Apache:Commons-IO"}: "org.Apache:Commons-IO",
	}
	for in, want := range cases {
		if got := CanonicalName(in[0], in[1]); got != want {
			t.Errorf("CanonicalName(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestParseDebian(t *testing.T) {
	f, err := os.Open("testdata/debian.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	recs := collect(t, func(emit func(Record) error) error { return parseDebian(f, stamp, emit) })

	r, ok := recs["DEBIAN-CVE-2024-0001"]
	if !ok {
		t.Fatalf("CVE-2024-0001 missing: %v", recs)
	}
	// Bookworm fixed it; trixie was never affected ("0"); sid is not a
	// release Varde checks.
	if len(r.Vuln.Affected) != 1 || r.Vuln.Affected[0].Package.Ecosystem != "Debian:12" || r.Vuln.Affected[0].Package.Name != "openssl" {
		t.Fatalf("affected = %+v", r.Vuln.Affected)
	}
	if got := events(r.Vuln.Affected[0]); got != "i:0,f:3.0.14-1~deb12u2" {
		t.Errorf("events = %s", got)
	}
	if r.Vuln.Affected[0].EcosystemSpecific["urgency"] != "high" {
		t.Errorf("urgency = %v", r.Vuln.Affected[0].EcosystemSpecific)
	}
	if len(r.Vuln.Upstream) != 1 || r.Vuln.Upstream[0] != "CVE-2024-0001" {
		t.Errorf("upstream = %v", r.Vuln.Upstream)
	}
	if r.Vuln.Summary != "A buffer overflow in X allows remote attackers to execute code. More text follows here." || !strings.Contains(r.Vuln.Details, "More text") {
		t.Errorf("summary %q details %q", r.Vuln.Summary, r.Vuln.Details)
	}
	if r.Vuln.URL() != "https://security-tracker.debian.org/tracker/CVE-2024-0001" || !r.Vuln.Modified.Equal(stamp) {
		t.Errorf("url %s modified %s", r.Vuln.URL(), r.Vuln.Modified)
	}

	// Open: affected without a fix; bullseye is not in the tracker.
	r = recs["DEBIAN-CVE-2024-0002"]
	if len(r.Vuln.Affected) != 1 || events(r.Vuln.Affected[0]) != "i:0" || r.Vuln.Affected[0].EcosystemSpecific["status"] != "open" ||
		r.Vuln.Affected[0].EcosystemSpecific["urgency"] != "unimportant" {
		t.Errorf("open issue = %+v", r.Vuln.Affected)
	}
	if recs["DEBIAN-CVE-2024-0003"].Vuln.Affected[0].EcosystemSpecific["nodsa"] != "postponed" {
		t.Errorf("nodsa = %+v", recs["DEBIAN-CVE-2024-0003"].Vuln.Affected)
	}
	tmp := recs["DEBIAN-TEMP-0000000-ABCDEF"]
	if len(tmp.Vuln.Affected) != 1 || len(tmp.Vuln.Upstream) != 0 || tmp.Vuln.Summary != "" {
		t.Errorf("TEMP issue = %+v", tmp.Vuln)
	}
	for _, id := range []string{"DEBIAN-DSA-1234-1", "DEBIAN-CVE-2024-0004", "DEBIAN-CVE-2024-0005"} {
		if _, ok := recs[id]; ok {
			t.Errorf("%s should be left out (notice, bad package name, sid only)", id)
		}
	}
}

func TestParseDebianMalformed(t *testing.T) {
	for _, in := range []string{``, `[]`, `{"a": 1}`, `{"a": {"CVE-1": {"releases": []}}}`, `{"a": {}`, `{"a": {"CVE-1": "x"}}`, `{"a": {"CVE-1": {}`} {
		err := parseDebian(strings.NewReader(in), stamp, func(Record) error { return nil })
		if err == nil {
			t.Errorf("parseDebian(%q) accepted", in)
		}
	}
}

func TestParseSecDB(t *testing.T) {
	f, err := os.Open("testdata/secdb.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	recs := collect(t, func(emit func(Record) error) error { return parseSecDB(f, "Alpine:v3.22", "ALPINE-", stamp, emit) })
	want := map[string]string{
		"ALPINE-CVE-2025-0001":       "i:0,f:3.5.1-r0",
		"ALPINE-CVE-2025-0002":       "i:0,f:3.5.1-r0",
		"ALPINE-CVE-2025-0003":       "i:0,f:3.5.2-r0",
		"ALPINE-CVE-2025-0004":       "i:0,f:3.5.2-r0",
		"ALPINE-GHSA-2wp2-chmh-r934": "i:0,f:1.37.0-r5",
		"ALPINE-GHSA-xxxx-xxxx-xxxx": "i:0,f:1.37.0-r5",
	}
	if len(recs) != len(want) {
		t.Errorf("records %d, want %d: %v", len(recs), len(want), keysOf(recs))
	}
	for id, ev := range want {
		r, ok := recs[id]
		if !ok {
			t.Errorf("%s missing", id)
			continue
		}
		if got := events(r.Vuln.Affected[0]); got != ev || r.Vuln.Affected[0].Package.Ecosystem != "Alpine:v3.22" {
			t.Errorf("%s: %s %+v", id, got, r.Vuln.Affected[0].Package)
		}
		if r.Vuln.Upstream[0] != strings.TrimPrefix(id, "ALPINE-") {
			t.Errorf("%s upstream %v", id, r.Vuln.Upstream)
		}
	}
	// Listed under "0": the release was never affected.
	if _, ok := recs["ALPINE-CVE-2025-0009"]; ok {
		t.Error("an issue listed under version 0 must be left out")
	}
	if !strings.HasPrefix(recs["ALPINE-GHSA-2wp2-chmh-r934"].Vuln.URL(), "https://github.com/advisories/") {
		t.Error("GHSA link")
	}
}

func keysOf(m map[string]Record) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestParseUbuntuOVAL(t *testing.T) {
	f, err := os.Open("testdata/ubuntu.pkg.oval.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	recs := collect(t, func(emit func(Record) error) error {
		return parseUbuntuOVAL(f, "Ubuntu:24.04:LTS", stamp, emit)
	})
	r, ok := recs["UBUNTU-CVE-2025-1000"]
	if !ok {
		t.Fatalf("CVE-2025-1000 missing: %v", keysOf(recs))
	}
	// One record per CVE, an entry per source package that fixed it.
	if len(r.Vuln.Affected) != 2 {
		t.Fatalf("affected = %+v", r.Vuln.Affected)
	}
	byPkg := map[string]advisory.Affected{}
	for _, a := range r.Vuln.Affected {
		byPkg[a.Package.Name] = a
		if a.Package.Ecosystem != "Ubuntu:24.04:LTS" {
			t.Errorf("ecosystem %s", a.Package.Ecosystem)
		}
	}
	if events(byPkg["openssl"]) != "i:0,f:3.0.13-0ubuntu3.5" || events(byPkg["7zip"]) != "i:0,f:23.01+dfsg-11ubuntu0.1" {
		t.Errorf("events openssl %s 7zip %s", events(byPkg["openssl"]), events(byPkg["7zip"]))
	}
	if r.CVSS != 7.5 || r.Severity != "high" || len(r.Vuln.Severity) != 1 || r.Vuln.Severity[0].Type != "CVSS_V3" {
		t.Errorf("severity cvss=%v label=%q vec=%v", r.CVSS, r.Severity, r.Vuln.Severity)
	}
	if !r.Vuln.Published.Equal(time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("published %s", r.Vuln.Published)
	}
	var urls []string
	for _, ref := range r.Vuln.References {
		urls = append(urls, ref.URL)
	}
	if strings.Join(urls, " ") != "https://ubuntu.com/security/CVE-2025-1000 https://ubuntu.com/security/notices/USN-7001-1 https://ubuntu.com/security/notices/USN-7001-2" {
		t.Errorf("references %v", urls)
	}
	// A fix in Ubuntu Pro only is marked.
	esm := recs["UBUNTU-CVE-2025-1001"]
	if len(esm.Vuln.Affected) != 1 || esm.Vuln.Affected[0].EcosystemSpecific["pro"] != true || esm.Severity != "low" {
		t.Errorf("esm record %+v", esm)
	}
	// No state, no fix; kernel definitions are left out.
	for _, id := range []string{"UBUNTU-CVE-2025-1002", "UBUNTU-CVE-2025-2000"} {
		if _, ok := recs[id]; ok {
			t.Errorf("%s should be left out", id)
		}
	}
}

func TestOSVZip(t *testing.T) {
	path := writeZip(t, map[string]string{
		"GHSA-aaaa-bbbb-cccc.json": `{"id":"GHSA-aaaa-bbbb-cccc","modified":"2026-01-02T03:04:05Z","aliases":["CVE-2026-1"],"summary":"bad","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"database_specific":{"severity":"CRITICAL"},"affected":[{"package":{"ecosystem":"PyPI","name":"PyYAML"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.0.1"}]}]},{"package":{"ecosystem":"PyPI","name":"other"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0"}]}]}]}`,
		"PYSEC-2026-1.json":        `{"id":"PYSEC-2026-1","modified":"2026-01-02T03:04:05Z","withdrawn":"2026-02-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"pyyaml"}}]}`,
		"broken.json":              `{"id":`,
		"README.txt":               `not a record`,
	})
	d := Datasets("PyPI")[0]
	out := filepath.Join(t.TempDir(), "pypi.jsonl.gz")
	st, err := Normalize(d, path, out, stamp)
	if err != nil {
		t.Fatal(err)
	}
	if st.Records != 1 || st.Packages != 2 {
		t.Errorf("stats %+v", st)
	}
	w := Want([]distro.Package{{Ecosystem: "PyPI", Name: "pyyaml", Version: "5.4"}}, nil, stamp)
	sel := map[string][]Selected{}
	if err := Select(out, w, sel); err != nil {
		t.Fatal(err)
	}
	got := sel["os:PyPI/pyyaml"]
	if len(got) != 1 {
		t.Fatalf("selected %v", sel)
	}
	// Only the entry of the installed package stays, under its installed
	// name; the severity comes along.
	if len(got[0].Vuln.Affected) != 1 || got[0].Vuln.Affected[0].Package.Name != "pyyaml" || got[0].CVSS != 9.8 || got[0].Severity != "critical" {
		t.Errorf("selected %+v", got[0])
	}
}

func writeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "all.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNormalizeAndSelect(t *testing.T) {
	dir := t.TempDir()
	deb := Datasets("Debian:12")[0]
	if _, err := Normalize(deb, "testdata/debian.json", CachePath(dir, deb), stamp); err != nil {
		t.Fatal(err)
	}
	ubu := Datasets("Ubuntu:24.04:LTS")[0]
	if _, err := Normalize(ubu, "testdata/ubuntu.pkg.oval.xml.bz2", CachePath(dir, ubu), stamp); err != nil {
		t.Fatal(err)
	}
	w := Want([]distro.Package{
		{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.13-1~deb12u1"},
		{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.15-1~deb12u1"}, // same package, other image
		{Ecosystem: "Debian:13", Name: "openssl", Version: "3.5.0-1"},
		{Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl", Version: "3.0.13-0ubuntu3"},
		{Ecosystem: "Debian:12", Name: "curl", Version: "7.88.1-10"},
	}, nil, stamp)
	if got := len(w.Apps()); got != 4 {
		t.Errorf("wanted apps %d, want 4", got)
	}
	sel := map[string][]Selected{}
	for _, d := range []Dataset{deb, ubu} {
		if err := Select(CachePath(dir, d), w, sel); err != nil {
			t.Fatal(err)
		}
	}
	Tidy(sel)
	var ids []string
	for _, s := range sel["os:Debian:12/openssl"] {
		ids = append(ids, s.Vuln.ID)
	}
	// CVE-2024-0002 is unimportant to Debian: not a finding of a system
	// package.
	if strings.Join(ids, ",") != "DEBIAN-CVE-2024-0001,DEBIAN-CVE-2024-0003" {
		t.Errorf("Debian 12 openssl: %v", ids)
	}
	if s := sel["os:Debian:12/openssl"][0]; s.Severity != "high" {
		t.Errorf("Debian urgency as severity: %q", s.Severity)
	}
	// Debian 13: only the TEMP issue affects trixie.
	if got := sel["os:Debian:13/openssl"]; len(got) != 1 || got[0].Vuln.ID != "DEBIAN-TEMP-0000000-ABCDEF" {
		t.Errorf("Debian 13 openssl: %+v", got)
	}
	ub := sel["os:Ubuntu:24.04:LTS/openssl"]
	if len(ub) != 2 {
		t.Fatalf("Ubuntu openssl: %+v", ub)
	}
	for _, s := range ub {
		if len(s.Vuln.Affected) != 1 || s.Vuln.Affected[0].Package.Name != "openssl" {
			t.Errorf("Ubuntu entry not trimmed: %+v", s.Vuln.Affected)
		}
	}
	if _, ok := sel["os:Debian:12/curl"]; ok {
		t.Error("curl has no records")
	}
}

func TestNormalizeEmptyRefused(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	if err := os.WriteFile(raw, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	d := Datasets("Debian:12")[0]
	if _, err := Normalize(d, raw, CachePath(dir, d), stamp); err == nil {
		t.Fatal("an empty dataset must not replace the cache")
	}
	if _, err := os.Stat(CachePath(dir, d)); !os.IsNotExist(err) {
		t.Error("no cache file may be written")
	}
}

func TestSelectRejectsCorruptCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.jsonl.gz")
	if err := os.WriteFile(path, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Select(path, Want(nil, nil, stamp), map[string][]Selected{}); err == nil {
		t.Fatal("corrupt cache accepted")
	}
}

func FuzzParseDebian(f *testing.F) {
	seed, err := os.ReadFile("testdata/debian.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = parseDebian(bytes.NewReader(data), stamp, func(r Record) error {
			if _, err := json.Marshal(r); err != nil {
				t.Fatal(err)
			}
			return nil
		})
	})
}

func FuzzParseSecDB(f *testing.F) {
	seed, err := os.ReadFile("testdata/secdb.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = parseSecDB(bytes.NewReader(data), "Alpine:v3.22", "ALPINE-", stamp, func(Record) error { return nil })
	})
}

func FuzzParseUbuntuOVAL(f *testing.F) {
	seed, err := os.ReadFile("testdata/ubuntu.pkg.oval.xml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = parseUbuntuOVAL(bytes.NewReader(data), "Ubuntu:24.04:LTS", stamp, func(Record) error { return nil })
	})
}

func TestSummary(t *testing.T) {
	long := "Vim is an open source, command line text editor. Vim is vulnerable to path traversal through the zip.vim plugin, which lets a crafted archive overwrite files outside the directory the user opened, " +
		"in versions before 9.1.1551."
	got := summary(long)
	if !strings.HasPrefix(got, "Vim is an open source, command line text editor. Vim is vulnerable to path traversal") || !strings.HasSuffix(got, "…") || len(got) > 230 {
		t.Errorf("summary = %q", got)
	}
	if got := summary("  short\n text "); got != "short text" {
		t.Errorf("summary = %q", got)
	}
}

func TestRatings(t *testing.T) {
	dir := t.TempDir()
	d := CVEDataset()
	if _, err := Normalize(d, "testdata/ubuntu.cve.oval.xml.bz2", CachePath(dir, d), stamp); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRatings(CachePath(dir, d), nil)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := r["CVE-2025-3000"]
	if !ok || c.CVSS != 9.8 || c.Severity != "high" || !strings.HasPrefix(c.Vuln.Summary, "A heap overflow") || len(c.Vuln.Severity) != 1 {
		t.Fatalf("rating = %+v (all %v)", c, r)
	}
	if _, ok := r["CVE-2025-3001"]; ok {
		t.Error("a CVE without score and description carries nothing")
	}
	// Only the CVEs asked for are read.
	some, err := LoadRatings(CachePath(dir, d), map[string]bool{"CVE-2025-9999": true})
	if err != nil || len(some) != 0 {
		t.Errorf("ratings %v %v", some, err)
	}
	sel := map[string][]Selected{"a": {{Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2025-3000", Upstream: []string{"CVE-2025-3000"}}},
		{Vuln: advisory.Vulnerability{ID: "GHSA-x", Aliases: []string{"CVE-2025-1"}}, CVSS: 5}}}
	if u := Unrated(sel); len(u) != 1 || !u["CVE-2025-3000"] {
		t.Errorf("unrated %v", u)
	}

	// A Debian record without a rating takes the CVE's score and a label
	// from it; Debian's own urgency stays where Debian gave one.
	s := Selected{Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2025-3000", Upstream: []string{"CVE-2025-3000"}}}
	r.Rate(&s)
	if s.CVSS != 9.8 || s.Severity != "critical" || s.Vuln.DatabaseSpecific[advisory.RatedByKey] == nil || s.Vuln.Summary == "" {
		t.Errorf("rated %+v", s)
	}
	s = Selected{Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2025-3000", Upstream: []string{"CVE-2025-3000"}, Summary: "own"}, Severity: "low"}
	r.Rate(&s)
	if s.Severity != "low" || s.Vuln.Summary != "own" || s.CVSS != 9.8 {
		t.Errorf("rated %+v", s)
	}
	// A record with a score of its own keeps it.
	s = Selected{Vuln: advisory.Vulnerability{ID: "GHSA-x", Aliases: []string{"CVE-2025-3000"}}, CVSS: 5}
	r.Rate(&s)
	if s.CVSS != 5 {
		t.Errorf("own score replaced: %+v", s)
	}
}

// A record naming packages of two ecosystems is in both exports; the
// package gets it once.
func TestTidyDropsRecordsOfTwoExports(t *testing.T) {
	rec := `{"id":"GHSA-qppj-fm5r-hxr3","modified":"2026-01-02T03:04:05Z","affected":[` +
		`{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.17.0"}]}]},` +
		`{"package":{"ecosystem":"Maven","name":"org.apache.tomcat:tomcat-coyote"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.0.81"}]}]}]}`
	dir := t.TempDir()
	var paths []string
	for _, eco := range []string{"Go", "Maven"} {
		d := Datasets(eco)[0]
		raw := writeZip(t, map[string]string{"GHSA-qppj-fm5r-hxr3.json": rec})
		if _, err := Normalize(d, raw, CachePath(dir, d), stamp); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, CachePath(dir, d))
	}
	w := Want([]distro.Package{{Ecosystem: "Go", Name: "golang.org/x/net", Version: "0.10.0"}}, nil, stamp)
	sel := map[string][]Selected{}
	for _, p := range paths {
		if err := Select(p, w, sel); err != nil {
			t.Fatal(err)
		}
	}
	Tidy(sel)
	if got := sel["os:Go/golang.org/x/net"]; len(got) != 1 {
		t.Fatalf("records %d, want 1", len(got))
	}
}

// Ubuntu kernels stay with the sources that compare them; Debian's tracker
// covers its kernel, and other packages of Ubuntu are covered.
func TestHandles(t *testing.T) {
	cases := []struct {
		p    distro.Package
		want bool
	}{
		{distro.Package{Ecosystem: "Ubuntu:24.04:LTS", Name: "linux-hwe-6.8"}, false},
		{distro.Package{Ecosystem: "Ubuntu:24.04:LTS", Name: "linux"}, false},
		{distro.Package{Ecosystem: "Ubuntu:24.04:LTS", Name: "linux-firmware"}, true},
		{distro.Package{Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl"}, true},
		{distro.Package{Ecosystem: "Debian:12", Name: "linux"}, true},
		{distro.Package{Ecosystem: "npm", Name: "lodash"}, false},
	}
	for _, c := range cases {
		if got := Handles(c.p); got != c.want {
			t.Errorf("Handles(%+v) = %v, want %v", c.p, got, c.want)
		}
	}
	if w := Want([]distro.Package{{Ecosystem: "Ubuntu:24.04:LTS", Name: "linux", Version: "6.8.0-1"}}, nil, stamp); len(w.Apps()) != 0 {
		t.Error("an Ubuntu kernel is not wanted from the datasets")
	}
}

// A catalog app installed on two Ubuntu releases gets one record per CVE
// that keeps the entry of each release.
func TestTidyMergesReleases(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for _, eco := range []string{"Ubuntu:24.04:LTS", "Ubuntu:22.04:LTS"} {
		d := Datasets(eco)[0]
		if _, err := Normalize(d, "testdata/ubuntu.pkg.oval.xml.bz2", CachePath(dir, d), stamp); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, CachePath(dir, d))
	}
	w := Want(nil, map[string][]distro.Package{"openssl-app": {
		{Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl", Version: "3.0.13-0ubuntu3"},
		{Ecosystem: "Ubuntu:22.04:LTS", Name: "openssl", Version: "3.0.2-0ubuntu1"},
	}}, stamp)
	sel := map[string][]Selected{}
	for _, p := range paths {
		if err := Select(p, w, sel); err != nil {
			t.Fatal(err)
		}
	}
	Tidy(sel)
	var rec *Selected
	for i := range sel["openssl-app"] {
		if sel["openssl-app"][i].Vuln.ID == "UBUNTU-CVE-2025-1000" {
			rec = &sel["openssl-app"][i]
		}
	}
	if rec == nil || len(sel["openssl-app"]) != 2 {
		t.Fatalf("records %+v", sel["openssl-app"])
	}
	ecos := map[string]bool{}
	for _, a := range rec.Vuln.Affected {
		ecos[a.Package.Ecosystem] = true
	}
	if !ecos["Ubuntu:24.04:LTS"] || !ecos["Ubuntu:22.04:LTS"] || len(rec.Vuln.Affected) != 2 {
		t.Errorf("entries %+v", rec.Vuln.Affected)
	}
}

// A catalog app keeps Debian's unimportant entries: the matcher says what
// they are there, as with osv.dev's records of catalog apps.
func TestUnimportantKeptForCatalogApps(t *testing.T) {
	dir := t.TempDir()
	d := Datasets("Debian:12")[0]
	if _, err := Normalize(d, "testdata/debian.json", CachePath(dir, d), stamp); err != nil {
		t.Fatal(err)
	}
	w := Want(nil, map[string][]distro.Package{"tls-app": {{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.13-1~deb12u1"}}}, stamp)
	sel := map[string][]Selected{}
	if err := Select(CachePath(dir, d), w, sel); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range sel["tls-app"] {
		found = found || s.Vuln.ID == "DEBIAN-CVE-2024-0002"
	}
	if !found {
		t.Error("unimportant entry missing for a catalog app")
	}
}
