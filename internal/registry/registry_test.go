// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// fakeRegistry speaks the distribution API with a bearer challenge: no
// request succeeds without the token, tags come in two pages, manifests
// answer HEAD with their digest.
func fakeRegistry(t *testing.T, digests map[string]string) (*Client, string, *[]string) {
	t.Helper()
	var reqs []string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/token" {
			if !strings.Contains(r.URL.RawQuery, "scope=repository%3Aorg%2Fapp%3Apull") {
				t.Errorf("token scope %s", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, `{"token":"t0k"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="reg",scope="repository:org/app:pull"`, srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/v2/org/app/tags/list" && r.URL.Query().Get("last") == "":
			w.Header().Set("Link", `</v2/org/app/tags/list?n=1000&last=1.2.0>; rel="next"`)
			_, _ = io.WriteString(w, `{"tags":["latest","1.0.0","1.2.0"]}`)
		case r.URL.Path == "/v2/org/app/tags/list":
			_, _ = io.WriteString(w, `{"tags":["1.3.0","1.3.0-alpine","nightly"]}`)
		case strings.HasPrefix(r.URL.Path, "/v2/org/app/manifests/") && r.Method == http.MethodHead:
			d, ok := digests[strings.TrimPrefix(r.URL.Path, "/v2/org/app/manifests/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Docker-Content-Digest", d)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc := httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second})
	return New(hc), strings.TrimPrefix(srv.URL, "https://"), &reqs
}

func TestResolveFindsTheTagOfTheDigest(t *testing.T) {
	c, host, reqs := fakeRegistry(t, map[string]string{"1.3.0": "sha256:new", "1.2.0": "sha256:run", "1.0.0": "sha256:old", "latest": "sha256:run"})
	keep := func(tag string) bool { return tag != "latest" && tag != "nightly" && !strings.Contains(tag, "-") }
	less := func(a, b string) bool { return a > b }
	tag, err := c.Resolve(t.Context(), host+"/org/app", "sha256:run", keep, less, 10)
	if err != nil || tag != "1.2.0" {
		t.Fatalf("tag %q %v", tag, err)
	}
	for _, r := range *reqs {
		if !strings.HasPrefix(r, "GET ") && !strings.HasPrefix(r, "HEAD ") {
			t.Errorf("non-read request %s", r)
		}
		if strings.HasPrefix(r, "GET /v2/org/app/manifests/") {
			t.Errorf("manifest fetched with GET (counts as a pull): %s", r)
		}
	}
	// The newest tags are asked first, at most limit of them.
	tag, err = c.Resolve(t.Context(), host+"/org/app", "sha256:old", keep, less, 2)
	if err != nil || tag != "" {
		t.Errorf("limit not kept: %q %v", tag, err)
	}
}

func TestDigestAsksWithHead(t *testing.T) {
	c, host, reqs := fakeRegistry(t, map[string]string{"1.3.0": "sha256:new"})
	d, err := c.Digest(t.Context(), host+"/org/app", "1.3.0")
	if err != nil || d != "sha256:new" {
		t.Fatalf("digest %q %v", d, err)
	}
	for _, r := range *reqs {
		if strings.HasPrefix(r, "GET /v2/org/app/manifests/") {
			t.Errorf("manifest fetched with GET (counts as a pull): %s", r)
		}
	}
	if _, err := c.Digest(t.Context(), host+"/org/app", "9.9.9"); err == nil {
		t.Error("a missing tag resolved")
	}
}

func TestAllTagsReportsACutList(t *testing.T) {
	c, host, _ := fakeRegistry(t, nil)
	tags, complete, err := c.AllTags(t.Context(), host+"/org/app")
	if err != nil || !complete || len(tags) != 6 {
		t.Fatalf("%v %v %v", tags, complete, err)
	}
	// A registry that always has another page is cut at maxPages.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `</v2/org/app/tags/list?n=1000&last=x>; rel="next"`)
		_, _ = io.WriteString(w, `{"tags":["1.0.0"]}`)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c = New(httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second}))
	tags, complete, err = c.AllTags(t.Context(), strings.TrimPrefix(srv.URL, "https://")+"/org/app")
	if err != nil || complete || len(tags) != maxPages {
		t.Fatalf("%d tags, complete %v, %v", len(tags), complete, err)
	}
	// Tags keeps its behaviour: the cut list, no error.
	if tags, err := c.Tags(t.Context(), strings.TrimPrefix(srv.URL, "https://")+"/org/app"); err != nil || len(tags) != maxPages {
		t.Fatalf("Tags: %d %v", len(tags), err)
	}
}

func TestNextLinkStaysOnRegistry(t *testing.T) {
	if p := nextLink(`<https://evil.example/v2/x/tags/list?last=a>; rel="next"`); p != "" {
		t.Errorf("followed a foreign link: %q", p)
	}
	if p := nextLink(`</v2/x/tags/list?last=a&n=1000>; rel="next"`); p != "/v2/x/tags/list?last=a&n=1000" {
		t.Errorf("link %q", p)
	}
}

func TestJobs(t *testing.T) {
	now := time.Now()
	ws := []inventory.Workload{
		{ID: "a", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "vaultwarden/server:latest", RepoDigests: []string{"vaultwarden/server@sha256:aaa"}}},
		{ID: "b", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "vaultwarden/server:1.30.0", RepoDigests: []string{"vaultwarden/server@sha256:bbb"}}},
		{ID: "c", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "vaultwarden/server:latest"}},
	}
	ids := map[string]identify.Result{
		"a": {AppID: "vaultwarden", Confidence: identify.Exact},
		"b": {AppID: "vaultwarden", Confidence: identify.Exact, Version: "1.30.0", Trust: identify.Confirmed},
		"c": {AppID: "vaultwarden", Confidence: identify.Exact},
	}
	jobs := Jobs(mustCatalog(t), ws, ids, nil, now)
	if len(jobs) != 1 || jobs[0].Digest != "sha256:aaa" || jobs[0].Repository != "docker.io/vaultwarden/server" {
		t.Fatalf("jobs %+v", jobs)
	}
	// A recent miss is not asked again; an old one is.
	known := map[string]store.ImageTag{"docker.io/vaultwarden/server@sha256:aaa": {Checked: now.Add(-time.Hour)}}
	if len(Jobs(mustCatalog(t), ws, ids, known, now)) != 0 {
		t.Error("recent miss asked again")
	}
	known["docker.io/vaultwarden/server@sha256:aaa"] = store.ImageTag{Checked: now.Add(-48 * time.Hour)}
	if len(Jobs(mustCatalog(t), ws, ids, known, now)) != 1 {
		t.Error("old miss not retried")
	}
}

func mustCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	app := &catalog.App{ID: "vaultwarden", Name: "Vaultwarden", Version: catalog.VersionSpec{Scheme: "semver"}}
	c, err := (&catalog.Catalog{}).WithDerived([]*catalog.App{{ID: app.ID, Name: app.Name, Version: app.Version, OCISource: []string{"https://github.com/dani-garcia/vaultwarden"}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// An image a generated entry knows only through its source label was
// identified with the derived entry's chain; the resolver keeps and orders
// its tags the same way, not with the entry's checked tag rule, and so do
// the tag lists for update suggestions.
func TestJobsReadUncheckedImageAsDerived(t *testing.T) {
	gen := `id: gh-acme-widget
name: widget
homepage: https://github.com/acme/widget
images:
  - match: ghcr.io/acme/widget
oci_source:
  - https://github.com/acme/widget
version:
  scheme: semver
  sources:
    - label: org.opencontainers.image.version
    - tag: '^v?(?P<v>\d+\.\d+\.\d+)$'
advisories:
  coverage: partial
  github_repos: [acme/widget]
maintainers_of_entry: [generator]
verified: "2026-11-12"
`
	cat, err := catalog.BuildLayered(nil, catalog.OriginBuiltin, []catalog.Entry{{Name: "gh-acme-widget.yaml", Data: gen}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	src := map[string]string{identify.LabelOCISource: "https://github.com/acme/widget"}
	ws := []inventory.Workload{
		{ID: "own", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "ghcr.io/acme/widget:latest", RepoDigests: []string{"ghcr.io/acme/widget@sha256:aaa"}}},
		{ID: "label", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "docker.io/acme/widget-worker:latest", ImageLabels: src, RepoDigests: []string{"docker.io/acme/widget-worker@sha256:bbb"}}},
	}
	ids := map[string]identify.Result{}
	for _, w := range ws {
		ids[w.ID] = identify.Identify(cat, w)
	}
	jobs := Jobs(cat, ws, ids, nil, time.Now())
	if len(jobs) != 2 {
		t.Fatalf("jobs %+v", jobs)
	}
	for _, j := range jobs {
		keep, less := TagOrder(j.App, j.Repository)
		ranked := strings.Join(Rank([]string{"1.2.0", "1.2.0.7", "latest", "1.10.0"}, keep, less), ",")
		want := "1.10.0,1.2.0"
		if j.Repository == "docker.io/acme/widget-worker" {
			// The derived chain's default pattern reads four parts.
			want = "1.10.0,1.2.0.7,1.2.0"
		}
		if ranked != want {
			t.Errorf("%s: ranked %s, want %s", j.Repository, ranked, want)
		}
	}
	findings := []store.Finding{{WorkloadID: "label", MatchState: "affected"}}
	tl := TagListJobs(cat, ws, ids, findings, nil, time.Now())
	if len(tl) != 1 || tl[0].App.Version.Sources != nil {
		t.Errorf("tag list jobs %+v", tl)
	}
}
