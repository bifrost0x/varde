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
