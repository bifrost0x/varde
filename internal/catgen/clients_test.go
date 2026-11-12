// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/httpx"
)

func tlsServer(t *testing.T, h http.HandlerFunc) (*httpx.Client, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second}), srv.URL
}

func TestGitHubReleasesConditional(t *testing.T) {
	hc, base := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget/releases" || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("If-None-Match") == `"e1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"e1"`)
		_, _ = io.WriteString(w, `[{"tag_name":"v1.2.0"},{"tag_name":"v1.3.0-rc.1","prerelease":true},{"tag_name":"v9","draft":true}]`)
	})
	g := &GitHub{HTTP: hc, Token: "tok", BaseURL: base}
	rels, etag, nm, err := g.Releases(t.Context(), "acme/widget", "")
	if err != nil || nm || etag != `"e1"` || len(rels) != 3 || rels[0].Tag != "v1.2.0" || !rels[1].Prerelease || !rels[2].Draft {
		t.Fatalf("%+v %q %v %v", rels, etag, nm, err)
	}
	if rels, _, nm, err = g.Releases(t.Context(), "acme/widget", `"e1"`); err != nil || !nm || rels != nil {
		t.Fatalf("conditional: %+v %v %v", rels, nm, err)
	}
	if _, _, _, err = g.Releases(t.Context(), "acme/gone", ""); !notFound(err) {
		t.Errorf("missing repository: %v", err)
	}
	if _, _, _, err = g.Releases(t.Context(), "acme/../x/y", ""); err == nil {
		t.Error("a path in the repository name was accepted")
	}
}

func TestNVDProducts(t *testing.T) {
	var queries []string
	hc, base := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		_, _ = io.WriteString(w, `{"products":[{"cpe":{"cpeName":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*","deprecated":false,"refs":[{"ref":"https://github.com/acme/widget"}]}}]}`)
	})
	n := &NVD{HTTP: hc, BaseURL: base, Pause: time.Millisecond}
	ps, err := n.SearchProducts(t.Context(), "widget")
	if err != nil || len(ps) != 1 || ps[0].Name != "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*" || len(ps[0].Refs) != 1 {
		t.Fatalf("%+v %v", ps, err)
	}
	if _, err := n.Products(t.Context(), "cpe:2.3:a:acme:widget"); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || queries[0] != "keywordSearch=widget&resultsPerPage=200" || queries[1] != "cpeMatchString=cpe%3A2.3%3Aa%3Aacme%3Awidget&resultsPerPage=200" {
		t.Errorf("queries %v", queries)
	}
}

func TestHubPullCount(t *testing.T) {
	hc, base := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/repositories/acme/widget/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"name":"widget","pull_count":12345}`)
	})
	h := &Hub{HTTP: hc, BaseURL: base}
	if n, err := h.PullCount(t.Context(), "acme/widget"); err != nil || n != 12345 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := h.PullCount(t.Context(), "acme/gone"); !notFound(err) {
		t.Errorf("missing repository: %v", err)
	}
}
