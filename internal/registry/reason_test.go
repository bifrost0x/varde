// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/httpx"
)

// A registry that refuses is never an answer: each refusal has its reason.
func TestReasonOfRegistryFailures(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
		want    string
	}{
		{"rate limited", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }, 0, ReasonRateLimited},
		{"basic authentication only", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			w.WriteHeader(http.StatusUnauthorized)
		}, 0, ReasonCredentials},
		{"forbidden", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }, 0, ReasonCredentials},
		{"tag missing", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, 0, ReasonNotFound},
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }, 0, ReasonUnreachable},
		{"too slow", func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}, 200 * time.Millisecond, ReasonTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(c.handler)
			defer srv.Close()
			pool := x509.NewCertPool()
			pool.AddCert(srv.Certificate())
			timeout := c.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			cl := New(httpx.New(httpx.Options{RootCAs: pool, Timeout: timeout}))
			_, err := cl.Digest(t.Context(), strings.TrimPrefix(srv.URL, "https://")+"/org/app", "latest")
			if err == nil {
				t.Fatal("no error")
			}
			if got := Reason(err); got != c.want {
				t.Errorf("Reason(%v) = %q, want %q", err, got, c.want)
			}
		})
	}
	if Reason(nil) != "" {
		t.Error("a success has a reason")
	}
}

// The bearer flow and a paginated tag list end in a track candidate.
func TestTagsAndDigestForATrack(t *testing.T) {
	c, host, _ := fakeRegistry(t, map[string]string{"1.3.0-alpine": "sha256:new"})
	tags, err := c.Tags(t.Context(), host+"/org/app")
	if err != nil || len(tags) != 6 {
		t.Fatalf("tags %v: %v", tags, err)
	}
	d, err := c.Digest(t.Context(), host+"/org/app", "1.3.0-alpine")
	if err != nil || d != "sha256:new" {
		t.Errorf("digest %q: %v", d, err)
	}
}
