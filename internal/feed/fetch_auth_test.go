// SPDX-License-Identifier: Apache-2.0

package feed_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/httpx"
)

func TestFetcherAuthorization(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc := httpx.New(httpx.Options{RootCAs: pool})

	value := ""
	for _, tc := range []struct {
		name string
		auth func() string
		set  string
		want string
	}{
		{"no function", nil, "", ""},
		{"empty value", func() string { return value }, "", ""},
		{"license", func() string { return value }, "Varde-License abc", "Varde-License abc"},
		{"switched off again", func() string { return value }, "", ""},
	} {
		value = tc.set
		f, err := feed.NewFetcher(srv.URL, hc, tc.auth)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := f.Get(context.Background(), "v1/manifest.json", "", 1024); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		mu.Lock()
		got := seen[len(seen)-1]
		mu.Unlock()
		if got != tc.want {
			t.Errorf("%s: Authorization = %q, want %q", tc.name, got, tc.want)
		}
	}
}
