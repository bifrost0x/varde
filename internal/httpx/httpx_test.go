// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func tlsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, New(Options{RootCAs: pool, Timeout: 5 * time.Second})
}

func TestGetConditionalAndHeaders(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.UserAgent(), "varde/") {
			t.Errorf("user agent %q", r.UserAgent())
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("X-RateLimit-Remaining", "41")
		w.Header().Set("X-RateLimit-Reset", "1794178806")
		w.Header().Set("Link", `<https://example.test/next?after=abc>; rel="next", <https://example.test/first>; rel="first"`)
		_, _ = w.Write([]byte("hello"))
	})
	resp, err := c.Do(t.Context(), Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "hello" || resp.ETag != `"v1"` || resp.RateLimit.Remaining != 41 || resp.RateLimit.Reset.Unix() != 1794178806 {
		t.Fatalf("response: %+v", resp)
	}
	if NextLink(resp.Header) != "https://example.test/next?after=abc" {
		t.Errorf("next link %q", NextLink(resp.Header))
	}
	resp, err = c.Do(t.Context(), Request{URL: srv.URL, ETag: `"v1"`})
	if err != nil || !resp.NotModified || resp.Body != nil {
		t.Fatalf("conditional: %+v %v", resp, err)
	}
}

func TestRefusals(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 100))) })

	if _, err := c.Do(t.Context(), Request{URL: strings.Replace(srv.URL, "https://", "http://", 1)}); err == nil {
		t.Error("plain http accepted")
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer plain.Close()
	if resp, err := New(Options{AllowHTTP: true}).Do(t.Context(), Request{URL: plain.URL}); err != nil || string(resp.Body) != "ok" {
		t.Errorf("explicit AllowHTTP: %v", err)
	}
	if _, err := New(Options{AllowHTTP: true}).Do(t.Context(), Request{URL: "ftp://example.test/x"}); err == nil {
		t.Error("ftp accepted")
	}
	if _, err := c.Do(t.Context(), Request{URL: srv.URL, MaxBytes: 99}); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("size limit: %v", err)
	}
	if _, err := c.Do(t.Context(), Request{URL: srv.URL, MaxBytes: 100}); err != nil {
		t.Errorf("exact limit: %v", err)
	}
	if _, err := c.Do(t.Context(), Request{URL: srv.URL, Method: http.MethodDelete}); err == nil {
		t.Error("DELETE accepted")
	}

	u, _ := url.Parse(srv.URL)
	restricted := New(Options{AllowHosts: []string{"api.github.com"}, RootCAs: c.hc.Transport.(*http.Transport).TLSClientConfig.RootCAs})
	if _, err := restricted.Do(t.Context(), Request{URL: srv.URL}); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("allowlist: %v", err)
	}
	allowed := New(Options{AllowHosts: []string{strings.ToUpper(u.Hostname())}, RootCAs: c.hc.Transport.(*http.Transport).TLSClientConfig.RootCAs})
	if _, err := allowed.Do(t.Context(), Request{URL: srv.URL}); err != nil {
		t.Errorf("allowlisted host refused: %v", err)
	}
}

func TestRedirects(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("other")) }))
	defer other.Close()
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, other.URL+"/x", http.StatusFound)
		case "/final":
			_, _ = w.Write([]byte("final"))
		}
	})
	resp, err := c.Do(t.Context(), Request{URL: srv.URL + "/same"})
	if err != nil || string(resp.Body) != "final" {
		t.Fatalf("same-host redirect: %v", err)
	}
	if _, err := c.Do(t.Context(), Request{URL: srv.URL + "/cross"}); err == nil {
		t.Fatal("cross-host redirect followed")
	}
}

func TestStatusErrorsAndRateLimits(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/limited":
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1794178806")
			w.WriteHeader(http.StatusForbidden)
		case "/429":
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	})
	check := func(path string, status int, limited bool) {
		t.Helper()
		_, err := c.Do(t.Context(), Request{URL: srv.URL + path})
		var se *StatusError
		if !errors.As(err, &se) || se.Status != status || se.RateLimited() != limited {
			t.Errorf("%s: %v (limited=%v)", path, err, se != nil && se.RateLimited())
		}
	}
	check("/limited", 403, true)
	check("/429", 429, true)
	check("/forbidden", 403, false)
	check("/5xx", 502, false)

	rl := parseRateLimit(http.Header{"Retry-After": {time.Now().Add(time.Minute).UTC().Format(http.TimeFormat)}}, time.Now())
	if rl.RetryAfter <= 0 || rl.RetryAfter > time.Minute {
		t.Errorf("http-date Retry-After: %v", rl.RetryAfter)
	}
}

func TestOpenFollowsCrossHostHTTPSRedirectWithoutAuthorization(t *testing.T) {
	var got string
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("data"))
	}))
	t.Cleanup(cdn.Close)
	srv, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cdn.URL, http.StatusFound)
	})
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	pool.AddCert(cdn.Certificate())
	// An IP-literal target is refused by default.
	strict := New(Options{RootCAs: pool, Timeout: 5 * time.Second})
	if _, err := strict.Open(t.Context(), Request{URL: srv.URL}); err == nil || !strings.Contains(err.Error(), "internal host") {
		t.Errorf("redirect to an IP literal followed: %v", err)
	}
	c := New(Options{RootCAs: pool, Timeout: 5 * time.Second, AllowInternalRedirects: true})
	st, err := c.Open(t.Context(), Request{URL: srv.URL, Header: http.Header{"Authorization": {"Bearer x"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Body.Close() }()
	if got != "" {
		t.Errorf("authorization sent to the other host: %q", got)
	}

	blocked := New(Options{RootCAs: pool, AllowHosts: []string{"127.0.0.1"}, Timeout: 5 * time.Second})
	if _, err := blocked.Open(t.Context(), Request{URL: "https://example.invalid/x"}); !errors.Is(err, ErrHostNotAllowed) {
		t.Errorf("allowlist ignored: %v", err)
	}
}

func TestOpenRefusesRedirectToHTTP(t *testing.T) {
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://cdn.example/blob", http.StatusFound)
	})
	if _, err := c.Open(t.Context(), Request{URL: srv.URL}); err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Errorf("http redirect followed: %v", err)
	}
}

func TestInternalHost(t *testing.T) {
	for h, want := range map[string]bool{"127.0.0.1": true, "::1": true, "10.0.0.1": true, "localhost": true, "a.localhost": true, "cdn.example.com": false} {
		if internalHost(h) != want {
			t.Errorf("%s: %v", h, !want)
		}
	}
}
