// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func endpointServer(t *testing.T, routes map[string]string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s with credentials %q", r.Method, r.Header.Get("Authorization"))
		}
		body, ok := routes[r.URL.RequestURI()]
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
		case strings.HasPrefix(body, "redirect:"):
			http.Redirect(w, r, strings.TrimPrefix(body, "redirect:"), http.StatusFound)
		default:
			_, _ = io.WriteString(w, body)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

var plain = func(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func TestReadVersion(t *testing.T) {
	target := endpointServer(t, map[string]string{
		"/System/Info/Public":                    `{"Version":"12.4.0","ProductName":"Jellyfin Server","Id":"x"}`,
		"/other":                                 `{"Version":"1.0.0","ProductName":"Something Else"}`,
		"/api/config":                            `{"version":"2026.6.0","server":{"name":"Vaultwarden"}}`,
		"/api/version":                           `"1.37.5"`,
		"/rest/getOpenSubsonicExtensions?f=json": `{"subsonic-response":{"type":"navidrome","serverVersion":"0.64.2 (abc1234)"}}`,
		"/html":                                  `<html>Jellyfin Server</html>`,
		"/moved":                                 `redirect:/System/Info/Public`,
		"/big":                                   `{"ProductName":"Jellyfin Server","Version":"1.0.0","pad":"` + strings.Repeat("x", 70<<10) + `"}`,
	})
	jellyfin := VersionEndpoint{Path: "/System/Info/Public", VersionPointer: "/Version", Expect: map[string]string{"/ProductName": "Jellyfin Server"}}
	if v, err := ReadVersion(t.Context(), plain, target, false, jellyfin); err != nil || v != "12.4.0" {
		t.Errorf("jellyfin: %q %v", v, err)
	}
	vw := VersionEndpoint{CheckPath: "/api/config", Expect: map[string]string{"/server/name": "Vaultwarden"}, Path: "/api/version",
		VersionPattern: regexp.MustCompile(`^(?P<v>\d+\.\d+\.\d+)$`)}
	if v, err := ReadVersion(t.Context(), plain, target, false, vw); err != nil || v != "1.37.5" {
		t.Errorf("vaultwarden: %q %v", v, err)
	}
	nd := VersionEndpoint{Path: "/rest/getOpenSubsonicExtensions?f=json", VersionPointer: "/subsonic-response/serverVersion",
		VersionPattern: regexp.MustCompile(`^(?P<v>\d+\.\d+\.\d+) `), Expect: map[string]string{"/subsonic-response/type": "navidrome"}}
	if v, err := ReadVersion(t.Context(), plain, target, false, nd); err != nil || v != "0.64.2" {
		t.Errorf("navidrome: %q %v", v, err)
	}
	// Something else on the port, a page that only mentions the name, a
	// redirect and an oversized answer never yield a version.
	for _, path := range []string{"/other", "/html", "/moved", "/big", "/missing"} {
		ep := jellyfin
		ep.Path = path
		if v, err := ReadVersion(t.Context(), plain, target, false, ep); err == nil {
			t.Errorf("%s: version %q accepted", path, v)
		}
	}
	if _, err := ReadVersion(t.Context(), plain, target, false, VersionEndpoint{Path: "/System/Info/Public", VersionPointer: "/Version"}); err == nil {
		t.Error("endpoint without expect fields accepted")
	}
	wrong := jellyfin
	wrong.Path = "/other"
	if _, err := ReadVersion(t.Context(), plain, target, false, wrong); !errors.Is(err, ErrNotThisApp) {
		t.Errorf("wrong product: %v", err)
	}
}
