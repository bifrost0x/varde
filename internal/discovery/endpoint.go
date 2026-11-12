// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// VersionEndpoint is a documented, unauthenticated endpoint where an app
// reports its own version, as defined in the catalog.
type VersionEndpoint struct {
	// Path is requested with GET, without credentials.
	Path string
	// VersionPointer is the JSON pointer (RFC 6901) of the version; empty
	// when the whole response is a JSON string.
	VersionPointer string
	// VersionPattern, if set, extracts the version from the field with the
	// named group v ("0.64.2 (abc123)" -> "0.64.2").
	VersionPattern *regexp.Regexp
	// Expect maps JSON pointers to values the response must hold; they
	// prove it comes from the app and not from something else on the
	// port. When CheckPath is set they are read from that response.
	Expect    map[string]string
	CheckPath string
}

// endpointBodyLimit bounds what Varde reads from one response.
const endpointBodyLimit = 64 << 10

// ErrNotThisApp is returned when the response does not prove it comes from
// the app.
var ErrNotThisApp = errors.New("the response does not come from this app")

// ReadVersion requests the endpoint on target (host:port) and returns the
// version the app reports. It sends GET requests without credentials,
// follows no redirects and reads at most 64 KiB per response. TLS
// certificates are not verified, as for the scan: homelab services use
// self-signed ones and nothing secret is sent. A version is returned only
// when every Expect field matches.
func ReadVersion(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), target string, tlsOn bool, ep VersionEndpoint) (string, error) {
	if !strings.HasPrefix(ep.Path, "/") || len(ep.Expect) == 0 {
		return "", errors.New("incomplete version endpoint")
	}
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dial,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // public endpoint, nothing secret sent; see above and docs/threat-model.md
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 4 * time.Second,
			TLSHandshakeTimeout:   4 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	get := func(path string) (any, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "varde-discovery")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s answered %d", path, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, endpointBodyLimit+1))
		if err != nil {
			return nil, err
		}
		if len(body) > endpointBodyLimit {
			return nil, errors.New("response too large")
		}
		var doc any
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, ErrNotThisApp
		}
		return doc, nil
	}
	checkPath := ep.Path
	if ep.CheckPath != "" {
		checkPath = ep.CheckPath
	}
	check, err := get(checkPath)
	if err != nil {
		return "", err
	}
	for field, want := range ep.Expect {
		if got, ok := jsonString(check, field); !ok || got != want {
			return "", ErrNotThisApp
		}
	}
	doc := check
	if ep.CheckPath != "" {
		if doc, err = get(ep.Path); err != nil {
			return "", err
		}
	}
	v, ok := jsonString(doc, ep.VersionPointer)
	if !ok || v == "" || len(v) > 128 {
		return "", ErrNotThisApp
	}
	if ep.VersionPattern != nil {
		m := ep.VersionPattern.FindStringSubmatch(v)
		if m == nil {
			return "", ErrNotThisApp
		}
		v = m[ep.VersionPattern.SubexpIndex("v")]
	}
	return v, nil
}

// jsonString returns the string at a JSON pointer (RFC 6901, objects
// only); an empty pointer is the document itself.
func jsonString(doc any, pointer string) (string, bool) {
	cur := doc
	if pointer != "" {
		if !strings.HasPrefix(pointer, "/") {
			return "", false
		}
		for _, part := range strings.Split(pointer[1:], "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			m, ok := cur.(map[string]any)
			if !ok {
				return "", false
			}
			if cur, ok = m[part]; !ok {
				return "", false
			}
		}
	}
	s, ok := cur.(string)
	return s, ok
}
