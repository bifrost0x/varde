// SPDX-License-Identifier: Apache-2.0

// Package httpx is the only way Varde talks to the internet. It enforces
// HTTPS, timeouts, response size limits, same-host redirects and an
// optional host allowlist, sends a fixed User-Agent without user data, and
// supports conditional requests and rate-limit reporting.
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
)

const (
	defaultTimeout  = 60 * time.Second
	defaultMaxBytes = 16 << 20
	maxRedirects    = 3
)

// Options configures a Client.
type Options struct {
	// AllowHosts, when not empty, restricts requests to these hosts
	// (exact match, case-insensitive).
	AllowHosts []string
	// RootCAs replaces the system trust store when set (custom CA bundle,
	// tests).
	RootCAs *x509.CertPool
	// Timeout bounds a whole request including the body (default 60 s).
	Timeout time.Duration
	// AllowHTTP permits plain http URLs. Only for endpoints the operator
	// configured explicitly (self-hosted notification services in the LAN);
	// never for advisory sources.
	AllowHTTP bool
	// AllowInternalRedirects lets Open follow a redirect to an IP literal or
	// localhost. Only for tests, whose servers have no DNS name.
	AllowInternalRedirects bool
}

// Client is a hardened HTTP client.
type Client struct {
	hc            *http.Client
	allow         map[string]bool
	timeout       time.Duration
	allowHTTP     bool
	allowInternal bool
}

// ErrHostNotAllowed is returned for hosts outside the allowlist.
var ErrHostNotAllowed = errors.New("httpx: host not in egress allowlist")

// New returns a Client.
func New(o Options) *Client {
	c := &Client{timeout: o.Timeout, allowHTTP: o.AllowHTTP, allowInternal: o.AllowInternalRedirects}
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}
	if len(o.AllowHosts) > 0 {
		c.allow = map[string]bool{}
		for _, h := range o.AllowHosts {
			c.allow[strings.ToLower(strings.TrimSpace(h))] = true
		}
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	c.hc = &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("httpx: too many redirects")
			}
			if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				return fmt.Errorf("httpx: refusing redirect from %s to %s", via[0].URL.Host, req.URL.Host)
			}
			return nil
		},
	}
	return c
}

// Request describes one outbound request.
type Request struct {
	Method string // GET (default), HEAD or POST
	URL    string
	Body   []byte
	Header http.Header
	// ETag and LastModified make the request conditional.
	ETag         string
	LastModified string
	// MaxBytes caps the response body (default 16 MB).
	MaxBytes int64
}

// Response is a fully read response.
type Response struct {
	Status       int
	Header       http.Header
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
	RateLimit    RateLimit
}

// RateLimit is what the server said about its limits; zero values mean
// "not stated".
type RateLimit struct {
	Remaining  int // -1 when unknown
	Reset      time.Time
	RetryAfter time.Duration
}

// StatusError is a non-2xx, non-304 response.
type StatusError struct {
	URL       string
	Status    int
	RateLimit RateLimit
	// Header holds the response headers, for example an authentication
	// challenge.
	Header http.Header
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("httpx: %s: status %d", e.URL, e.Status)
}

// RateLimited reports whether the server refused because of rate limits.
func (e *StatusError) RateLimited() bool {
	return e.Status == http.StatusTooManyRequests ||
		(e.Status == http.StatusForbidden && (e.RateLimit.Remaining == 0 || e.RateLimit.RetryAfter > 0))
}

// Do performs r and reads the body within the size limit.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, fmt.Errorf("httpx: parse url: %w", err)
	}
	if u.Scheme != "https" && (!c.allowHTTP || u.Scheme != "http") {
		return nil, fmt.Errorf("httpx: refusing non-https url %s", u.Redacted())
	}
	if c.allow != nil && !c.allow[strings.ToLower(u.Hostname())] {
		return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, u.Hostname())
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodPost {
		return nil, fmt.Errorf("httpx: method %s not supported", method)
	}
	limit := r.MaxBytes
	if limit <= 0 {
		limit = defaultMaxBytes
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var body io.Reader
	if r.Body != nil {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("httpx: build request: %w", err)
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", buildinfo.UserAgent())
	if r.ETag != "" {
		req.Header.Set("If-None-Match", r.ETag)
	}
	if r.LastModified != "" {
		req.Header.Set("If-Modified-Since", r.LastModified)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpx: %s %s: %w", method, u.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	out := &Response{
		Status:       resp.StatusCode,
		Header:       resp.Header,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		RateLimit:    parseRateLimit(resp.Header, time.Now()),
	}
	switch {
	case resp.StatusCode == http.StatusNotModified:
		out.NotModified = true
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return out, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, &StatusError{URL: u.Redacted(), Status: resp.StatusCode, RateLimit: out.RateLimit, Header: resp.Header}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("httpx: read %s: %w", u.Redacted(), err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("httpx: %s: response larger than %d bytes", u.Redacted(), limit)
	}
	out.Body = b
	return out, nil
}

func parseRateLimit(h http.Header, now time.Time) RateLimit {
	rl := RateLimit{Remaining: -1}
	if v := h.Get("X-RateLimit-Remaining"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rl.Remaining = n
		}
	}
	if v := h.Get("X-RateLimit-Reset"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			rl.Reset = time.Unix(n, 0)
		}
	}
	if v := h.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			rl.RetryAfter = time.Duration(n) * time.Second
		} else if t, err := http.ParseTime(v); err == nil && t.After(now) {
			rl.RetryAfter = t.Sub(now)
		}
	}
	return rl
}

// NextLink returns the rel="next" URL of an RFC 8288 Link header.
func NextLink(h http.Header) string {
	for _, part := range strings.Split(h.Get("Link"), ",") {
		segs := strings.Split(part, ";")
		if len(segs) < 2 {
			continue
		}
		target := strings.TrimSpace(segs[0])
		for _, p := range segs[1:] {
			if strings.TrimSpace(p) == `rel="next"` && strings.HasPrefix(target, "<") && strings.HasSuffix(target, ">") {
				return target[1 : len(target)-1]
			}
		}
	}
	return ""
}

// Stream is a response whose body is read by the caller, for downloads too
// large to hold in memory.
type Stream struct {
	Status    int
	Header    http.Header
	Body      io.ReadCloser
	RateLimit RateLimit
}

// Open performs a GET and returns the body unread. It has no total timeout
// (the caller bounds a download with ctx and the transport's header timeout),
// and unlike Do it follows redirects to other hosts, as registries answer
// blob requests with a redirect to a CDN. The scheme must stay https, the
// allowlist still applies to every hop, and an Authorization header is never
// carried to another host.
func (c *Client) Open(ctx context.Context, r Request) (*Stream, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, fmt.Errorf("httpx: parse url: %w", err)
	}
	if u.Scheme != "https" && (!c.allowHTTP || u.Scheme != "http") {
		return nil, fmt.Errorf("httpx: refusing non-https url %s", u.Redacted())
	}
	if !c.hostAllowed(u.Hostname()) {
		return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, u.Hostname())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("httpx: build request: %w", err)
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("User-Agent", buildinfo.UserAgent())
	hc := *c.hc
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("httpx: too many redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("httpx: refusing redirect to %s", req.URL.Redacted())
		}
		if !c.hostAllowed(req.URL.Hostname()) {
			return fmt.Errorf("%w: %s", ErrHostNotAllowed, req.URL.Hostname())
		}
		if !strings.EqualFold(req.URL.Host, via[0].URL.Host) && !c.allowInternal && internalHost(req.URL.Hostname()) {
			// A registry must not make Varde fetch from internal services.
			return fmt.Errorf("httpx: refusing redirect to internal host %s", req.URL.Hostname())
		}
		if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			req.Header.Del("Authorization")
		}
		return nil
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpx: GET %s: %w", u.Redacted(), err)
	}
	rl := parseRateLimit(resp.Header, time.Now())
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		return nil, &StatusError{URL: u.Redacted(), Status: resp.StatusCode, RateLimit: rl, Header: resp.Header}
	}
	return &Stream{Status: resp.StatusCode, Header: resp.Header, Body: resp.Body, RateLimit: rl}, nil
}

func (c *Client) hostAllowed(host string) bool {
	return c.allow == nil || c.allow[strings.ToLower(host)]
}

// internalHost reports IP literals and localhost names; a CDN is always
// named by a DNS name.
func internalHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	return net.ParseIP(h) != nil || h == "localhost" || strings.HasSuffix(h, ".localhost")
}
