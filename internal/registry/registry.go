// SPDX-License-Identifier: Apache-2.0

// Package registry asks container registries which tag points to a digest,
// so a container started from a floating tag ("latest") gets the version
// tag the publisher gave the same image. It uses the OCI distribution API
// read-only: anonymously, or with an access token for one configured
// registry. It reads tag lists and HEAD requests for manifests (which Docker
// Hub does not count as pulls), and for the release reader manifests and
// layer blobs.
package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"

	"github.com/bifrost0x/varde/internal/httpx"
)

// manifestTypes are the media types a manifest request accepts, so the
// registry answers with the digest of the index or manifest the tag names.
var manifestTypes = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

const (
	// maxPages and pageSize bound a tag list (Docker Hub lists thousands
	// of tags for popular images).
	maxPages = 10
	pageSize = 1000
)

// Client resolves digests to tags and reads image manifests and layers.
type Client struct {
	http *httpx.Client

	credHost, credUser, credToken string

	mu    sync.Mutex
	usage Usage
}

// Option configures a Client.
type Option func(*Client)

// WithCredentials makes the client authenticate to the token service of one
// registry with a user name and an access token (Docker Hub raises its pull
// limit for authenticated clients). host is the registry as written in an
// image reference ("docker.io"); the credentials are sent only while talking
// to that registry's token service, never to another registry.
func WithCredentials(host, user, token string) Option {
	return func(c *Client) {
		if user == "" || token == "" {
			return
		}
		c.credHost, c.credUser, c.credToken = registryHost(host), user, token
	}
}

// New returns a client using the hardened HTTP client.
func New(hc *httpx.Client, opts ...Option) *Client {
	c := &Client{http: hc}
	for _, o := range opts {
		o(c)
	}
	return c
}

// registryHost maps a registry as written in a reference to its API host.
func registryHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "docker.io" || h == "index.docker.io" {
		return "registry-1.docker.io"
	}
	return h
}

// Usage is what a client has spent so far, so a caller can stay within the
// registry's limits.
type Usage struct {
	// ManifestRequests counts manifest GETs (Docker Hub counts those as
	// pulls); HEAD requests and token requests are not included.
	ManifestRequests int
	// Bytes is the size of response bodies read.
	Bytes int64
	// RateRemaining is the last ratelimit-remaining header seen, verbatim
	// (Docker Hub sends "98;w=21600").
	RateRemaining string
}

// Budget returns the usage so far.
func (c *Client) Budget() Usage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.usage
}

func (c *Client) note(h http.Header, bytes int64, manifest bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if manifest {
		c.usage.ManifestRequests++
	}
	c.usage.Bytes += bytes
	if v := h.Get("RateLimit-Remaining"); v != "" {
		c.usage.RateRemaining = v
	}
}

// endpoint maps a normalised repository ("docker.io/library/nginx",
// "ghcr.io/org/app") to the registry API host and the repository name.
func endpoint(repository string) (host, name string, err error) {
	host, name, ok := strings.Cut(repository, "/")
	if !ok || name == "" || strings.Contains(host, "@") {
		return "", "", fmt.Errorf("registry: not a repository: %q", repository)
	}
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	return host, name, nil
}

// session carries the bearer token of one repository.
type session struct {
	c     *Client
	host  string
	name  string
	token string
}

// withAuth runs call with the session's token and, after one 401 with a
// Bearer challenge, again with a fresh token.
func (s *session) withAuth(ctx context.Context, hdr http.Header, call func(h http.Header) error) error {
	for attempt := 0; attempt < 2; attempt++ {
		h := hdr.Clone()
		if h == nil {
			h = http.Header{}
		}
		if s.token != "" {
			h.Set("Authorization", "Bearer "+s.token)
		}
		err := call(h)
		var se *httpx.StatusError
		if attempt == 0 && errors.As(err, &se) && se.Status == http.StatusUnauthorized && se.Header != nil {
			if terr := s.authenticate(ctx, se.Header.Get("WWW-Authenticate")); terr != nil {
				return terr
			}
			continue
		}
		return err
	}
	return errors.New("registry: authentication failed")
}

func (s *session) do(ctx context.Context, method, path string, hdr http.Header, max int64) (*httpx.Response, error) {
	var resp *httpx.Response
	err := s.withAuth(ctx, hdr, func(h http.Header) error {
		r, err := s.c.http.Do(ctx, httpx.Request{Method: method, URL: "https://" + s.host + path, Header: h, MaxBytes: max})
		var se *httpx.StatusError
		switch {
		case err == nil:
			s.c.note(r.Header, int64(len(r.Body)), method == http.MethodGet && strings.Contains(path, "/manifests/"))
		case errors.As(err, &se):
			s.c.note(se.Header, 0, false)
		}
		resp = r
		return err
	})
	return resp, err
}

// open starts a streamed GET; the registry may redirect to a CDN.
func (s *session) open(ctx context.Context, path string) (*httpx.Stream, error) {
	var st *httpx.Stream
	err := s.withAuth(ctx, nil, func(h http.Header) error {
		r, err := s.c.http.Open(ctx, httpx.Request{URL: "https://" + s.host + path, Header: h})
		var se *httpx.StatusError
		switch {
		case err == nil:
			s.c.note(r.Header, 0, false)
		case errors.As(err, &se):
			s.c.note(se.Header, 0, false)
		}
		st = r
		return err
	})
	return st, err
}

// authenticate follows a Bearer challenge (read scope only), anonymously or,
// for the configured registry, with Basic credentials.
func (s *session) authenticate(ctx context.Context, challenge string) error {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return errors.New("registry: unsupported authentication challenge")
	}
	params := map[string]string{}
	for _, part := range splitChallenge(strings.TrimPrefix(challenge, "Bearer ")) {
		if k, v, ok := strings.Cut(part, "="); ok {
			params[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme != "https" || realm.Host == "" || realm.User != nil {
		return errors.New("registry: invalid token realm")
	}
	if !realmAllowed(s.host, realm.Hostname()) {
		// The realm comes from whoever serves the image; following it to
		// any host would let a registry make Varde call internal services.
		return fmt.Errorf("registry: token realm %s is not part of the registry %s", realm.Hostname(), s.host)
	}
	q := realm.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	// Only pull (read) access is ever requested.
	q.Set("scope", "repository:"+s.name+":pull")
	realm.RawQuery = q.Encode()
	treq := httpx.Request{URL: realm.String(), MaxBytes: 64 << 10}
	if s.c.credUser != "" && strings.EqualFold(s.host, s.c.credHost) {
		// The credentials belong to exactly this registry. The token realm
		// may be another host of the same registrable domain (auth.docker.io
		// for registry-1.docker.io); realmAllowed vetted it above, and httpx
		// refuses redirects to other hosts, so they cannot travel further.
		treq.Header = http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(s.c.credUser+":"+s.c.credToken))}}
	}
	resp, err := s.c.http.Do(ctx, treq)
	if err != nil {
		return fmt.Errorf("registry: token: %w", err)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(resp.Body, &tok); err != nil {
		return fmt.Errorf("registry: token: %w", err)
	}
	s.token = tok.Token
	if s.token == "" {
		s.token = tok.AccessToken
	}
	if s.token == "" {
		return errors.New("registry: no token")
	}
	return nil
}

// splitChallenge splits on commas outside quotes.
func splitChallenge(s string) []string {
	var out []string
	var b strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			b.WriteRune(r)
		case r == ',' && !quoted:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(out, b.String())
}

// Tags lists the tags of a repository, at most maxPages pages.
func (c *Client) Tags(ctx context.Context, repository string) ([]string, error) {
	tags, _, err := c.AllTags(ctx, repository)
	return tags, err
}

// AllTags is Tags that also reports whether the list is complete: false
// when the registry had more pages than maxPages. A caller that draws
// conclusions from the whole list (the catalog generator) must not trust a
// cut one.
func (c *Client) AllTags(ctx context.Context, repository string) ([]string, bool, error) {
	host, name, err := endpoint(repository)
	if err != nil {
		return nil, false, err
	}
	s := &session{c: c, host: host, name: name}
	return s.tags(ctx)
}

func (s *session) tags(ctx context.Context) ([]string, bool, error) {
	var out []string
	path := "/v2/" + s.name + "/tags/list?n=" + fmt.Sprint(pageSize)
	for i := 0; i < maxPages && path != ""; i++ {
		resp, err := s.do(ctx, http.MethodGet, path, nil, 8<<20)
		if err != nil {
			return out, false, err
		}
		var page struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return out, false, fmt.Errorf("registry: tag list: %w", err)
		}
		out = append(out, page.Tags...)
		path = nextLink(resp.Header.Get("Link"))
	}
	return out, path == "", nil
}

// nextLink extracts the path of a Link: <...>; rel="next" header; only
// paths on the same registry are followed.
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start, end := strings.Index(part, "<"), strings.Index(part, ">")
		if start < 0 || end <= start {
			return ""
		}
		u, err := url.Parse(part[start+1 : end])
		if err != nil || u.IsAbs() || !strings.HasPrefix(u.Path, "/v2/") {
			return ""
		}
		return u.RequestURI()
	}
	return ""
}

// Digest returns the digest the registry gives for a tag (HEAD request).
func (s *session) digest(ctx context.Context, tag string) (string, error) {
	resp, err := s.do(ctx, http.MethodHead, "/v2/"+s.name+"/manifests/"+url.PathEscape(tag), http.Header{"Accept": {manifestTypes}}, 1)
	if err != nil {
		return "", err
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if !strings.HasPrefix(d, "sha256:") {
		return "", errors.New("registry: no digest in the answer")
	}
	return d, nil
}

// Digest returns the digest a tag of a repository points to. It asks with
// a HEAD request, which Docker Hub does not count as a pull.
func (c *Client) Digest(ctx context.Context, repository, tag string) (string, error) {
	host, name, err := endpoint(repository)
	if err != nil {
		return "", err
	}
	s := &session{c: c, host: host, name: name}
	return s.digest(ctx, tag)
}

// Match returns the first of the candidate tags (in the given order, best
// first) whose manifest has the digest; at most limit tags are asked. An
// empty tag means none matched.
func (c *Client) Match(ctx context.Context, repository, digest string, candidates []string, limit int) (string, error) {
	host, name, err := endpoint(repository)
	if err != nil {
		return "", err
	}
	s := &session{c: c, host: host, name: name}
	for i, tag := range candidates {
		if i >= limit {
			break
		}
		d, err := s.digest(ctx, tag)
		if err != nil {
			var se *httpx.StatusError
			if errors.As(err, &se) && se.Status == http.StatusNotFound {
				continue
			}
			return "", err
		}
		if d == digest {
			return tag, nil
		}
	}
	return "", nil
}

// Resolve lists the tags, keeps those keep accepts, orders them with less
// (best first) and returns the first whose manifest has the digest.
func (c *Client) Resolve(ctx context.Context, repository, digest string, keep func(tag string) bool, less func(a, b string) bool, limit int) (string, error) {
	tags, err := c.Tags(ctx, repository)
	if err != nil {
		return "", err
	}
	return c.Match(ctx, repository, digest, Rank(tags, keep, less), limit)
}

// Rank returns the tags keep accepts, ordered with less (best first); tags
// less does not order keep the order of the list. These are the candidates
// Resolve asks in turn.
func Rank(tags []string, keep func(tag string) bool, less func(a, b string) bool) []string {
	var cands []string
	for _, t := range tags {
		if keep(t) {
			cands = append(cands, t)
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return less(cands[i], cands[j]) })
	return cands
}

// realmTokenHosts are token services that live on another domain than their
// registry.
var realmTokenHosts = map[string]string{"lscr.io": "ghcr.io"}

// realmAllowed accepts a token realm on the registry's own host or domain
// (registry-1.docker.io and auth.docker.io) or a known token service.
func realmAllowed(registry, realm string) bool {
	registry, realm = strings.ToLower(hostOnly(registry)), strings.ToLower(realm)
	if realm == registry || realmTokenHosts[registry] == realm {
		return true
	}
	if net.ParseIP(realm) != nil || net.ParseIP(registry) != nil {
		return false
	}
	return baseDomain(realm) != "" && baseDomain(realm) == baseDomain(registry)
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// baseDomain is the registrable domain, including private suffix boundaries
// such as github.io. Sharing a public suffix never establishes trust.
func baseDomain(h string) string {
	domain, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return domain
}
