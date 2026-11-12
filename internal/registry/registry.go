// SPDX-License-Identifier: Apache-2.0

// Package registry asks container registries which tag points to a digest,
// so a container started from a floating tag ("latest") gets the version
// tag the publisher gave the same image. It uses the OCI distribution API
// read-only and anonymously: tag lists and HEAD requests for manifests,
// which Docker Hub does not count as pulls.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/httpx"
)

// manifestTypes are the media types a HEAD request accepts, so the
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

// Client resolves digests to tags.
type Client struct {
	http *httpx.Client
}

// New returns a client using the hardened HTTP client.
func New(hc *httpx.Client) *Client { return &Client{http: hc} }

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

func (s *session) do(ctx context.Context, method, path string, hdr http.Header, max int64) (*httpx.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		h := hdr.Clone()
		if h == nil {
			h = http.Header{}
		}
		if s.token != "" {
			h.Set("Authorization", "Bearer "+s.token)
		}
		resp, err := s.c.http.Do(ctx, httpx.Request{Method: method, URL: "https://" + s.host + path, Header: h, MaxBytes: max})
		var se *httpx.StatusError
		if attempt == 0 && errors.As(err, &se) && se.Status == http.StatusUnauthorized && se.Header != nil {
			if terr := s.authenticate(ctx, se.Header.Get("WWW-Authenticate")); terr != nil {
				return nil, terr
			}
			continue
		}
		return resp, err
	}
	return nil, errors.New("registry: authentication failed")
}

// authenticate follows a Bearer challenge anonymously (read scope only).
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
	resp, err := s.c.http.Do(ctx, httpx.Request{URL: realm.String(), MaxBytes: 64 << 10})
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
	host, name, err := endpoint(repository)
	if err != nil {
		return nil, err
	}
	s := &session{c: c, host: host, name: name}
	return s.tags(ctx)
}

func (s *session) tags(ctx context.Context) ([]string, error) {
	var out []string
	path := "/v2/" + s.name + "/tags/list?n=" + fmt.Sprint(pageSize)
	for i := 0; i < maxPages && path != ""; i++ {
		resp, err := s.do(ctx, http.MethodGet, path, nil, 8<<20)
		if err != nil {
			return out, err
		}
		var page struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(resp.Body, &page); err != nil {
			return out, fmt.Errorf("registry: tag list: %w", err)
		}
		out = append(out, page.Tags...)
		path = nextLink(resp.Header.Get("Link"))
	}
	return out, nil
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
	var cands []string
	for _, t := range tags {
		if keep(t) {
			cands = append(cands, t)
		}
	}
	sortTags(cands, less)
	return c.Match(ctx, repository, digest, cands, limit)
}

func sortTags(tags []string, less func(a, b string) bool) {
	sort.SliceStable(tags, func(i, j int) bool { return less(tags[i], tags[j]) })
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

// baseDomain is the last two labels of a host name ("docker.io").
func baseDomain(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
