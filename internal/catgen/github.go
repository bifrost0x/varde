// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bifrost0x/varde/internal/httpx"
)

// GitHub lists releases through the REST API with the hardened HTTP client.
// A conditional request answered 304 does not count against an
// authenticated client's rate limit, so the generator can ask after every
// shipped entry's releases each build.
type GitHub struct {
	HTTP *httpx.Client
	// Token raises the rate limit; optional.
	Token string
	// BaseURL overrides https://api.github.com (tests).
	BaseURL string
}

// Releases implements GitHubAPI. It reads the first page (the newest 100
// releases), which is all the checks look at.
func (g *GitHub) Releases(ctx context.Context, repo, etag string) ([]Release, string, bool, error) {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return nil, "", false, fmt.Errorf("github: invalid repository %q", repo)
	}
	base := g.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	header := http.Header{
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
	}
	if g.Token != "" {
		header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.HTTP.Do(ctx, httpx.Request{
		URL:    fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100", base, url.PathEscape(owner), url.PathEscape(name)),
		Header: header, ETag: etag, MaxBytes: 16 << 20,
	})
	if err != nil {
		return nil, "", false, fmt.Errorf("github releases of %s: %w", repo, err)
	}
	if resp.NotModified {
		return nil, etag, true, nil
	}
	var items []struct {
		TagName    string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
		Draft      bool   `json:"draft"`
	}
	if err := json.Unmarshal(resp.Body, &items); err != nil {
		return nil, "", false, fmt.Errorf("github releases of %s: %w", repo, err)
	}
	out := make([]Release, 0, len(items))
	for _, it := range items {
		out = append(out, Release{Tag: it.TagName, Prerelease: it.Prerelease, Draft: it.Draft})
	}
	return out, resp.ETag, false, nil
}
