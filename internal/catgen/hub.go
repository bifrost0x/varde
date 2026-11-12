// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bifrost0x/varde/internal/httpx"
)

// Hub reads repository metadata from Docker Hub's web API. That endpoint is
// not a manifest pull and does not count against the pull limit.
type Hub struct {
	HTTP *httpx.Client
	// BaseURL overrides https://hub.docker.com (tests).
	BaseURL string
}

// PullCount implements HubAPI.
func (h *Hub) PullCount(ctx context.Context, repository string) (int64, error) {
	ns, name, ok := strings.Cut(repository, "/")
	if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
		return 0, fmt.Errorf("docker hub: invalid repository %q", repository)
	}
	base := h.BaseURL
	if base == "" {
		base = "https://hub.docker.com"
	}
	resp, err := h.HTTP.Do(ctx, httpx.Request{URL: base + "/v2/repositories/" + ns + "/" + name + "/", MaxBytes: 1 << 20})
	if err != nil {
		return 0, fmt.Errorf("docker hub %s: %w", repository, err)
	}
	var doc struct {
		PullCount *int64 `json:"pull_count"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return 0, fmt.Errorf("docker hub %s: %w", repository, err)
	}
	if doc.PullCount == nil {
		return 0, fmt.Errorf("docker hub %s: no pull count", repository)
	}
	return *doc.PullCount, nil
}
