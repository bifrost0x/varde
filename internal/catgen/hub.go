// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/httpx"
)

// Hub reads repository metadata from Docker Hub's web API. That endpoint is
// not a manifest pull and does not count against the pull limit.
type Hub struct {
	HTTP *httpx.Client
	// BaseURL overrides https://hub.docker.com (tests).
	BaseURL string
	// Pause between requests (default 1 s): the endpoint has a limit of
	// its own, and the first build asks for about a thousand repositories.
	Pause time.Duration

	pace pacer
}

// PullCount implements HubAPI.
func (h *Hub) PullCount(ctx context.Context, repository string) (int64, error) {
	ns, name, ok := strings.Cut(repository, "/")
	if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
		return 0, fmt.Errorf("docker hub: invalid repository %q", repository)
	}
	pause := h.Pause
	if pause == 0 {
		pause = time.Second
	}
	if err := h.pace.wait(ctx, pause); err != nil {
		return 0, err
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
