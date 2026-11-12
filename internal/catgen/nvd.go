// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/httpx"
)

// NVD asks NVD's CPE API (services.nvd.nist.gov/rest/json/cpes/2.0). Its
// answers are not cached: the generator asks only for candidates that
// passed C1 to C4 and records what it saw in the candidate's inputs hash.
type NVD struct {
	HTTP *httpx.Client
	// APIKey raises the rate limit; optional.
	APIKey string
	// BaseURL overrides the API endpoint (tests).
	BaseURL string
	// Pause between requests; default 6 s without a key and 0.6 s with
	// one, NVD's published limits of 5 and 50 requests per 30 s.
	Pause time.Duration

	mu   sync.Mutex
	last time.Time
}

// SearchProducts implements NVDAPI.
func (n *NVD) SearchProducts(ctx context.Context, keyword string) ([]CPEProduct, error) {
	return n.get(ctx, url.Values{"keywordSearch": {keyword}})
}

// Products implements NVDAPI.
func (n *NVD) Products(ctx context.Context, cpe string) ([]CPEProduct, error) {
	return n.get(ctx, url.Values{"cpeMatchString": {cpe}})
}

func (n *NVD) get(ctx context.Context, q url.Values) ([]CPEProduct, error) {
	if err := n.wait(ctx); err != nil {
		return nil, err
	}
	base := n.BaseURL
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	}
	q.Set("resultsPerPage", "200")
	header := http.Header{}
	if n.APIKey != "" {
		header.Set("apiKey", n.APIKey)
	}
	resp, err := n.HTTP.Do(ctx, httpx.Request{URL: base + "?" + q.Encode(), Header: header, MaxBytes: 16 << 20})
	if err != nil {
		return nil, fmt.Errorf("nvd cpe: %w", err)
	}
	var doc struct {
		Products []struct {
			CPE struct {
				Name       string `json:"cpeName"`
				Deprecated bool   `json:"deprecated"`
				Refs       []struct {
					Ref string `json:"ref"`
				} `json:"refs"`
			} `json:"cpe"`
		} `json:"products"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return nil, fmt.Errorf("nvd cpe: %w", err)
	}
	out := make([]CPEProduct, 0, len(doc.Products))
	for _, p := range doc.Products {
		cp := CPEProduct{Name: p.CPE.Name, Deprecated: p.CPE.Deprecated}
		for _, r := range p.CPE.Refs {
			cp.Refs = append(cp.Refs, r.Ref)
		}
		out = append(out, cp)
	}
	return out, nil
}

// wait keeps the pause since the previous request.
func (n *NVD) wait(ctx context.Context) error {
	pause := n.Pause
	if pause == 0 {
		pause = 6 * time.Second
		if n.APIKey != "" {
			pause = 600 * time.Millisecond
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if d := time.Until(n.last.Add(pause)); !n.last.IsZero() && d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	n.last = time.Now()
	return nil
}
