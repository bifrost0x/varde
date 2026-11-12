// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

const eolAPI = "https://endoflife.date"

// EOLStore keeps release lines.
type EOLStore interface {
	RecordEOL(ctx context.Context, product string, releases []store.EOLRelease, now time.Time) error
}

// EOL reads the release lines and their end of life from endoflife.date
// for apps whose catalog entry names a product (catalog eol). Opt-in: the
// requests reveal the products in use (ADR 0029).
type EOL struct {
	Deps
	EOLStore EOLStore
	BaseURL  string
}

// Name implements Source.
func (*EOL) Name() string { return "eol" }

// Refresh implements Source.
func (e *EOL) Refresh(ctx context.Context, apps []*catalog.App) (Result, error) {
	var res Result
	base := e.BaseURL
	if base == "" {
		base = eolAPI
	}
	seen := map[string]bool{}
	for _, app := range apps {
		product := app.EOL
		if product == "" || seen[product] {
			continue
		}
		seen[product] = true
		st, err := e.Store.SourceState(ctx, "eol", product)
		if err != nil {
			return res, err
		}
		now := e.now()
		if !due(st, now) {
			res.Skipped++
			continue
		}
		rel, err := e.fetch(ctx, base, product)
		res.Requests++
		if err != nil {
			_ = recordFailure(ctx, e.Store, st, now, err)
			if isRateLimited(err) {
				return res, ErrRateLimited
			}
			res.Skipped++
			continue
		}
		if err := e.EOLStore.RecordEOL(ctx, product, rel, now); err != nil {
			return res, err
		}
		res.Updated++
		st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(dailyInterval)
		if err := e.Store.PutSourceState(ctx, st); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (e *EOL) fetch(ctx context.Context, base, product string) ([]store.EOLRelease, error) {
	resp, err := e.HTTP.Do(ctx, httpx.Request{URL: base + "/api/v1/products/" + url.PathEscape(product), MaxBytes: 2 << 20})
	if err != nil {
		return nil, err
	}
	var doc struct {
		Result struct {
			Name     string `json:"name"`
			Releases []struct {
				Name    string `json:"name"`
				IsEOL   bool   `json:"isEol"`
				EOLFrom string `json:"eolFrom"`
				Latest  *struct {
					Name string `json:"name"`
				} `json:"latest"`
			} `json:"releases"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", product, err)
	}
	if doc.Result.Name != product {
		return nil, fmt.Errorf("answer for %q does not name it", product)
	}
	out := make([]store.EOLRelease, 0, len(doc.Result.Releases))
	for _, r := range doc.Result.Releases {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			continue
		}
		rel := store.EOLRelease{Name: name, IsEOL: r.IsEOL, EOLFrom: r.EOLFrom}
		if _, err := time.Parse(time.DateOnly, r.EOLFrom); err != nil {
			rel.EOLFrom = ""
		}
		if r.Latest != nil {
			rel.Latest = r.Latest.Name
		}
		out = append(out, rel)
	}
	return out, nil
}

// EOLLine returns the release line of version: the longest line name that
// is a leading part of it ("1.29" for "1.29.8", "2" for "2.11.9").
func EOLLine(releases []store.EOLRelease, version string) (store.EOLRelease, bool) {
	var best store.EOLRelease
	found := false
	for _, r := range releases {
		if version == r.Name || strings.HasPrefix(version, r.Name+".") {
			if !found || len(r.Name) > len(best.Name) {
				best, found = r, true
			}
		}
	}
	return best, found
}
