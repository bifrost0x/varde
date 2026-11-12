// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

const (
	osvAPI = "https://api.osv.dev"
	// osvMaxFetch bounds record downloads per refresh; the rest follows on
	// the next run.
	osvMaxFetch = 300
)

// OSV queries osv.dev for catalog osv_packages. Opt-in: the queries reveal
// package names to a third party.
type OSV struct {
	Deps
	BaseURL string
}

// Name implements Source.
func (*OSV) Name() string { return "osv" }

// Refresh implements Source.
func (o *OSV) Refresh(ctx context.Context, apps []*catalog.App) (Result, error) {
	var res Result
	base := o.BaseURL
	if base == "" {
		base = osvAPI
	}
	fetched := 0
	for _, app := range apps {
		if len(app.Advisories.OSVPackages) == 0 {
			continue
		}
		st, err := o.Store.SourceState(ctx, "osv", app.ID)
		if err != nil {
			return res, err
		}
		now := o.now()
		if !due(st, now) {
			res.Skipped++
			continue
		}

		type query struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
		}
		var body struct {
			Queries []query `json:"queries"`
		}
		for _, p := range app.Advisories.OSVPackages {
			var q query
			q.Package.Ecosystem, q.Package.Name = p.Ecosystem, p.Name
			body.Queries = append(body.Queries, q)
		}
		payload, err := json.Marshal(body)
		if err != nil {
			return res, err
		}
		resp, err := o.HTTP.Do(ctx, httpx.Request{Method: "POST", URL: base + "/v1/querybatch", Body: payload,
			Header: map[string][]string{"Content-Type": {"application/json"}}, MaxBytes: 8 << 20})
		res.Requests++
		if err != nil {
			_ = recordFailure(ctx, o.Store, st, now, err)
			if isRateLimited(err) {
				return res, ErrRateLimited
			}
			res.Skipped++
			continue
		}
		var batch struct {
			Results []struct {
				Vulns []struct {
					ID       string    `json:"id"`
					Modified time.Time `json:"modified"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := json.Unmarshal(resp.Body, &batch); err != nil {
			_ = recordFailure(ctx, o.Store, st, now, fmt.Errorf("decode querybatch: %w", err))
			res.Skipped++
			continue
		}

		stored, err := o.Store.Advisories(ctx, app.ID)
		if err != nil {
			return res, err
		}
		have := map[string]store.AdvisoryRecord{}
		for _, r := range stored {
			if r.Source == "osv" {
				have[r.Vuln.ID] = r
			}
		}
		var recs []store.AdvisoryRecord
		changed, complete := false, true
		seen := map[string]bool{}
		for _, r := range batch.Results {
			for _, v := range r.Vulns {
				if seen[v.ID] || !validOSVID(v.ID) {
					continue
				}
				seen[v.ID] = true
				if prev, ok := have[v.ID]; ok && !v.Modified.After(prev.Vuln.Modified) {
					recs = append(recs, prev)
					continue
				}
				if fetched >= osvMaxFetch {
					complete = false
					if prev, ok := have[v.ID]; ok {
						recs = append(recs, prev)
					}
					continue
				}
				rec, err := o.fetch(ctx, base, v.ID)
				res.Requests++
				fetched++
				if err != nil {
					complete = false
					if prev, ok := have[v.ID]; ok {
						recs = append(recs, prev)
					}
					continue
				}
				rec.AppID, rec.Source = app.ID, "osv"
				rec.Vuln.Affected = onlyPackages(rec.Vuln.Affected, app.Advisories.OSVPackages)
				recs = append(recs, rec)
				changed = true
			}
		}
		if len(have) != len(seen) {
			changed = true
		}
		if changed {
			if err := o.Store.ReplaceAdvisories(ctx, app.ID, "osv", recs, now); err != nil {
				return res, err
			}
			res.Updated++
		} else {
			res.NotModified++
		}
		st.LastAttempt, st.LastError = now, ""
		if complete {
			st.LastSuccess = now
		} else {
			st.LastError = "partial refresh, continuing next run"
		}
		if err := o.Store.PutSourceState(ctx, st); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (o *OSV) fetch(ctx context.Context, base, id string) (store.AdvisoryRecord, error) {
	return fetchOSV(ctx, o.HTTP, base, id)
}

// fetchOSV downloads one OSV record and checks its ID.
func fetchOSV(ctx context.Context, hc *httpx.Client, base, id string) (store.AdvisoryRecord, error) {
	resp, err := hc.Do(ctx, httpx.Request{URL: base + "/v1/vulns/" + url.PathEscape(id), MaxBytes: 4 << 20})
	if err != nil {
		return store.AdvisoryRecord{}, err
	}
	var v advisory.Vulnerability
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return store.AdvisoryRecord{}, fmt.Errorf("decode %s: %w", id, err)
	}
	if v.ID != id {
		return store.AdvisoryRecord{}, fmt.Errorf("record id %q does not match %q", v.ID, id)
	}
	v.Summary = truncate(v.Summary, 512)
	v.Details = truncate(v.Details, 32<<10)
	var score float64
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if c, err := advisory.CVSS3BaseScore(s.Score); err == nil && c > score {
				score = c
			}
		}
	}
	label := ""
	if sev, ok := v.DatabaseSpecific["severity"].(string); ok {
		label = strings.ToLower(truncate(sev, 16))
	}
	return store.AdvisoryRecord{Vuln: v, CVSS: score, SeverityLabel: label}, nil
}

// onlyPackages keeps the affected entries of the packages that were
// queried; OSV records often also list unrelated packages (dependencies,
// the language runtime) whose ranges must not be compared with the app.
func onlyPackages(entries []advisory.Affected, pkgs []catalog.OSVPackage) []advisory.Affected {
	out := []advisory.Affected{}
	for _, e := range entries {
		for _, p := range pkgs {
			if strings.EqualFold(e.Package.Ecosystem, p.Ecosystem) && e.Package.Name == p.Name {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

func validOSVID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}
