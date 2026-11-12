// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// distroMaxFetch bounds record downloads per refresh; a package with a
// long history (openssh has over a hundred Debian records) completes over
// a few refreshes.
const distroMaxFetch = 600

// Distro fetches the distribution security records of the distribution
// packages present (Debian, Ubuntu, Alpine through osv.dev) and stores, per
// app, the per-CVE records with the entries of those packages (ADR 0028).
// It is switched together with the OSV source: the queries reveal the
// package names and releases to osv.dev.
type Distro struct {
	Deps
	BaseURL string
	// Packages returns the distribution packages present, by app ID.
	Packages func(ctx context.Context) (map[string][]distro.Package, error)
}

// Name implements Source.
func (*Distro) Name() string { return match.SourceDistro }

// Refresh implements Source.
func (d *Distro) Refresh(ctx context.Context, apps []*catalog.App) (Result, error) {
	var res Result
	if d.Packages == nil {
		return res, nil
	}
	present, err := d.Packages(ctx)
	if err != nil {
		return res, fmt.Errorf("distribution packages: %w", err)
	}
	base := d.BaseURL
	if base == "" {
		base = osvAPI
	}
	fetched := 0
	for _, app := range apps {
		keys := queryKeys(present[app.ID])
		if len(keys) == 0 {
			// No distribution package of the app any more: its records go.
			if err := d.drop(ctx, app.ID); err != nil {
				return res, err
			}
			continue
		}
		st, err := d.Store.SourceState(ctx, match.SourceDistro, app.ID)
		if err != nil {
			return res, err
		}
		now := d.now()
		if !due(st, now) {
			res.Skipped++
			continue
		}
		ids, err := d.query(ctx, base, keys)
		res.Requests++
		if err != nil {
			_ = recordFailure(ctx, d.Store, st, now, err)
			if isRateLimited(err) {
				return res, ErrRateLimited
			}
			res.Skipped++
			continue
		}
		stored, err := d.Store.Advisories(ctx, app.ID)
		if err != nil {
			return res, err
		}
		have := map[string]store.AdvisoryRecord{}
		for _, r := range stored {
			if r.Source == match.SourceDistro {
				have[r.Vuln.ID] = r
			}
		}
		var recs []store.AdvisoryRecord
		changed, complete := !sameIDs(have, ids), true
		sig := keySignature(keys)
		for _, id := range sortedIDs(ids) {
			prev, ok := have[id]
			if ok && !ids[id].After(prev.Vuln.Modified) && prev.Vuln.DatabaseSpecific[queriedKey] == sig {
				recs = append(recs, prev)
				continue
			}
			if fetched >= distroMaxFetch {
				complete = false
				if ok {
					recs = append(recs, prev)
				}
				continue
			}
			rec, err := fetchOSV(ctx, d.HTTP, base, id)
			res.Requests++
			fetched++
			if err != nil {
				complete = false
				if ok {
					recs = append(recs, prev)
				}
				continue
			}
			rec.AppID, rec.Source = app.ID, match.SourceDistro
			rec.Vuln.Affected = onlyKeys(rec.Vuln.Affected, keys)
			if rec.Vuln.DatabaseSpecific == nil {
				rec.Vuln.DatabaseSpecific = map[string]any{}
			}
			rec.Vuln.DatabaseSpecific[queriedKey] = sig
			recs = append(recs, rec)
			changed = true
		}
		if changed {
			if err := d.Store.ReplaceAdvisories(ctx, app.ID, match.SourceDistro, recs, now); err != nil {
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
		if err := d.Store.PutSourceState(ctx, st); err != nil {
			return res, err
		}
	}
	return res, nil
}

// queryKey is one (ecosystem, source package) pair.
type queryKey struct{ ecosystem, name string }

func queryKeys(pkgs []distro.Package) []queryKey {
	seen := map[queryKey]bool{}
	var out []queryKey
	for _, p := range pkgs {
		k := queryKey{p.Ecosystem, p.Name}
		if seen[k] || !distro.Supported(p.Ecosystem) {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ecosystem+out[i].name < out[j].ecosystem+out[j].name })
	return out
}

// query asks osv.dev for the records of the pairs and returns the per-CVE
// distribution record IDs with their modification time.
func (d *Distro) query(ctx context.Context, base string, keys []queryKey) (map[string]time.Time, error) {
	type pkg struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	}
	type query struct {
		Package pkg `json:"package"`
	}
	var body struct {
		Queries []query `json:"queries"`
	}
	for _, k := range keys {
		body.Queries = append(body.Queries, query{Package: pkg{Ecosystem: k.ecosystem, Name: k.name}})
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp, err := d.HTTP.Do(ctx, httpx.Request{Method: "POST", URL: base + "/v1/querybatch", Body: payload,
		Header: map[string][]string{"Content-Type": {"application/json"}}, MaxBytes: 16 << 20})
	if err != nil {
		return nil, err
	}
	var batch struct {
		Results []struct {
			Vulns []struct {
				ID       string    `json:"id"`
				Modified time.Time `json:"modified"`
			} `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resp.Body, &batch); err != nil {
		return nil, fmt.Errorf("decode querybatch: %w", err)
	}
	if len(batch.Results) != len(keys) {
		return nil, fmt.Errorf("querybatch returned %d results for %d queries", len(batch.Results), len(keys))
	}
	ids := map[string]time.Time{}
	for i, r := range batch.Results {
		found := map[string]time.Time{}
		add := func(id string, modified time.Time) {
			if validOSVID(id) {
				found[id] = modified
			}
		}
		for _, v := range r.Vulns {
			add(v.ID, v.Modified)
		}
		// More records than one answer holds: the rest page by page, and
		// rather nothing than a silently incomplete list.
		token := r.NextPageToken
		for page := 0; token != ""; page++ {
			if page == distroMaxPages {
				return nil, fmt.Errorf("%s/%s has more than %d pages of records", keys[i].ecosystem, keys[i].name, distroMaxPages)
			}
			more, next, err := d.queryPage(ctx, base, keys[i], token)
			if err != nil {
				return nil, err
			}
			for id, m := range more {
				add(id, m)
			}
			token = next
		}
		for id, m := range distro.KeepRecords(keys[i].ecosystem, found) {
			ids[id] = m
		}
	}
	return ids, nil
}

// distroMaxPages bounds the follow-up pages of one package.
const distroMaxPages = 20

// queryPage reads one follow-up page of a package's records.
func (d *Distro) queryPage(ctx context.Context, base string, k queryKey, token string) (map[string]time.Time, string, error) {
	payload, err := json.Marshal(map[string]any{
		"package":    map[string]string{"ecosystem": k.ecosystem, "name": k.name},
		"page_token": token,
	})
	if err != nil {
		return nil, "", err
	}
	resp, err := d.HTTP.Do(ctx, httpx.Request{Method: "POST", URL: base + "/v1/query", Body: payload,
		Header: map[string][]string{"Content-Type": {"application/json"}}, MaxBytes: 32 << 20})
	if err != nil {
		return nil, "", err
	}
	var page struct {
		Vulns []struct {
			ID       string    `json:"id"`
			Modified time.Time `json:"modified"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	}
	if err := json.Unmarshal(resp.Body, &page); err != nil {
		return nil, "", fmt.Errorf("decode query page: %w", err)
	}
	out := make(map[string]time.Time, len(page.Vulns))
	for _, v := range page.Vulns {
		out[v.ID] = v.Modified
	}
	if page.NextPageToken == token {
		return nil, "", fmt.Errorf("query page token did not advance")
	}
	return out, page.NextPageToken, nil
}

func sortedIDs(ids map[string]time.Time) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// onlyKeys keeps the affected entries of the queried packages: a record
// lists every release, and other releases' versions must not be compared.
func onlyKeys(entries []advisory.Affected, keys []queryKey) []advisory.Affected {
	out := []advisory.Affected{}
	for _, e := range entries {
		for _, k := range keys {
			if strings.EqualFold(e.Package.Ecosystem, k.ecosystem) && e.Package.Name == k.name {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// queriedKey marks, on a stored record, the package set it was reduced to:
// when a host adds a release, the record is fetched again for it.
const queriedKey = "varde_queried"

func keySignature(keys []queryKey) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k.ecosystem + "/" + k.name
	}
	return strings.Join(parts, ",")
}

// drop removes the stored distribution records of an app.
func (d *Distro) drop(ctx context.Context, appID string) error {
	stored, err := d.Store.Advisories(ctx, appID)
	if err != nil {
		return err
	}
	for _, r := range stored {
		if r.Source == match.SourceDistro {
			return d.Store.ReplaceAdvisories(ctx, appID, match.SourceDistro, nil, d.now())
		}
	}
	return nil
}
