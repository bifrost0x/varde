// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// SourceSystem is the source state name of the system package check.
const SourceSystem = "system-packages"

const (
	// systemBatch is the number of packages per osv.dev batch query; the
	// API takes up to 1000.
	systemBatch = 500
	// systemMaxFetch bounds record downloads per refresh; a first check of
	// many hosts completes over a few refreshes.
	systemMaxFetch = 3000
	// systemParallel bounds the record downloads running at once.
	systemParallel = 8
)

// SystemPackages checks every system package of every host against its
// distribution's security data (ADR 0032). osv.dev evaluates the installed
// version: a batch query returns only the records that affect it. Varde
// downloads those records once and keeps them until they change; the
// matcher then compares the version again in the package manager's order.
// It is switched together with the OSV source: the queries reveal package
// names, versions and releases to osv.dev.
type SystemPackages struct {
	Deps
	BaseURL string
	// Packages returns the system packages present, deduplicated.
	Packages func(ctx context.Context) ([]distro.Package, error)
	// Stored returns the app IDs with stored system package records, so
	// that packages no longer present lose theirs.
	Stored func(ctx context.Context) ([]string, error)
}

// Name implements Source.
func (*SystemPackages) Name() string { return SourceSystem }

type systemKey struct{ ecosystem, name, version string }

// Refresh implements Source. The apps argument is ignored: system packages
// need no catalog entry.
func (s *SystemPackages) Refresh(ctx context.Context, _ []*catalog.App) (Result, error) {
	var res Result
	if s.Packages == nil {
		return res, nil
	}
	pkgs, err := s.Packages(ctx)
	if err != nil {
		return res, fmt.Errorf("system packages: %w", err)
	}
	st, err := s.Store.SourceState(ctx, SourceSystem, "")
	if err != nil {
		return res, err
	}
	now := s.now()
	if !due(st, now) {
		res.Skipped++
		return res, nil
	}
	base := s.BaseURL
	if base == "" {
		base = osvAPI
	}
	keys := systemKeys(pkgs)
	// IDs per app: the records of every version present of a package.
	want := map[string]map[string]time.Time{}
	for start := 0; start < len(keys); start += systemBatch {
		batch := keys[start:min(start+systemBatch, len(keys))]
		ids, err := s.query(ctx, base, batch)
		res.Requests++
		if err != nil {
			_ = recordFailure(ctx, s.Store, st, now, err)
			if isRateLimited(err) {
				return res, ErrRateLimited
			}
			return res, err
		}
		for i, k := range batch {
			app := distro.SystemAppID(k.ecosystem, k.name)
			if want[app] == nil {
				want[app] = map[string]time.Time{}
			}
			for id, m := range ids[i] {
				want[app][id] = m
			}
		}
	}

	complete := true
	cves := &cveCache{byID: map[string]*store.AdvisoryRecord{}}
	var budget sync.Mutex
	fetched := 0
	take := func() bool {
		budget.Lock()
		defer budget.Unlock()
		if fetched >= systemMaxFetch {
			return false
		}
		fetched++
		return true
	}
	apps := make([]string, 0, len(want))
	for app := range want {
		apps = append(apps, app)
	}
	// Packages with few records first: one package with thousands (an old
	// kernel) must not use up the budget of a refresh while the rest wait.
	sort.Slice(apps, func(i, j int) bool {
		if len(want[apps[i]]) != len(want[apps[j]]) {
			return len(want[apps[i]]) < len(want[apps[j]])
		}
		return apps[i] < apps[j]
	})
	for _, app := range apps {
		eco, name, _ := distro.ParseSystemAppID(app)
		stored, err := s.Store.Advisories(ctx, app)
		if err != nil {
			return res, err
		}
		have := map[string]store.AdvisoryRecord{}
		for _, r := range stored {
			if r.Source == match.SourceDistro {
				have[r.Vuln.ID] = r
			}
		}
		ids := sortedIDs(want[app])
		recs := make([]*store.AdvisoryRecord, len(ids))
		// A record gone or new changes the stored set, even when the number
		// stays the same.
		changed := !sameIDs(have, want[app])
		var mu sync.Mutex
		sem := make(chan struct{}, systemParallel)
		var wg sync.WaitGroup
		for i, id := range ids {
			if prev, ok := have[id]; ok && !want[app][id].After(prev.Vuln.Modified) && prev.Vuln.DatabaseSpecific[enrichedKey] != nil {
				recs[i] = &prev
				continue
			}
			if !take() {
				complete = false
				if prev, ok := have[id]; ok {
					recs[i] = &prev
				}
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				rec, err := fetchOSV(ctx, s.HTTP, base, id)
				mu.Lock()
				defer mu.Unlock()
				res.Requests++
				if err != nil {
					complete = false
					if prev, ok := have[id]; ok {
						recs[i] = &prev
					}
					return
				}
				rec.AppID, rec.Source = app, match.SourceDistro
				rec.Vuln.Affected = systemEntries(rec.Vuln.Affected, eco, name, now)
				if len(rec.Vuln.Affected) == 0 {
					return
				}
				// Severity outside the lock: it may fetch the CVE record.
				mu.Unlock()
				s.enrich(ctx, base, &rec, cves, take)
				mu.Lock()
				recs[i] = &rec
				changed = true
			}()
		}
		wg.Wait()
		if !changed {
			res.NotModified++
			continue
		}
		var out []store.AdvisoryRecord
		for _, r := range recs {
			if r != nil {
				out = append(out, *r)
			}
		}
		if err := s.Store.ReplaceAdvisories(ctx, app, match.SourceDistro, out, now); err != nil {
			return res, err
		}
		res.Updated++
	}
	// Packages no longer installed anywhere lose their records.
	if s.Stored != nil {
		stored, err := s.Stored(ctx)
		if err != nil {
			return res, err
		}
		for _, app := range stored {
			if _, ok := want[app]; !ok {
				if err := s.Store.ReplaceAdvisories(ctx, app, match.SourceDistro, nil, now); err != nil {
					return res, err
				}
				res.Updated++
			}
		}
	}
	st.LastAttempt, st.LastError = now, ""
	if complete {
		st.LastSuccess = now
	} else {
		st.LastError = "partial refresh, continuing next run"
	}
	if err := s.Store.PutSourceState(ctx, st); err != nil {
		return res, err
	}
	return res, nil
}

func systemKeys(pkgs []distro.Package) []systemKey {
	seen := map[systemKey]bool{}
	var out []systemKey
	for _, p := range pkgs {
		k := systemKey{p.Ecosystem, p.Name, p.Version}
		if seen[k] || !distro.Supported(p.Ecosystem) || p.Name == "" || p.Version == "" {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.ecosystem+"\x00"+a.name+"\x00"+a.version < b.ecosystem+"\x00"+b.name+"\x00"+b.version
	})
	return out
}

// query asks osv.dev which records affect each package at its version and
// returns, per key, the IDs of the distribution's records.
func (s *SystemPackages) query(ctx context.Context, base string, keys []systemKey) ([]map[string]time.Time, error) {
	type pkg struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	}
	type query struct {
		Package   pkg    `json:"package"`
		Version   string `json:"version"`
		PageToken string `json:"page_token,omitempty"`
	}
	var body struct {
		Queries []query `json:"queries"`
	}
	// One query per ecosystem whose records apply: an Ubuntu release past
	// standard support is asked under its Pro ecosystem too. pending maps
	// each query to its key.
	var pending []int
	now := s.now()
	for ki, k := range keys {
		for _, eco := range distro.Variants(k.ecosystem, now) {
			body.Queries = append(body.Queries, query{Package: pkg{Ecosystem: eco, Name: k.name}, Version: k.version})
			pending = append(pending, ki)
		}
	}
	out := make([]map[string]time.Time, len(keys))
	for i := range out {
		out[i] = map[string]time.Time{}
	}
	// Answers too long for one page come back with a token; those queries
	// are asked again with it, a bounded number of times.
	for page := 0; len(body.Queries) > 0; page++ {
		if page == distroMaxPages {
			return nil, fmt.Errorf("more than %d pages of records", distroMaxPages)
		}
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		resp, err := s.HTTP.Do(ctx, httpx.Request{Method: "POST", URL: base + "/v1/querybatch", Body: payload,
			Header: map[string][]string{"Content-Type": {"application/json"}}, MaxBytes: 32 << 20})
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
		if len(batch.Results) != len(body.Queries) {
			return nil, fmt.Errorf("querybatch returned %d results for %d queries", len(batch.Results), len(body.Queries))
		}
		var next []query
		idx := make([]int, 0, len(body.Queries))
		for qi, r := range batch.Results {
			ki := pending[qi]
			for _, v := range r.Vulns {
				// A Go flaw has a GO- record and usually a GitHub advisory
				// with the same aliases; both are kept (a GitHub advisory
				// the Go team has not reviewed has no GO- record) and the
				// matcher merges them by alias into one finding.
				if validOSVID(v.ID) {
					out[ki][v.ID] = v.Modified
				}
			}
			if r.NextPageToken != "" && r.NextPageToken != body.Queries[qi].PageToken {
				q := body.Queries[qi]
				q.PageToken = r.NextPageToken
				next = append(next, q)
				idx = append(idx, ki)
			}
		}
		body.Queries, pending = next, idx
	}
	for i := range out {
		out[i] = distro.KeepRecords(keys[i].ecosystem, out[i])
	}
	return out, nil
}

// systemEntries keeps the affected entries of the one package a record was
// fetched for, without those the distribution rates as no security problem
// for it (Debian's "unimportant").
func systemEntries(entries []advisory.Affected, ecosystem, name string, now time.Time) []advisory.Affected {
	out := []advisory.Affected{}
	for _, e := range entries {
		if !distro.SameRelease(e.Package.Ecosystem, ecosystem, now) || e.Package.Name != name {
			continue
		}
		if u, _ := e.EcosystemSpecific["urgency"].(string); strings.EqualFold(u, "unimportant") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// enrichedKey marks a stored record whose severity was taken from its CVE.
const enrichedKey = "varde_enriched"

// cveCache keeps the CVE records fetched during one refresh: several
// distribution records name the same CVE.
type cveCache struct {
	mu   sync.Mutex
	byID map[string]*store.AdvisoryRecord
}

// enrich gives a distribution record the severity of the CVE it names.
// Debian's per-CVE records carry none; osv.dev's record of the CVE has the
// CVSS vectors (NVD's and others'). The vectors are copied, so the score
// and the attack vector (network, adjacent, local) are known. A record the
// distribution rates itself keeps its own severity.
func (s *SystemPackages) enrich(ctx context.Context, base string, rec *store.AdvisoryRecord, cache *cveCache, take func() bool) {
	if rec.Vuln.DatabaseSpecific == nil {
		rec.Vuln.DatabaseSpecific = map[string]any{}
	}
	rec.Vuln.DatabaseSpecific[enrichedKey] = true
	if len(rec.Vuln.Severity) > 0 {
		return
	}
	cve := ""
	for _, id := range append(append([]string(nil), rec.Vuln.Upstream...), rec.Vuln.Aliases...) {
		if strings.HasPrefix(id, "CVE-") && validOSVID(id) {
			cve = id
			break
		}
	}
	if cve == "" {
		return
	}
	cache.mu.Lock()
	c, ok := cache.byID[cve]
	cache.mu.Unlock()
	if !ok {
		if !take() {
			// Without budget the record stays unrated and is enriched on a
			// later refresh.
			delete(rec.Vuln.DatabaseSpecific, enrichedKey)
			return
		}
		got, err := fetchOSV(ctx, s.HTTP, base, cve)
		var se *httpx.StatusError
		switch {
		case errors.As(err, &se) && se.Status == http.StatusNotFound:
			// osv.dev has no record of the CVE: nothing to take over, and
			// nothing to ask for again.
			got = store.AdvisoryRecord{}
		case err != nil:
			// A passing failure: the next refresh tries again.
			delete(rec.Vuln.DatabaseSpecific, enrichedKey)
			return
		}
		c = &got
		cache.mu.Lock()
		cache.byID[cve] = c
		cache.mu.Unlock()
	}
	rec.Vuln.Severity = append(rec.Vuln.Severity, c.Vuln.Severity...)
	rec.CVSS, rec.SeverityLabel = c.CVSS, c.SeverityLabel
	if rec.Vuln.Summary == "" {
		rec.Vuln.Summary = truncate(c.Vuln.Summary, 300)
	}
}

// sameIDs reports whether the stored records are exactly the wanted ones.
func sameIDs[T any](have map[string]store.AdvisoryRecord, want map[string]T) bool {
	if len(have) != len(want) {
		return false
	}
	for id := range want {
		if _, ok := have[id]; !ok {
			return false
		}
	}
	return true
}
