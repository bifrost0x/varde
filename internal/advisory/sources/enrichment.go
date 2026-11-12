// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

const (
	kevURL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL       = "https://api.first.org/data/v1/epss"
	dailyInterval = 24 * time.Hour
	epssBatch     = 100
)

// KEV refreshes the CISA Known Exploited Vulnerabilities catalog daily.
type KEV struct {
	Deps
	URL string // override for tests
}

// Name implements Source.
func (*KEV) Name() string { return "kev" }

// Refresh implements Source. The catalog is global; apps are ignored.
func (k *KEV) Refresh(ctx context.Context, _ []*catalog.App) (Result, error) {
	var res Result
	st, err := k.Store.SourceState(ctx, "kev", "catalog")
	if err != nil {
		return res, err
	}
	now := k.now()
	if !due(st, now) {
		res.Skipped++
		return res, nil
	}
	u := k.URL
	if u == "" {
		u = kevURL
	}
	resp, err := k.HTTP.Do(ctx, httpx.Request{URL: u, ETag: st.ETag, LastModified: st.LastModified, MaxBytes: 32 << 20})
	res.Requests++
	if err != nil {
		return res, wrap("kev", "catalog", recordFailure(ctx, k.Store, st, now, err))
	}
	st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(dailyInterval)
	if resp.NotModified {
		res.NotModified++
		return res, k.Store.PutSourceState(ctx, st)
	}
	var doc struct {
		Vulnerabilities []struct {
			CVEID      string `json:"cveID"`
			DateAdded  string `json:"dateAdded"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return res, wrap("kev", "catalog", recordFailure(ctx, k.Store, st, now, fmt.Errorf("decode: %w", err)))
	}
	entries := make([]store.KEVEntry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if strings.HasPrefix(v.CVEID, "CVE-") && len(v.CVEID) < 32 {
			entries = append(entries, store.KEVEntry{CVE: v.CVEID, DateAdded: truncate(v.DateAdded, 16), Ransomware: truncate(v.Ransomware, 16)})
		}
	}
	// An empty or tiny catalog means a broken response, not a cleared one;
	// keep the previous data.
	if len(entries) < 100 {
		return res, wrap("kev", "catalog", recordFailure(ctx, k.Store, st, now, fmt.Errorf("implausible catalog with %d entries", len(entries))))
	}
	if err := k.Store.ReplaceKEV(ctx, entries); err != nil {
		return res, err
	}
	st.ETag, st.LastModified = resp.ETag, resp.LastModified
	res.Updated++
	return res, k.Store.PutSourceState(ctx, st)
}

// EPSS refreshes FIRST EPSS scores daily, only for CVEs referenced by
// stored advisories (never the full dataset).
type EPSS struct {
	Deps
	URL string // override for tests
	// CVEs, when set, returns the CVE IDs to ask about instead of those
	// of every stored advisory.
	CVEs func(ctx context.Context) ([]string, error)
}

// Name implements Source.
func (*EPSS) Name() string { return "epss" }

// Refresh implements Source.
func (e *EPSS) Refresh(ctx context.Context, _ []*catalog.App) (Result, error) {
	var res Result
	st, err := e.Store.SourceState(ctx, "epss", "scores")
	if err != nil {
		return res, err
	}
	now := e.now()
	if !due(st, now) {
		res.Skipped++
		return res, nil
	}
	list := e.Store.AdvisoryCVEs
	if e.CVEs != nil {
		list = e.CVEs
	}
	cves, err := list(ctx)
	if err != nil {
		return res, err
	}
	sort.Strings(cves)
	base := e.URL
	if base == "" {
		base = epssURL
	}
	var all []store.EPSSEntry
	for i := 0; i < len(cves); i += epssBatch {
		batch := cves[i:min(i+epssBatch, len(cves))]
		if i > 0 {
			if err := e.sleep(ctx, time.Second); err != nil {
				return res, err
			}
		}
		resp, err := e.HTTP.Do(ctx, httpx.Request{URL: base + "?cve=" + url.QueryEscape(strings.Join(batch, ",")), MaxBytes: 4 << 20})
		res.Requests++
		if err != nil {
			return res, wrap("epss", "scores", recordFailure(ctx, e.Store, st, now, err))
		}
		var doc struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			} `json:"data"`
		}
		if err := json.Unmarshal(resp.Body, &doc); err != nil {
			return res, wrap("epss", "scores", recordFailure(ctx, e.Store, st, now, fmt.Errorf("decode: %w", err)))
		}
		for _, d := range doc.Data {
			score, err1 := strconv.ParseFloat(d.EPSS, 64)
			pct, err2 := strconv.ParseFloat(d.Percentile, 64)
			if err := errors.Join(err1, err2); err != nil || score < 0 || score > 1 || !strings.HasPrefix(d.CVE, "CVE-") {
				continue
			}
			all = append(all, store.EPSSEntry{CVE: d.CVE, Score: score, Percentile: pct, Date: truncate(d.Date, 16)})
		}
	}
	if err := e.Store.UpsertEPSS(ctx, all); err != nil {
		return res, err
	}
	st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(dailyInterval)
	if len(all) > 0 {
		res.Updated++
	}
	return res, e.Store.PutSourceState(ctx, st)
}
