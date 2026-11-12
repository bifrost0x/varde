// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

const (
	nvdAPI      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdPageSize = 2000
	nvdMaxPages = 10
)

// NVD queries the NVD CVE API by the catalog's CPE prefixes. Opt-in: the
// queries reveal which products run. Ranges come from CPE configurations
// and are less precise than project advisories (ADR 0017).
type NVD struct {
	Deps
	APIKey  string
	BaseURL string
}

// Name implements Source.
func (*NVD) Name() string { return "nvd" }

// pause respects the published limits: 5 requests per 30 s without a key,
// 50 with one.
func (n *NVD) pause() time.Duration {
	if n.APIKey != "" {
		return time.Second
	}
	return 7 * time.Second
}

// Refresh implements Source.
func (n *NVD) Refresh(ctx context.Context, apps []*catalog.App) (Result, error) {
	var res Result
	base := n.BaseURL
	if base == "" {
		base = nvdAPI
	}
	for _, app := range apps {
		for _, cpe := range app.Advisories.CPE {
			st, err := n.Store.SourceState(ctx, "nvd", cpe)
			if err != nil {
				return res, err
			}
			now := n.now()
			if !due(st, now) {
				res.Skipped++
				continue
			}
			if res.Requests > 0 {
				if err := n.sleep(ctx, n.pause()); err != nil {
					return res, err
				}
			}
			recs, requests, err := n.fetchCPE(ctx, base, cpe)
			res.Requests += requests
			if err != nil {
				ferr := recordFailure(ctx, n.Store, st, now, err)
				if isRateLimited(err) {
					return res, fmt.Errorf("%w: %w", ErrRateLimited, ferr)
				}
				res.Skipped++
				continue
			}
			for i := range recs {
				recs[i].AppID, recs[i].Source = app.ID, "nvd:"+cpe
			}
			if err := n.Store.ReplaceAdvisories(ctx, app.ID, "nvd:"+cpe, recs, now); err != nil {
				return res, err
			}
			st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(dailyInterval)
			if err := n.Store.PutSourceState(ctx, st); err != nil {
				return res, err
			}
			res.Updated++
		}
	}
	return res, nil
}

func (n *NVD) fetchCPE(ctx context.Context, base, cpe string) ([]store.AdvisoryRecord, int, error) {
	vendorProduct := cpeVendorProduct(cpe)
	if vendorProduct == "" {
		return nil, 0, fmt.Errorf("invalid cpe %q", cpe)
	}
	header := http.Header{}
	if n.APIKey != "" {
		header.Set("apiKey", n.APIKey)
	}
	var out []store.AdvisoryRecord
	requests := 0
	match := "cpe:2.3:" + vendorProduct + ":*:*:*:*:*:*:*:*"
	for page, start := 0, 0; ; page++ {
		if page >= nvdMaxPages {
			return nil, requests, fmt.Errorf("more than %d pages", nvdMaxPages)
		}
		if page > 0 {
			if err := n.sleep(ctx, n.pause()); err != nil {
				return nil, requests, err
			}
		}
		q := url.Values{
			"virtualMatchString": {match},
			"resultsPerPage":     {strconv.Itoa(nvdPageSize)},
			"startIndex":         {strconv.Itoa(start)},
		}
		resp, err := n.HTTP.Do(ctx, httpx.Request{URL: base + "?" + q.Encode(), Header: header, MaxBytes: 64 << 20})
		requests++
		if err != nil {
			return nil, requests, err
		}
		var doc nvdResponse
		if err := json.Unmarshal(resp.Body, &doc); err != nil {
			return nil, requests, fmt.Errorf("decode: %w", err)
		}
		for _, item := range doc.Vulnerabilities {
			if rec, ok := convertNVD(item.CVE, vendorProduct); ok {
				out = append(out, rec)
			}
		}
		start += len(doc.Vulnerabilities)
		if len(doc.Vulnerabilities) == 0 || start >= doc.TotalResults {
			return out, requests, nil
		}
	}
}

// cpeVendorProduct returns "part:vendor:product" of a CPE 2.3 prefix.
func cpeVendorProduct(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
		return ""
	}
	return strings.Join(parts[2:5], ":")
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		Type     string `json:"type"`
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			VectorString string  `json:"vectorString"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			Negate   bool `json:"negate"`
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// nvdTime parses NVD timestamps, which carry no zone (UTC).
func nvdTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// convertNVD maps a CVE to OSV, keeping only CPE matches of vendorProduct.
func convertNVD(c nvdCVE, vendorProduct string) (store.AdvisoryRecord, bool) {
	if !strings.HasPrefix(c.ID, "CVE-") || c.VulnStatus == "Rejected" {
		return store.AdvisoryRecord{}, false
	}
	v := advisory.Vulnerability{
		SchemaVersion: "1.6.0",
		ID:            c.ID,
		Modified:      nvdTime(c.LastModified),
		Published:     nvdTime(c.Published),
		References:    []advisory.Reference{{Type: "WEB", URL: "https://nvd.nist.gov/vuln/detail/" + c.ID}},
		DatabaseSpecific: map[string]any{
			"nvd_status": c.VulnStatus,
		},
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			v.Details = truncate(d.Value, 32<<10)
			v.Summary = truncate(firstSentence(d.Value), 256)
			break
		}
	}

	aff := advisory.Affected{Package: advisory.Package{Ecosystem: "CPE", Name: vendorProduct}}
	prefix := "cpe:2.3:" + vendorProduct + ":"
	matched := false
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			for _, m := range node.CPEMatch {
				if !m.Vulnerable || !strings.HasPrefix(m.Criteria, prefix) {
					continue
				}
				matched = true
				fields := strings.Split(m.Criteria, ":")
				exact, update := "", ""
				if len(fields) > 5 && fields[5] != "*" && fields[5] != "-" {
					exact = fields[5]
				}
				if len(fields) > 6 {
					update = fields[6]
				}
				form := nvdVersionForm(vendorProduct)
				exact = form(exact, update)
				m.VersionStartIncluding, m.VersionStartExcluding = form(m.VersionStartIncluding, ""), form(m.VersionStartExcluding, "")
				m.VersionEndIncluding, m.VersionEndExcluding = form(m.VersionEndIncluding, ""), form(m.VersionEndExcluding, "")
				hasRange := m.VersionStartIncluding+m.VersionStartExcluding+m.VersionEndIncluding+m.VersionEndExcluding != ""
				switch {
				case exact != "" && !hasRange:
					aff.Versions = append(aff.Versions, exact)
				case hasRange:
					r := advisory.Range{Type: advisory.RangeEcosystem}
					intro := "0"
					if m.VersionStartIncluding != "" {
						intro = m.VersionStartIncluding
					} else if m.VersionStartExcluding != "" {
						intro = m.VersionStartExcluding
						r.DatabaseSpecific = map[string]any{advisory.RangeInferred: true}
					}
					r.Events = append(r.Events, advisory.Event{Introduced: intro})
					switch {
					case m.VersionEndExcluding != "":
						r.Events = append(r.Events, advisory.Event{Fixed: m.VersionEndExcluding})
					case m.VersionEndIncluding != "":
						r.Events = append(r.Events, advisory.Event{LastAffected: m.VersionEndIncluding})
					}
					aff.Ranges = append(aff.Ranges, r)
				default:
					// "*" without bounds: every version. Too broad to
					// assert; keep it as an entry without ranges, which
					// matches as unverified.
				}
			}
		}
	}
	if !matched {
		// The product appears only as a non-vulnerable platform.
		return store.AdvisoryRecord{}, false
	}
	v.Affected = []advisory.Affected{aff}

	var score float64
	label := ""
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV40"} {
		for _, m := range c.Metrics[key] {
			if m.Type != "Primary" && score > 0 {
				continue
			}
			if m.CVSSData.BaseScore > 0 {
				score, label = m.CVSSData.BaseScore, strings.ToLower(m.CVSSData.BaseSeverity)
				if strings.HasPrefix(m.CVSSData.VectorString, "CVSS:3") {
					v.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: m.CVSSData.VectorString}}
				}
			}
		}
		if score > 0 {
			break
		}
	}
	return store.AdvisoryRecord{Vuln: v, CVSS: score, SeverityLabel: label}, true
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	return s
}

// nvdVersionForm returns how a product's NVD versions are rewritten into
// the notation Varde records for it: appliance integrations record
// builds and updates as further dotted numbers (Synology "7.2.1-69057
// Update 5" is 7.2.1.69057.5, TrueNAS CORE "13.0-U6.2" is 13.0.6.2), and
// NVD writes them with dashes or in the CPE's update field. Without the
// rewrite a build after a dash would read as a pre-release.
func nvdVersionForm(vendorProduct string) func(v, update string) string {
	_, vp, _ := strings.Cut(vendorProduct, ":")
	switch vp {
	case "synology:diskstation_manager":
		return func(v, update string) string {
			if v == "" {
				return v
			}
			v = strings.ReplaceAll(strings.ToLower(v), " update ", "-")
			v = strings.ReplaceAll(v, "-", ".")
			// The update field holds the build ("69057", "69057-5") when
			// the version does not.
			if u := strings.ReplaceAll(update, "-", "."); u != "" && u[0] >= '0' && u[0] <= '9' && strings.Count(v, ".") < 3 {
				v += "." + u
			}
			return v
		}
	case "ixsystems:truenas_core", "ixsystems:truenas":
		return func(v, update string) string {
			if v == "" {
				return v
			}
			v = strings.ReplaceAll(strings.ToLower(v), "-u", ".")
			if u := strings.TrimPrefix(strings.ToLower(update), "u"); u != "" && u != update && u[0] >= '0' && u[0] <= '9' {
				v += "." + u
			}
			return v
		}
	}
	return func(v, _ string) string { return v }
}
