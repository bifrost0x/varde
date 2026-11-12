// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

const (
	githubAPI      = "https://api.github.com"
	githubMaxPages = 30
	// githubLowWater stops a refresh before the quota is exhausted, so the
	// next scheduled run is not blocked entirely.
	githubLowWater = 3
)

// GitHub fetches repository security advisories (REST API
// /repos/{owner}/{repo}/security-advisories, published only).
type GitHub struct {
	Deps
	// Token raises rate limits; optional.
	Token string
	// BaseURL overrides the API endpoint (tests, GitHub Enterprise).
	BaseURL string
	// Pause between requests; spreads anonymous usage (default 1 s).
	Pause time.Duration
	// MinInterval between checks of one repository (default 1 h), so
	// on-demand runs only fetch repositories that were not checked
	// recently.
	MinInterval time.Duration
}

func (g *GitHub) minInterval() time.Duration {
	if g.MinInterval > 0 {
		return g.MinInterval
	}
	return time.Hour
}

// Name implements Source.
func (*GitHub) Name() string { return "github" }

// SourceKey is the advisory source name stored per repository.
func githubSource(repo string) string { return "github:" + repo }

// Refresh implements Source.
func (g *GitHub) Refresh(ctx context.Context, apps []*catalog.App) (Result, error) {
	var res Result
	pause := g.Pause
	if pause == 0 {
		pause = time.Second
	}
	for _, app := range apps {
		for _, repo := range app.Advisories.GitHubRepos {
			st, err := g.Store.SourceState(ctx, "github", repo)
			if err != nil {
				return res, err
			}
			now := g.now()
			if !due(st, now) {
				res.Skipped++
				continue
			}
			if res.Requests > 0 {
				if err := g.sleep(ctx, pause); err != nil {
					return res, err
				}
			}
			changed, requests, remaining, err := g.refreshRepo(ctx, app.ID, repo, st)
			res.Requests += requests
			switch {
			case err != nil && isRateLimited(err):
				return res, fmt.Errorf("%w: %w", ErrRateLimited, recordFailure(ctx, g.Store, st, now, err))
			case err != nil && app.Origin == catalog.OriginDerived && notFound(err):
				// A derived entry may guess a repository that does not
				// exist: no advisories, not a failing source.
				st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(g.minInterval())
				if err := g.Store.PutSourceState(ctx, st); err != nil {
					return res, err
				}
				res.NotModified++
				continue
			case err != nil:
				// One broken repository must not stop the others.
				_ = recordFailure(ctx, g.Store, st, now, err)
				res.Skipped++
				continue
			case changed:
				res.Updated++
			default:
				res.NotModified++
			}
			if remaining >= 0 && remaining <= githubLowWater {
				return res, ErrRateLimited
			}
		}
	}
	return res, nil
}

// refreshRepo fetches all pages of one repository's advisories if the first
// page changed. It returns the remaining rate-limit budget (-1 if unknown).
func (g *GitHub) refreshRepo(ctx context.Context, appID, repo string, st store.SourceState) (changed bool, requests, remaining int, err error) {
	base := g.BaseURL
	if base == "" {
		base = githubAPI
	}
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return false, 0, -1, fmt.Errorf("invalid repository %q", repo)
	}
	next := fmt.Sprintf("%s/repos/%s/%s/security-advisories?state=published&per_page=100",
		base, url.PathEscape(owner), url.PathEscape(name))
	header := http.Header{
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
	}
	if g.Token != "" {
		header.Set("Authorization", "Bearer "+g.Token)
	}

	var items []ghsaItem
	var etag, lastMod string
	remaining = -1
	for page := 0; next != ""; page++ {
		if page >= githubMaxPages {
			return false, requests, remaining, fmt.Errorf("more than %d pages", githubMaxPages)
		}
		req := httpx.Request{URL: next, Header: header, MaxBytes: 32 << 20}
		if page == 0 {
			req.ETag, req.LastModified = st.ETag, st.LastModified
		}
		resp, err := g.HTTP.Do(ctx, req)
		requests++
		if err != nil {
			return false, requests, remaining, err
		}
		remaining = resp.RateLimit.Remaining
		if resp.NotModified {
			now := g.now()
			st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(g.minInterval())
			return false, requests, remaining, g.Store.PutSourceState(ctx, st)
		}
		if page == 0 {
			etag, lastMod = resp.ETag, resp.LastModified
		}
		var batch []ghsaItem
		if err := json.Unmarshal(resp.Body, &batch); err != nil {
			return false, requests, remaining, fmt.Errorf("decode advisories: %w", err)
		}
		items = append(items, batch...)
		next = httpx.NextLink(resp.Header)
		if next != "" && !strings.HasPrefix(next, base+"/") {
			return false, requests, remaining, fmt.Errorf("unexpected pagination link host in %q", next)
		}
		if next != "" {
			if err := g.sleep(ctx, 200*time.Millisecond); err != nil {
				return false, requests, remaining, err
			}
		}
	}

	recs := make([]store.AdvisoryRecord, 0, len(items))
	for _, it := range items {
		rec, err := convertGHSA(it, repo)
		if err != nil {
			continue // a single malformed record must not drop the rest
		}
		rec.AppID, rec.Source = appID, githubSource(repo)
		recs = append(recs, rec)
	}
	now := g.now()
	if err := g.Store.ReplaceAdvisories(ctx, appID, githubSource(repo), recs, now); err != nil {
		return false, requests, remaining, err
	}
	st.ETag, st.LastModified = etag, lastMod
	st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(g.minInterval())
	return true, requests, remaining, g.Store.PutSourceState(ctx, st)
}

// ghsaItem is the subset of the repository advisory response Varde reads.
type ghsaItem struct {
	GHSAID      string     `json:"ghsa_id"`
	CVEID       *string    `json:"cve_id"`
	HTMLURL     string     `json:"html_url"`
	Summary     string     `json:"summary"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	PublishedAt time.Time  `json:"published_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	WithdrawnAt *time.Time `json:"withdrawn_at"`
	CVSS        *struct {
		VectorString *string  `json:"vector_string"`
		Score        *float64 `json:"score"`
	} `json:"cvss"`
	CVSSSeverities *struct {
		V3 *ghsaCVSS `json:"cvss_v3"`
		V4 *ghsaCVSS `json:"cvss_v4"`
	} `json:"cvss_severities"`
	Vulnerabilities []struct {
		Package *struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string  `json:"vulnerable_version_range"`
		PatchedVersions        *string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

type ghsaCVSS struct {
	VectorString *string  `json:"vector_string"`
	Score        *float64 `json:"score"`
}

// convertGHSA maps a repository advisory to OSV. Version ranges that cannot
// be mapped are kept as affected entries without ranges, which match as
// unverified.
func convertGHSA(it ghsaItem, repo string) (store.AdvisoryRecord, error) {
	if !strings.HasPrefix(it.GHSAID, "GHSA-") {
		return store.AdvisoryRecord{}, errors.New("missing ghsa_id")
	}
	v := advisory.Vulnerability{
		SchemaVersion:    "1.6.0",
		ID:               it.GHSAID,
		Modified:         it.UpdatedAt.UTC(),
		Published:        it.PublishedAt.UTC(),
		Summary:          truncate(strings.TrimSpace(it.Summary), 512),
		Details:          truncate(it.Description, 32<<10),
		DatabaseSpecific: map[string]any{"repository": repo, "severity": it.Severity},
	}
	if it.WithdrawnAt != nil {
		t := it.WithdrawnAt.UTC()
		v.Withdrawn = &t
	}
	if it.CVEID != nil && strings.HasPrefix(*it.CVEID, "CVE-") {
		v.Aliases = []string{*it.CVEID}
	}
	if it.HTMLURL != "" {
		v.References = []advisory.Reference{{Type: "ADVISORY", URL: it.HTMLURL}}
	}

	var score float64
	if cs := it.CVSSSeverities; cs != nil {
		if cs.V3 != nil && cs.V3.VectorString != nil && *cs.V3.VectorString != "" {
			v.Severity = append(v.Severity, advisory.Severity{Type: "CVSS_V3", Score: *cs.V3.VectorString})
			if cs.V3.Score != nil {
				score = *cs.V3.Score
			}
		}
		if cs.V4 != nil && cs.V4.VectorString != nil && *cs.V4.VectorString != "" {
			v.Severity = append(v.Severity, advisory.Severity{Type: "CVSS_V4", Score: *cs.V4.VectorString})
			if score == 0 && cs.V4.Score != nil {
				score = *cs.V4.Score
			}
		}
	}
	if score == 0 && it.CVSS != nil && it.CVSS.Score != nil {
		score = *it.CVSS.Score
	}
	if score == 0 {
		for _, s := range v.Severity {
			if s.Type == "CVSS_V3" {
				if computed, err := advisory.CVSS3BaseScore(s.Score); err == nil {
					score = computed
				}
			}
		}
	}

	for _, vu := range it.Vulnerabilities {
		aff := advisory.Affected{}
		if vu.Package != nil {
			aff.Package = advisory.Package{Ecosystem: strings.TrimSpace(vu.Package.Ecosystem), Name: strings.TrimSpace(vu.Package.Name)}
		}
		patched := ""
		if vu.PatchedVersions != nil {
			patched = *vu.PatchedVersions
		}
		ranges, versions, err := advisory.ParseGitHubRange(vu.VulnerableVersionRange, patched)
		if err != nil {
			aff.DatabaseSpecific = map[string]any{
				"varde_unparsed_range":   truncate(vu.VulnerableVersionRange, 256),
				"varde_unparsed_patched": truncate(patched, 256),
			}
		} else {
			aff.Ranges, aff.Versions = ranges, versions
		}
		v.Affected = append(v.Affected, aff)
	}
	return store.AdvisoryRecord{Vuln: v, CVSS: score, SeverityLabel: strings.ToLower(it.Severity)}, nil
}

func notFound(err error) bool {
	var se *httpx.StatusError
	return errors.As(err, &se) && se.Status == http.StatusNotFound
}
