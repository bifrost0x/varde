// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

// ReleaseNotes turns the security fixes a project names only in its
// release notes into records (ADR 0044). The package builder runs it; an
// installation never does, since asking about a repository tells GitHub
// that the app runs there.
type ReleaseNotes struct {
	Deps
	// Token raises rate limits; optional.
	Token string
	// BaseURL overrides the API endpoint (tests).
	BaseURL string
	// Pause between requests (default 1 s).
	Pause time.Duration
	// MinInterval between checks of one repository (default 12 h).
	MinInterval time.Duration
}

// ReleaseNotesState is the source name of a repository's request state.
const ReleaseNotesState = "release-notes"

const (
	// releasesPerRepo is how many of the newest releases are read.
	releasesPerRepo = 50
	// maxMentionLines bounds the quoted lines of one release.
	maxMentionLines = 5
	// maxMentionLine bounds one quoted line.
	maxMentionLine = 300
	// maxReleaseBody bounds the part of a release body that is read.
	maxReleaseBody = 64 << 10
)

// ReleaseNotesSource is the source a repository's release-note records
// are stored under.
func ReleaseNotesSource(repo string) string { return "release:" + repo }

// Name implements Source.
func (*ReleaseNotes) Name() string { return ReleaseNotesState }

func (n *ReleaseNotes) minInterval() time.Duration {
	if n.MinInterval > 0 {
		return n.MinInterval
	}
	return 12 * time.Hour
}

// Refresh reads the releases of every repository of apps that is due. It
// stops at a rate limit with ErrRateLimited; what earlier runs stored
// stays.
func (n *ReleaseNotes) Refresh(ctx context.Context, apps []*catalog.App) (Result, error) {
	var res Result
	pause := n.Pause
	if pause == 0 {
		pause = time.Second
	}
	for _, app := range apps {
		for _, repo := range app.Advisories.GitHubRepos {
			st, err := n.Store.SourceState(ctx, ReleaseNotesState, repo)
			if err != nil {
				return res, err
			}
			now := n.now()
			if !due(st, now) {
				res.Skipped++
				continue
			}
			if res.Requests > 0 {
				if err := n.sleep(ctx, pause); err != nil {
					return res, err
				}
			}
			changed, remaining, err := n.refreshRepo(ctx, app.ID, repo, st)
			res.Requests++
			switch {
			case err != nil && isRateLimited(err):
				return res, fmt.Errorf("%w: %w", ErrRateLimited, recordFailure(ctx, n.Store, st, now, err))
			case err != nil && notFound(err):
				// A derived entry may name a repository that does not
				// exist, or one without releases: nothing to read.
				st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(n.minInterval())
				if err := n.Store.PutSourceState(ctx, st); err != nil {
					return res, err
				}
				res.NotModified++
				continue
			case err != nil:
				_ = recordFailure(ctx, n.Store, st, now, err)
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

// ghRelease is the subset of a GitHub release Varde reads.
type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
}

func (n *ReleaseNotes) refreshRepo(ctx context.Context, appID, repo string, st store.SourceState) (changed bool, remaining int, err error) {
	base := n.BaseURL
	if base == "" {
		base = githubAPI
	}
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return false, -1, fmt.Errorf("invalid repository %q", repo)
	}
	header := http.Header{
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
	}
	if n.Token != "" {
		header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := n.HTTP.Do(ctx, httpx.Request{
		URL:    fmt.Sprintf("%s/repos/%s/%s/releases?per_page=%d", base, url.PathEscape(owner), url.PathEscape(name), releasesPerRepo),
		Header: header, MaxBytes: 16 << 20, ETag: st.ETag, LastModified: st.LastModified,
	})
	if err != nil {
		return false, -1, err
	}
	remaining = resp.RateLimit.Remaining
	now := n.now()
	if resp.NotModified {
		st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(n.minInterval())
		return false, remaining, n.Store.PutSourceState(ctx, st)
	}
	var rels []ghRelease
	if err := json.Unmarshal(resp.Body, &rels); err != nil {
		return false, remaining, fmt.Errorf("decode releases: %w", err)
	}
	recs := releaseRecords(repo, rels)
	for i := range recs {
		recs[i].AppID = appID
		recs[i].Source = ReleaseNotesSource(repo)
	}
	if err := n.Store.ReplaceAdvisories(ctx, appID, ReleaseNotesSource(repo), recs, now); err != nil {
		return false, remaining, err
	}
	st.ETag, st.LastModified = resp.ETag, resp.LastModified
	st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(n.minInterval())
	return true, remaining, n.Store.PutSourceState(ctx, st)
}

// releaseRecords turns the releases of repo that name a security fix into
// records: one per CVE or GHSA ID a release names, one for a release that
// names none. Each says that versions before the release lack the fix,
// with a range marked inferred, so it is never more than a finding to
// check (ADR 0044).
func releaseRecords(repo string, rels []ghRelease) []store.AdvisoryRecord {
	var out []store.AdvisoryRecord
	seen := map[string]bool{}
	for _, r := range rels {
		if r.Draft || r.Prerelease {
			continue
		}
		ver, ok := ReleaseVersion(r.TagName)
		if !ok {
			continue
		}
		body := r.Body
		if len(body) > maxReleaseBody {
			body = strings.ToValidUTF8(body[:maxReleaseBody], "")
		}
		m := SecurityMentions(r.Name + "\n" + body)
		if len(m.Lines) == 0 {
			continue
		}
		ids := m.IDs
		if len(ids) == 0 {
			ids = []string{""}
		}
		for _, id := range ids {
			v := releaseVuln(repo, r, ver, id, m.Lines)
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			out = append(out, store.AdvisoryRecord{Vuln: v})
		}
	}
	return out
}

func releaseVuln(repo string, r ghRelease, ver, id string, lines []string) advisory.Vulnerability {
	sum := sha256.Sum256([]byte(repo + "\x00" + r.TagName + "\x00" + id))
	summary := "Release " + ver + " names a security fix"
	if id != "" {
		summary += " (" + id + ")"
	}
	v := advisory.Vulnerability{
		SchemaVersion: "1.6.0",
		ID:            "VARDE-REL-" + hex.EncodeToString(sum[:8]),
		Modified:      r.PublishedAt.UTC(),
		Published:     r.PublishedAt.UTC(),
		Summary:       summary,
		Details:       "The release notes of " + ver + " say:\n" + strings.Join(lines, "\n"),
		DatabaseSpecific: map[string]any{
			"repository": repo,
			"release":    truncate(r.TagName, 128),
		},
		Affected: []advisory.Affected{{
			Ranges: []advisory.Range{{
				Type:             advisory.RangeEcosystem,
				Events:           []advisory.Event{{Introduced: "0"}, {Fixed: ver}},
				DatabaseSpecific: map[string]any{advisory.RangeInferred: true},
			}},
		}},
	}
	if id != "" {
		v.Aliases = []string{id}
	}
	if strings.HasPrefix(r.HTMLURL, "https://github.com/") {
		v.References = []advisory.Reference{{Type: "WEB", URL: r.HTMLURL}}
	}
	return v
}

// releaseTag is a tag that names a plain version: digits and dots, with
// an optional leading "v". Anything else (pre-releases, product prefixes,
// dates with words) is skipped rather than guessed.
var releaseTag = regexp.MustCompile(`^[vV]?(\d{1,9}(?:\.\d{1,9}){0,3})$`)

// ReleaseVersion returns the version a release tag names.
func ReleaseVersion(tag string) (string, bool) {
	m := releaseTag.FindStringSubmatch(strings.TrimSpace(tag))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Mentions are what a release text says about security.
type Mentions struct {
	// Lines are the lines that name a security fix, trimmed.
	Lines []string
	// IDs are the CVE and GHSA IDs those lines name, sorted.
	IDs []string
}

var (
	cveMention  = regexp.MustCompile(`\bCVE-\d{4}-\d{4,9}\b`)
	ghsaMention = regexp.MustCompile(`\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b`)
	// securityHeading is a Markdown heading of a security section
	// ("### Security", "## Security fixes").
	securityHeading = regexp.MustCompile(`(?i)^#{1,6}\s*(?:\W\s*)?security(?:\s+(?:fix(?:es)?|updates?|patch(?:es)?))?\s*:?\s*$`)
	// securityWording names a fix of a flaw in the app itself.
	securityWording = regexp.MustCompile(`(?i)\b(?:` +
		`security\s+(?:fix(?:es|ed)?|issues?|vulnerabilit(?:y|ies)|patch(?:es|ed)?|release|advisor(?:y|ies)|bugs?|flaws?|holes?|problems?|hardening)` +
		`|fix(?:es|ed)?\s+(?:an?\s+|the\s+|several\s+|multiple\s+)?(?:security|vulnerabilit)` +
		`|vulnerabilit(?:y|ies)` +
		`|cross[- ]site\s+(?:scripting|request\s+forgery)|xss|csrf|ssrf|xxe` +
		`|remote\s+code\s+execution|rce` +
		`|(?:sql|command|code|template|ldap|header)\s+injection` +
		`|(?:path|directory)\s+traversal` +
		`|auth(?:entication|orization)?\s+bypass` +
		`|privilege\s+escalation` +
		`|arbitrary\s+file\s+(?:read|write|upload|access|deletion)` +
		`|open\s+redirect` +
		`|denial[- ]of[- ]service` +
		`)\b`)
	// dependencyBump is a line that updates a dependency; a CVE it names
	// belongs to the dependency, not the app.
	dependencyBump = regexp.MustCompile(`(?i)^(?:[-*+]\s*)?(?:\[[^\]]*\]\s*)?(?:` +
		`bump(?:s|ed)?\b|build\(deps(?:-dev)?\)|chore\(deps(?:-dev)?\)|fix\(deps\)|deps(?:\(.*?\))?:|` +
		`update(?:s|d)?\s+(?:dependency|dependencies|module|package|rust\s+crate|npm)\b|` +
		`upgrade(?:s|d)?\s+(?:dependency|dependencies)\b)`)
	// botAuthor is a line written by a dependency bot.
	botAuthor = regexp.MustCompile(`(?i)@(?:dependabot|renovate|renovate-bot|snyk-bot)\b|\b(?:dependabot|renovate)\[bot\]`)
)

// SecurityMentions finds the lines of a release text that name a security
// fix: lines with an ID or the wording, and the lines of a section headed
// "Security". A dependency bump never counts.
func SecurityMentions(text string) Mentions {
	var m Mentions
	ids := map[string]bool{}
	section := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if strings.HasPrefix(line, "#") {
			// A heading opens or ends a security section; it still names
			// a fix itself when it carries an ID or the wording.
			section = securityHeading.MatchString(line)
		}
		if line == "" || dependencyBump.MatchString(line) || botAuthor.MatchString(line) {
			continue
		}
		found := cveMention.FindAllString(line, -1)
		found = append(found, ghsaMention.FindAllString(line, -1)...)
		if len(found) == 0 && !section && !securityWording.MatchString(line) {
			continue
		}
		for _, id := range found {
			ids[id] = true
		}
		if len(m.Lines) < maxMentionLines {
			m.Lines = append(m.Lines, truncate(line, maxMentionLine))
		}
	}
	for id := range ids {
		m.IDs = append(m.IDs, id)
	}
	sort.Strings(m.IDs)
	return m
}
