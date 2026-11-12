// SPDX-License-Identifier: Apache-2.0

package indexbuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/applists"
)

// Fetcher gets one public page. A status other than 200 is not an error.
type Fetcher interface {
	Get(ctx context.Context, url string) (body []byte, status int, err error)
}

// Candidate is a place to look: a repository, and optionally an image a
// pointer (an app store list) ties to it. A pointer is never evidence.
type Candidate struct {
	Repo  string // "github.com/<owner>/<name>", lower case
	Image string // normalised image repository, or empty
}

// Stats counts what a crawl met.
type Stats struct {
	Candidates  int // distinct candidates
	Repos       int // repositories visited
	Readmes     int // repositories with a README or Compose file
	HubPages    int // Docker Hub pages read
	Requests    int // pages asked for
	Failed      int // requests that failed or returned something unreadable
	RateLimited int // requests refused with 429 or 403
}

// Bounds of a crawl.
const (
	maxCandidates = 50000
	// MaxPageBytes bounds one fetched file.
	MaxPageBytes = 1 << 20
)

// repoFiles are read from the root of a repository's default branch: the
// first README found, and both Compose names.
var (
	readmeNames  = []string{"README.md", "readme.md"}
	composeNames = []string{"docker-compose.yml", "compose.yaml"}
)

// Crawl visits the candidates and returns the first-party evidence found:
// for every repository the images its README and Compose files name, and
// for those and the pointed-to images whether the registry confirms the
// tie (the Docker Hub page links the repository, or the image is in the
// owner's namespace on GitHub's registry). A request that fails is counted
// and skipped; the crawl goes on.
func Crawl(ctx context.Context, f Fetcher, cands []Candidate, workers int) ([]Evidence, Stats) {
	if workers < 1 {
		workers = 1
	}
	var stats Stats
	// repository -> pointed-to images
	hinted := map[string]map[string]bool{}
	seen := map[Candidate]bool{}
	for _, c := range cands {
		if c.Repo == "" || seen[c] || len(seen) >= maxCandidates {
			continue
		}
		seen[c] = true
		if hinted[c.Repo] == nil {
			hinted[c.Repo] = map[string]bool{}
		}
		if c.Image != "" {
			hinted[c.Repo][c.Image] = true
		}
	}
	stats.Candidates = len(seen)
	repos := make([]string, 0, len(hinted))
	for r := range hinted {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	stats.Repos = len(repos)

	var mu sync.Mutex // guards stats and evidence
	var evidence []Evidence
	count := func(fn func(*Stats)) {
		mu.Lock()
		fn(&stats)
		mu.Unlock()
	}
	// get fetches a page and classifies what is not a readable answer.
	get := func(u string) ([]byte, bool) {
		count(func(s *Stats) { s.Requests++ })
		body, status, err := f.Get(ctx, u)
		switch {
		case err != nil:
			count(func(s *Stats) { s.Failed++ })
		case status == http.StatusOK:
			return body, true
		case status == http.StatusTooManyRequests || status == http.StatusForbidden:
			count(func(s *Stats) { s.RateLimited++ })
		case status != http.StatusNotFound:
			count(func(s *Stats) { s.Failed++ })
		}
		return nil, false
	}
	// Docker Hub pages are asked once, whoever points to the image.
	hub := &memo{get: func(image string) string {
		body, ok := get("https://hub.docker.com/v2/repositories/" + strings.TrimPrefix(image, "docker.io/") + "/")
		if !ok {
			return ""
		}
		var page struct {
			Description     string `json:"description"`
			FullDescription string `json:"full_description"`
		}
		if json.Unmarshal(body, &page) != nil {
			count(func(s *Stats) { s.Failed++ })
			return ""
		}
		count(func(s *Stats) { s.HubPages++ })
		return page.Description + "\n" + page.FullDescription
	}}

	visit := func(repo string) {
		base := "https://raw.githubusercontent.com/" + strings.TrimPrefix(repo, "github.com/") + "/HEAD/"
		var texts []string
		for _, name := range readmeNames {
			if body, ok := get(base + name); ok {
				texts = append(texts, string(body))
				break
			}
		}
		for _, name := range composeNames {
			if body, ok := get(base + name); ok {
				texts = append(texts, string(body))
			}
		}
		if len(texts) > 0 {
			count(func(s *Stats) { s.Readmes++ })
		}
		var found []Evidence
		images := map[string]bool{}
		for _, image := range ImagesIn(strings.Join(texts, "\n")) {
			images[image] = true
			found = append(found, Evidence{Image: image, Repo: repo, Kind: KindReadme})
		}
		for image := range hinted[repo] {
			images[image] = true
		}
		owner := strings.Split(repo, "/")[1]
		for image := range images {
			switch {
			case strings.HasPrefix(image, "ghcr.io/"+owner+"/"):
				found = append(found, Evidence{Image: image, Repo: repo, Kind: KindGHCR})
			case strings.HasPrefix(image, "docker.io/") && !applists.IsHelper(image):
				if LinksRepo(hub.lookup(image), repo) {
					found = append(found, Evidence{Image: image, Repo: repo, Kind: KindHub})
				}
			}
		}
		mu.Lock()
		evidence = append(evidence, found...)
		mu.Unlock()
	}

	work := make(chan string)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repo := range work {
				visit(repo)
			}
		}()
	}
	for _, r := range repos {
		if ctx.Err() != nil {
			break
		}
		work <- r
	}
	close(work)
	wg.Wait()
	return evidence, stats
}

// memo computes a value once per key, also under concurrent callers.
type memo struct {
	get func(key string) string
	mu  sync.Mutex
	m   map[string]*memoEntry
}

type memoEntry struct {
	once sync.Once
	val  string
}

func (m *memo) lookup(key string) string {
	m.mu.Lock()
	if m.m == nil {
		m.m = map[string]*memoEntry{}
	}
	e := m.m[key]
	if e == nil {
		e = &memoEntry{}
		m.m[key] = e
	}
	m.mu.Unlock()
	e.once.Do(func() { e.val = m.get(key) })
	return e.val
}

// cachingFetcher fetches public pages anonymously and keeps the answers in
// a directory, so a rerun asks nothing twice and builds the same table.
type cachingFetcher struct {
	dir    string
	limit  int64
	client *http.Client
	// sleep waits; replaceable in tests.
	sleep func(ctx context.Context, d time.Duration)
	// offline answers from the cache only and never asks the network.
	offline bool

	mu sync.Mutex
	// blockedUntil is, per host, when its rate limit resets.
	blockedUntil map[string]time.Time
}

// Rate limits: a refused request is asked again after the limit resets.
const (
	maxRateLimitTries = 4
	maxRateLimitWait  = 2 * time.Minute
)

// NewCachingFetcher returns a Fetcher that stores answers (200 and 404) in
// dir, one file per URL, and refuses bodies over limit bytes.
func NewCachingFetcher(dir string, limit int64) Fetcher {
	return &cachingFetcher{dir: dir, limit: limit, client: &http.Client{Timeout: 30 * time.Second},
		sleep: func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		}, blockedUntil: map[string]time.Time{}}
}

// ErrNotCached reports a page an offline fetcher does not have.
var ErrNotCached = errors.New("not in the cache")

// NewOfflineFetcher returns a Fetcher that answers from the cache in dir
// and never asks the network: a table can be rebuilt from what an earlier
// run fetched.
func NewOfflineFetcher(dir string) Fetcher {
	return &cachingFetcher{dir: dir, offline: true}
}

func (c *cachingFetcher) path(u string) string {
	sum := sha256.Sum256([]byte(u))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:]))
}

// Get implements Fetcher. A cached file is "<status>\n<body>".
func (c *cachingFetcher) Get(ctx context.Context, u string) ([]byte, int, error) {
	if data, err := os.ReadFile(c.path(u)); err == nil { //nolint:gosec // name is a hash inside the cache directory
		if head, body, ok := strings.Cut(string(data), "\n"); ok {
			if status, err := strconv.Atoi(head); err == nil {
				return []byte(body), status, nil
			}
		}
	}
	if c.offline {
		return nil, 0, fmt.Errorf("%s: %w", u, ErrNotCached)
	}
	parsed, err := url.ParseRequestURI(u)
	if err != nil {
		return nil, 0, err
	}
	var body []byte
	var status int
	for try := 1; ; try++ {
		// A host that said "not now" is left alone until its limit resets.
		c.mu.Lock()
		wait := time.Until(c.blockedUntil[parsed.Host])
		c.mu.Unlock()
		if wait > 0 {
			c.sleep(ctx, wait)
		}
		var retry time.Duration
		if body, status, retry, err = c.fetch(ctx, u); err != nil {
			return nil, 0, err
		}
		if status != http.StatusTooManyRequests || try >= maxRateLimitTries || ctx.Err() != nil {
			break
		}
		c.mu.Lock()
		if until := time.Now().Add(retry); until.After(c.blockedUntil[parsed.Host]) {
			c.blockedUntil[parsed.Host] = until
		}
		c.mu.Unlock()
	}
	// Only lasting answers are kept; a refusal or a server error is asked
	// again next time.
	if status == http.StatusOK || status == http.StatusNotFound {
		if err := os.MkdirAll(c.dir, 0o700); err != nil {
			return nil, 0, err
		}
		data := append([]byte(strconv.Itoa(status)+"\n"), body...)
		if err := os.WriteFile(c.path(u), data, 0o600); err != nil {
			return nil, 0, err
		}
	}
	return body, status, nil
}

// fetch makes one request. For a refusal it also returns how long the
// server asks to wait (Retry-After, or the reset time of its rate limit).
func (c *cachingFetcher) fetch(ctx context.Context, u string) ([]byte, int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("User-Agent", "varde-indexbuilder")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.limit+1))
	if err != nil {
		return nil, 0, 0, err
	}
	if int64(len(body)) > c.limit {
		return nil, 0, 0, fmt.Errorf("%s: answer larger than allowed", u)
	}
	retry := 30 * time.Second
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		retry = time.Duration(s) * time.Second
	} else if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		if d := time.Until(time.Unix(reset, 0)); d > 0 {
			retry = d
		}
	}
	// A moment more than asked, and never longer than the cap.
	retry = min(retry+time.Second, maxRateLimitWait)
	return body, resp.StatusCode, retry, nil
}

// Limits of Guard.
const (
	// maxTroubleShare is the share of failed or refused requests above
	// which a run is not trusted.
	maxTroubleShare = 0.05
	// maxShrink is how much smaller than the previous table a new one may be.
	maxShrink = 0.10
)

// Guard refuses the result of a run that cannot be trusted to replace the
// previous table: too many requests failed or were refused, or the table
// lost too many rows (previous is the row count of the table in place, 0
// for none). A partial run would otherwise drop rows whose pages merely
// could not be read.
func Guard(s Stats, previous, current int) error {
	if s.Requests == 0 {
		return errors.New("no page was asked for")
	}
	if share := float64(s.Failed+s.RateLimited) / float64(s.Requests); share > maxTroubleShare {
		return fmt.Errorf("%d of %d requests failed or were refused (%.1f %%, limit %.0f %%)",
			s.Failed+s.RateLimited, s.Requests, share*100, maxTroubleShare*100)
	}
	if previous > 0 && float64(current) < float64(previous)*(1-maxShrink) {
		return fmt.Errorf("the table shrank from %d to %d rows (limit %.0f %%)", previous, current, maxShrink*100)
	}
	return nil
}

// HintCandidates turns a table of app store lists into candidates: its
// pairs say where to look, nothing more.
func HintCandidates(t *applists.Table) []Candidate {
	var out []Candidate
	for _, line := range strings.Split(strings.TrimSuffix(string(t.Marshal()), "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 3 {
			out = append(out, Candidate{Repo: f[1], Image: f[0]})
		}
	}
	return out
}

// ErrSearchUnavailable reports that GitHub's search could not be asked.
var ErrSearchUnavailable = errors.New("GitHub search is not available")

// TopicCandidates asks GitHub's repository search for the most starred
// repositories of each topic (pages of 100) and returns them as candidates
// without an image. token is optional; without one the search allows only
// a few requests a minute.
func TopicCandidates(ctx context.Context, client *http.Client, api, token string, topics []string, pages int) ([]Candidate, error) {
	var out []Candidate
	seen := map[string]bool{}
	for _, topic := range topics {
		for page := 1; page <= pages; page++ {
			u := fmt.Sprintf("%s/search/repositories?q=%s&sort=stars&order=desc&per_page=100&page=%d", api, url.QueryEscape("topic:"+topic), page)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return out, err
			}
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("User-Agent", "varde-indexbuilder")
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			resp, err := client.Do(req)
			if err != nil {
				return out, fmt.Errorf("%w: %w", ErrSearchUnavailable, err)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				return out, fmt.Errorf("%w: topic %s page %d: status %d", ErrSearchUnavailable, topic, page, resp.StatusCode)
			}
			var res struct {
				Items []struct {
					FullName string `json:"full_name"`
					Fork     bool   `json:"fork"`
					Archived bool   `json:"archived"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &res); err != nil {
				return out, fmt.Errorf("%w: topic %s: %w", ErrSearchUnavailable, topic, err)
			}
			for _, it := range res.Items {
				repo, ok := applists.NormaliseRepo("https://github.com/" + it.FullName)
				if !ok || it.Fork || it.Archived || seen[repo] {
					continue
				}
				seen[repo] = true
				out = append(out, Candidate{Repo: repo})
			}
			if len(res.Items) < 100 {
				break
			}
		}
	}
	return out, nil
}
