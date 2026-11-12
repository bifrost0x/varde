// SPDX-License-Identifier: Apache-2.0

package indexbuild

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFetcher answers from a map; anything else is 404.
type fakeFetcher struct {
	mu    sync.Mutex
	pages map[string]string
	codes map[string]int
	errs  map[string]error
	calls map[string]int
}

func (f *fakeFetcher) Get(_ context.Context, url string) ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[url]++
	if err := f.errs[url]; err != nil {
		return nil, 0, err
	}
	if c := f.codes[url]; c != 0 {
		return []byte("limited"), c, nil
	}
	if body, ok := f.pages[url]; ok {
		return []byte(body), http.StatusOK, nil
	}
	return nil, http.StatusNotFound, nil
}

const (
	rawBase = "https://raw.githubusercontent.com/"
	hubBase = "https://hub.docker.com/v2/repositories/"
)

func TestCrawl(t *testing.T) {
	f := &fakeFetcher{
		pages: map[string]string{
			// A hinted pair both sides confirm.
			rawBase + "tandoorrecipes/recipes/HEAD/README.md": "```\ndocker pull vabene1111/recipes\n```",
			hubBase + "vabene1111/recipes/":                   `{"description":"Recipes","full_description":"Source: https://github.com/TandoorRecipes/recipes"}`,
			// A hinted pair nothing confirms: the README names another image.
			rawBase + "o/unrelated/HEAD/README.md": "docker pull o/something-else",
			hubBase + "x/claimed/":                 `{"full_description":"no links here"}`,
			// A repository found by search: its Compose file names the image.
			rawBase + "o/app/HEAD/readme.md":          "# app\nSee the compose file.",
			rawBase + "o/app/HEAD/docker-compose.yml": "services:\n  app:\n    image: ghcr.io/o/app:1\n  db:\n    image: postgres:16\n",
			// The Hub answers with a web page instead of JSON.
			rawBase + "o/html/HEAD/README.md": "docker pull o/html",
			hubBase + "o/html/":               "<html>please sign in</html>",
			// Only the Hub page confirms a hinted pair.
			hubBase + "o/hubonly/": `{"full_description":"https://github.com/o/hubonly-src"}`,
		},
		codes: map[string]int{hubBase + "o/limited/": http.StatusTooManyRequests},
		errs:  map[string]error{rawBase + "o/down/HEAD/README.md": errors.New("connection reset")},
	}
	cands := []Candidate{
		{Repo: "github.com/tandoorrecipes/recipes", Image: "docker.io/vabene1111/recipes"},
		{Repo: "github.com/o/unrelated", Image: "docker.io/x/claimed"},
		{Repo: "github.com/o/app"},
		{Repo: "github.com/o/html", Image: "docker.io/o/html"},
		{Repo: "github.com/o/hubonly-src", Image: "docker.io/o/hubonly"},
		{Repo: "github.com/o/limited", Image: "docker.io/o/limited"},
		{Repo: "github.com/o/down", Image: "docker.io/o/down"},
		{Repo: "github.com/tandoorrecipes/recipes", Image: "docker.io/vabene1111/recipes"}, // a duplicate hint
	}
	ev, stats := Crawl(context.Background(), f, cands, 4)
	tab, _ := Build(ev)
	want := "docker.io/o/html\tgithub.com/o/html\treadme\n" +
		"docker.io/o/hubonly\tgithub.com/o/hubonly-src\thub\n" +
		"docker.io/o/something-else\tgithub.com/o/unrelated\treadme\n" +
		"docker.io/vabene1111/recipes\tgithub.com/tandoorrecipes/recipes\thub,readme\n" +
		"ghcr.io/o/app\tgithub.com/o/app\tghcr,readme\n"
	if got := string(tab.Marshal()); got != want {
		t.Errorf("table:\n%s\nwant:\n%s", got, want)
	}
	if stats.Candidates != 7 || stats.Failed == 0 || stats.RateLimited != 1 {
		t.Errorf("stats = %+v", stats)
	}
	// The hinted image the README does not name is not evidence.
	if _, ok := tab.Lookup("docker.io/x/claimed"); ok {
		t.Error("a hint became a row without first-party evidence")
	}
	// Each page is asked once, also for the duplicate hint.
	if n := f.calls[hubBase+"vabene1111/recipes/"]; n != 1 {
		t.Errorf("hub page asked %d times", n)
	}
}

func TestCachingFetcher(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/missing":
			http.NotFound(w, r)
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
		default:
			_, _ = w.Write([]byte("hello " + r.URL.Path))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	ctx := context.Background()
	for range 2 {
		f := NewCachingFetcher(dir, 1024)
		body, code, err := f.Get(ctx, srv.URL+"/a")
		if err != nil || code != http.StatusOK || string(body) != "hello /a" {
			t.Fatalf("get: %q %d %v", body, code, err)
		}
		if _, code, err := f.Get(ctx, srv.URL+"/missing"); err != nil || code != http.StatusNotFound {
			t.Fatalf("missing: %d %v", code, err)
		}
		if _, _, err := f.Get(ctx, srv.URL+"/big"); err == nil || !strings.Contains(err.Error(), "larger") {
			t.Fatalf("oversized answer: %v", err)
		}
	}
	// The second fetcher answered /a and /missing from the cache; the
	// refused answer is not cached.
	if hits != 4 {
		t.Errorf("%d requests, want 4", hits)
	}
}

func TestTopicCandidates(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		if r.URL.Query().Get("q") != "topic:self-hosted" {
			http.Error(w, "limited", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"full_name":"Immich-App/immich"},{"full_name":"x/fork","fork":true},{"full_name":"x/old","archived":true},{"full_name":"immich-app/immich"}]}`))
	}))
	defer srv.Close()
	got, err := TopicCandidates(context.Background(), srv.Client(), srv.URL, "tok", []string{"self-hosted"}, 3)
	if err != nil || len(got) != 1 || got[0] != (Candidate{Repo: "github.com/immich-app/immich"}) {
		t.Fatalf("candidates = %+v, %v", got, err)
	}
	if len(auth) != 1 || auth[0] != "Bearer tok" {
		t.Errorf("requests: %v", auth)
	}
	// A refused search is reported as unavailable, with what was found so far.
	got, err = TopicCandidates(context.Background(), srv.Client(), srv.URL, "", []string{"self-hosted", "homelab"}, 1)
	if !errors.Is(err, ErrSearchUnavailable) || len(got) != 1 {
		t.Errorf("refused search: %+v, %v", got, err)
	}
}

// A refused request waits for the limit to reset and is asked again; other
// requests to that host wait too instead of running into the limit.
func TestCachingFetcherWaitsForRateLimit(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits <= 2 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	var slept []time.Duration
	f := NewCachingFetcher(t.TempDir(), 1024)
	f.(*cachingFetcher).sleep = func(_ context.Context, d time.Duration) { slept = append(slept, d) }
	body, code, err := f.Get(context.Background(), srv.URL+"/page")
	if err != nil || code != http.StatusOK || string(body) != "ok" {
		t.Fatalf("get: %q %d %v", body, code, err)
	}
	if hits != 3 || len(slept) != 2 || slept[0] < 7*time.Second || slept[0] > 9*time.Second {
		t.Errorf("hits %d, slept %v", hits, slept)
	}

	// A host that keeps refusing is given up on, with the refusal reported.
	hits = -100
	if _, code, err := f.Get(context.Background(), srv.URL+"/other"); err != nil || code != http.StatusTooManyRequests {
		t.Errorf("persistent refusal: %d %v", code, err)
	}
	if n := hits + 100; n != maxRateLimitTries {
		t.Errorf("asked %d times, want %d", n, maxRateLimitTries)
	}
}

// Offline, the fetcher answers from the cache and never asks the network.
func TestOfflineFetcher(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte("page"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ctx := context.Background()
	if _, _, err := NewCachingFetcher(dir, 1024).Get(ctx, srv.URL+"/cached"); err != nil {
		t.Fatal(err)
	}
	off := NewOfflineFetcher(dir)
	body, code, err := off.Get(ctx, srv.URL+"/cached")
	if err != nil || code != http.StatusOK || string(body) != "page" {
		t.Fatalf("cached page: %q %d %v", body, code, err)
	}
	if _, _, err := off.Get(ctx, srv.URL+"/never-fetched"); !errors.Is(err, ErrNotCached) {
		t.Fatalf("page that is not cached: %v", err)
	}
	if hits != 1 {
		t.Errorf("%d requests; offline must not ask the network", hits)
	}
}
