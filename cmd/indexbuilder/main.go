// SPDX-License-Identifier: Apache-2.0

// Command indexbuilder builds the first-party index (ADR 0038, stage 2b):
// index/images.tsv, a table of image repositories and the GitHub
// repositories of their projects. It visits candidate projects and keeps a
// pair only when the project or the registry states it; see
// internal/indexbuild. Candidates come from pointers that say where to
// look and are never evidence: a table of the app store lists (-hints) and
// GitHub's topic search (-topics).
//
//	go run ./cmd/indexbuilder -lists .cache/index-lists -topics self-hosted,selfhosted,homelab -cache .cache/index -out index/images.tsv
//
// -lists is a directory with the downloaded app store lists (unraid.json,
// umbrel.tar.gz; "make index-fetch" gets them).
//
// It only sends anonymous GET requests for public pages (a GITHUB_TOKEN in
// the environment is used for the search alone).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/indexbuild"
)

func main() {
	hints := flag.String("hints", "", "table of app store lists (image, repository, lists) used as pointers")
	lists := flag.String("lists", "", "directory with the downloaded app store lists (unraid.json, umbrel.tar.gz) used as pointers")
	topics := flag.String("topics", "", "comma-separated GitHub topics to search for candidate repositories")
	pages := flag.Int("topic-pages", 5, "pages of 100 repositories per topic")
	cache := flag.String("cache", "", "directory that keeps fetched pages (required)")
	out := flag.String("out", "", "file to write the table to (required)")
	workers := flag.Int("workers", 6, "concurrent repositories")
	force := flag.Bool("force", false, "write the table although many requests failed or it shrank a lot")
	offline := flag.Bool("offline", false, "send no request: build from the cache alone (pages not in it count as failed; -topics is ignored)")
	flag.Parse()
	if err := run(*hints, *lists, *topics, *pages, *cache, *out, *workers, *offline, *force); err != nil {
		fmt.Fprintln(os.Stderr, "indexbuilder:", err)
		os.Exit(1)
	}
}

// listPointers reduces the downloaded app store lists in dir to a table.
func listPointers(dir string) (*applists.Table, error) {
	var pairs []applists.Pair
	for _, l := range []struct {
		file  string
		parse func(*os.File) ([]applists.Pair, error)
	}{
		{"unraid.json", func(f *os.File) ([]applists.Pair, error) { return applists.ParseUnraid(f) }},
		{"umbrel.tar.gz", func(f *os.File) ([]applists.Pair, error) { return applists.ParseUmbrel(f) }},
	} {
		f, err := os.Open(filepath.Join(dir, l.file)) //nolint:gosec // path from the command line
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("notice: %s is not there; going on without it\n", l.file)
			continue
		}
		if err != nil {
			return nil, err
		}
		got, err := l.parse(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, got...)
	}
	table, _ := applists.Build(pairs)
	return table, nil
}

func run(hints, lists, topics string, pages int, cache, out string, workers int, offline, force bool) error {
	if cache == "" || out == "" {
		return errors.New("-cache and -out are required")
	}
	ctx := context.Background()
	var cands []indexbuild.Candidate
	if hints != "" {
		data, err := os.ReadFile(hints) //nolint:gosec // path from the command line
		if err != nil {
			return err
		}
		table, err := applists.Unmarshal(data)
		if err != nil {
			return fmt.Errorf("hints: %w", err)
		}
		cands = append(cands, indexbuild.HintCandidates(table)...)
		fmt.Printf("pointers from the app lists: %d\n", table.Len())
	}
	if lists != "" {
		table, err := listPointers(lists)
		if err != nil {
			return fmt.Errorf("lists: %w", err)
		}
		cands = append(cands, indexbuild.HintCandidates(table)...)
		fmt.Printf("pointers from the app lists: %d\n", table.Len())
	}
	if offline && topics != "" {
		fmt.Println("notice: offline, the topic search is not asked")
		topics = ""
	}
	if topics != "" {
		found, err := indexbuild.TopicCandidates(ctx, &http.Client{Timeout: 30 * time.Second}, "https://api.github.com",
			os.Getenv("GITHUB_TOKEN"), strings.Split(topics, ","), pages)
		cands = append(cands, found...)
		fmt.Printf("repositories from the topic search: %d\n", len(found))
		if err != nil {
			// The search is one of two pointers; without it the run goes on.
			fmt.Printf("notice: %v\n", err)
		}
	}
	if len(cands) == 0 {
		return errors.New("no candidates: give -lists, -hints or -topics")
	}
	fetcher := indexbuild.NewCachingFetcher(cache, indexbuild.MaxPageBytes)
	if offline {
		fetcher = indexbuild.NewOfflineFetcher(cache)
	}
	evidence, stats := indexbuild.Crawl(ctx, fetcher, cands, workers)
	table, dropped := indexbuild.Build(evidence)
	fmt.Printf("candidates %d, repositories %d, with a README or Compose file %d, Docker Hub pages %d, requests %d, failed %d, refused %d\n",
		stats.Candidates, stats.Repos, stats.Readmes, stats.HubPages, stats.Requests, stats.Failed, stats.RateLimited)
	if !force {
		// A partial run must not replace a good table.
		previous := 0
		if data, err := os.ReadFile(out); err == nil { //nolint:gosec // path from the command line
			if old, err := applists.Unmarshal(data); err == nil {
				previous = old.Len()
			}
		}
		if err := indexbuild.Guard(stats, previous, table.Len()); err != nil {
			return fmt.Errorf("table not written: %w (use -force to write it anyway)", err)
		}
	}
	if err := os.WriteFile(out, table.Marshal(), 0o644); err != nil { //nolint:gosec // published data file
		return err
	}
	confirmed := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(table.Marshal()), "\n"), "\n") {
		if f := strings.Split(line, "\t"); len(f) == 3 && strings.Contains(f[2], ",") {
			confirmed++
		}
	}
	reasons := map[string]int{}
	for _, r := range dropped {
		reasons[r]++
	}
	names := make([]string, 0, len(reasons))
	for r := range reasons {
		names = append(names, r)
	}
	sort.Strings(names)
	fmt.Printf("table: %d images, %d confirmed by two kinds of evidence\n", table.Len(), confirmed)
	for _, r := range names {
		fmt.Printf("dropped, %s: %d\n", r, reasons[r])
	}
	return nil
}
