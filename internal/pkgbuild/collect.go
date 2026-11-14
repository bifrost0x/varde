// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bifrost0x/varde/internal/advisory/sources"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/store"
)

// Options configure Collect.
type Options struct {
	// Store keeps the advisories and the request state between builds, so
	// that a normal day costs conditional requests only.
	Store *store.Store
	HTTP  *httpx.Client
	// Token authorises the GitHub requests; optional.
	Token string
	// GitHubURL, KEVURL and EPSSURL override the upstream endpoints (tests).
	GitHubURL, KEVURL, EPSSURL string
	Now                        func() time.Time
	// Sleep waits; replaceable in tests.
	Sleep func(ctx context.Context, d time.Duration) error
	// MaxWait bounds the total time spent waiting for rate limits to
	// reset (default 5 h).
	MaxWait time.Duration
	Log     *slog.Logger
	// Apps are the catalog apps the second sources are asked about: OSV
	// for those with osv_packages, the NVD for those NVDApp accepts. Nil
	// leaves both out.
	Apps []*catalog.App
	// OSV and NVD switch the second sources on; OSVURL and NVDURL
	// override their endpoints (tests), NVDKey raises the NVD's limit.
	OSV, NVD               bool
	OSVURL, NVDURL, NVDKey string
	// ReleaseNotes switches on the reads of release notes of the
	// repositories whose advisories are not complete (ADR 0044).
	ReleaseNotes bool
}

// Stats describe one collection.
type Stats struct {
	// Repos is the number of repositories asked about, Failed how many of
	// them could not be read.
	Repos, Failed int
	// Requests is the number of requests to GitHub, Waits how often the
	// builder waited for the rate limit to reset.
	Requests, Waits int
	// Failing names the repositories that could not be read, each with the
	// day it was last read and the error: what is published for them is
	// that old.
	Failing []string
	// OSVApps and NVDApps are the apps the second sources were asked
	// about, OSVRequests and NVDRequests the requests that took. OSVError
	// and NVDError say why a source stopped early; what the store holds
	// from earlier builds still ships.
	OSVApps, NVDApps, OSVRequests, NVDRequests int
	OSVError, NVDError                         string
	// NotesRepos are the repositories whose release notes are read,
	// NotesRequests the requests that took and NotesError why the reads
	// stopped early; what earlier builds stored still ships.
	NotesRepos, NotesRequests int
	NotesError                string
}

// NVDApp reports whether the NVD is asked about app: every app with a CPE.
// What ships of the answer depends on the app (NVDAll).
func NVDApp(app *catalog.App) bool { return len(app.Advisories.CPE) > 0 }

// NVDAll reports whether every NVD record of app ships: for a project
// that does not publish every flaw in a form a program can compare
// (coverage partial or limited). Where a project's own advisories are
// complete, CVE records derived from them add nothing but coarser ranges
// (ADR 0017); of those only the records ship that complete a project
// advisory which names no end of its affected versions.
func NVDAll(app *catalog.App) bool {
	return NVDApp(app) && app.Advisories.Coverage != catalog.CoverageFull
}

// OSVApp reports whether osv.dev is asked about app.
func OSVApp(app *catalog.App) bool { return len(app.Advisories.OSVPackages) > 0 }

// minInterval is the shortest time between two checks of one repository.
// The package is built once a day; a second build the same day (a manual
// run) only asks about what the first one did not reach.
const minInterval = 12 * time.Hour

// Collect fetches the advisories of repos, then KEV and EPSS, into the
// store. One broken repository does not stop the others; it is counted.
// When GitHub's rate limit is reached Collect waits for the reset and goes
// on, so that a package is never built from half the repositories.
func Collect(ctx context.Context, repos []Repo, o Options) (Stats, error) {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxWait <= 0 {
		o.MaxWait = 5 * time.Hour
	}
	deps := sources.Deps{HTTP: o.HTTP, Store: o.Store, Now: o.Now, Sleep: o.Sleep}
	sleep := o.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	apps := make([]*catalog.App, 0, len(repos))
	names := map[string]bool{}
	for _, r := range repos {
		apps = append(apps, r.App)
		names[r.Name] = true
	}
	stats := Stats{Repos: len(repos)}
	gh := &sources.GitHub{Deps: deps, Token: o.Token, BaseURL: o.GitHubURL, MinInterval: minInterval}
	if o.Token != "" {
		// An authorised client need not spread its requests.
		gh.Pause = time.Millisecond
	}
	var waited time.Duration
	for idle := 0; ; {
		res, err := gh.Refresh(ctx, apps)
		stats.Requests += res.Requests
		if err == nil {
			break
		}
		if !errors.Is(err, sources.ErrRateLimited) {
			return stats, fmt.Errorf("github: %w", err)
		}
		wait, err := untilReset(ctx, o.Store, o.Now())
		if err != nil {
			return stats, err
		}
		if wait == 0 {
			// The limit is close but not reached: GitHub names the reset
			// with the refusal. Go on until it does.
			if idle++; idle <= 8 {
				continue
			}
			wait = 5 * time.Minute
		}
		idle = 0
		if waited += wait; waited > o.MaxWait {
			return stats, fmt.Errorf("github: the rate limit resets in %s, beyond the %s the builder waits: %w", wait.Round(time.Second), o.MaxWait, sources.ErrRateLimited)
		}
		o.Log.Info("rate limit reached; waiting for the reset", "wait", wait.Round(time.Second))
		stats.Waits++
		if err := sleep(ctx, wait+5*time.Second); err != nil {
			return stats, err
		}
	}
	states, err := o.Store.SourceStates(ctx)
	if err != nil {
		return stats, err
	}
	for _, st := range states {
		if st.Source == "github" && names[st.Key] && st.LastError != "" {
			stats.Failed++
			since := "never read"
			if !st.LastSuccess.IsZero() {
				since = "last read " + st.LastSuccess.UTC().Format("2006-01-02")
			}
			stats.Failing = append(stats.Failing, fmt.Sprintf("%s (%s): %s", st.Key, since, st.LastError))
			o.Log.Warn("repository could not be read", "repository", st.Key, "since", since, "err", st.LastError)
		}
	}
	if o.ReleaseNotes {
		if err := collectNotes(ctx, repos, o, deps, &stats); err != nil {
			return stats, err
		}
	}
	// The second sources: what a project publishes elsewhere than in its
	// repository. They never stop the build: a source that fails or runs
	// into its limit leaves what earlier builds stored, and the summary
	// says so.
	if o.OSV {
		var apps []*catalog.App
		for _, a := range o.Apps {
			if OSVApp(a) {
				apps = append(apps, a)
			}
		}
		stats.OSVApps = len(apps)
		res, err := (&sources.OSV{Deps: deps, BaseURL: o.OSVURL}).Refresh(ctx, apps)
		stats.OSVRequests = res.Requests
		if err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			stats.OSVError = err.Error()
			o.Log.Warn("osv.dev not read completely; the package carries what earlier builds stored", "err", err)
		}
	}
	if o.NVD {
		var apps []*catalog.App
		for _, a := range o.Apps {
			if NVDApp(a) {
				apps = append(apps, a)
			}
		}
		stats.NVDApps = len(apps)
		res, err := (&sources.NVD{Deps: deps, BaseURL: o.NVDURL, APIKey: o.NVDKey}).Refresh(ctx, apps)
		stats.NVDRequests = res.Requests
		if err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			stats.NVDError = err.Error()
			o.Log.Warn("the NVD not read completely; the package carries what earlier builds stored", "err", err)
		}
	}
	// Enrichment last: EPSS is asked for the CVEs of the advisories above.
	// Both are due with every build, whatever time of day the last one ran.
	for _, key := range [][2]string{{"kev", "catalog"}, {"epss", "scores"}} {
		st, err := o.Store.SourceState(ctx, key[0], key[1])
		if err != nil {
			return stats, err
		}
		st.Source, st.Key, st.NextRun = key[0], key[1], time.Time{}
		if err := o.Store.PutSourceState(ctx, st); err != nil {
			return stats, err
		}
	}
	if _, err := (&sources.KEV{Deps: deps, URL: o.KEVURL}).Refresh(ctx, nil); err != nil {
		return stats, err
	}
	if _, err := (&sources.EPSS{Deps: deps, URL: o.EPSSURL}).Refresh(ctx, nil); err != nil {
		return stats, err
	}
	return stats, nil
}

// collectNotes reads the release notes of the repositories whose
// advisories are not complete. It never fails the build: a rate limit or
// an error leaves what earlier builds stored, and the repositories not
// reached are due first in the next build.
func collectNotes(ctx context.Context, repos []Repo, o Options, deps sources.Deps, stats *Stats) error {
	apps := make([]*catalog.App, 0, len(repos))
	for _, r := range repos {
		if !r.Complete {
			apps = append(apps, r.App)
		}
	}
	stats.NotesRepos = len(apps)
	n := &sources.ReleaseNotes{Deps: deps, Token: o.Token, BaseURL: o.GitHubURL, MinInterval: minInterval}
	if o.Token != "" {
		n.Pause = time.Millisecond
	}
	res, err := n.Refresh(ctx, apps)
	stats.NotesRequests = res.Requests
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stats.NotesError = err.Error()
		o.Log.Warn("release notes not read completely; the package carries what earlier builds stored", "err", err)
	}
	return nil
}

// untilReset is the time until the earliest rate-limit reset GitHub named
// in a refusal, zero when it named none.
func untilReset(ctx context.Context, st *store.Store, now time.Time) (time.Duration, error) {
	states, err := st.SourceStates(ctx)
	if err != nil {
		return 0, err
	}
	var wait time.Duration
	for _, s := range states {
		if s.Source != "github" || s.LastError == "" || !s.NextRun.After(now) {
			continue
		}
		if d := s.NextRun.Sub(now); wait == 0 || d < wait {
			wait = d
		}
	}
	return wait, nil
}
