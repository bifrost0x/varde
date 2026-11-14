// SPDX-License-Identifier: Apache-2.0

package match

import (
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/version"
)

// The package names are the ones repository advisories really carry.
func TestForeignPackage(t *testing.T) {
	gitea := &catalog.App{ID: "gitea", Name: "Gitea",
		Images: []catalog.Image{{Match: "gitea/gitea"}},
		Advisories: catalog.Advisories{GitHubRepos: []string{"go-gitea/gitea"},
			OSVPackages: []catalog.OSVPackage{{Ecosystem: "Go", Name: "gitea.dev"}}}}
	derived := func(repo string) *catalog.App {
		return &catalog.App{ID: "gh-" + strings.ReplaceAll(repo, "/", "-"), Name: repo,
			Advisories: catalog.Advisories{GitHubRepos: []string{repo}}}
	}
	cases := []struct {
		app     *catalog.App
		pkg     string
		foreign bool
	}{
		// Another project beside the server, under the project's own name.
		{gitea, "gitea.com/gitea/runner", true},
		{gitea, "code.gitea.io/gitea", false},
		{gitea, "gitea.dev", false},
		{gitea, "gitea.dev/modules/git", false},
		{gitea, "gitea", false},
		{gitea, "ssh", false}, // a bare word proves nothing
		// A library the report blames.
		{derived("traefik/traefik"), "golang.org/x/oauth2/jws", true},
		{derived("traefik/traefik"), "github.com/traefik/traefik/v3", false},
		{derived("0xJacky/nginx-ui"), "github.com/uozi-tech/cosy", true},
		{derived("0xJacky/nginx-ui"), "github.com/0xJacky/Nginx-UI", false},
		// The app's own repository, whatever it is called.
		{derived("gotify/server"), "github.com/gotify/server/v2", false},
		{derived("caddyserver/caddy"), "github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver", false},
		// A sibling image of the same author.
		{derived("louislam/uptime-kuma"), "louislam/dockge", true},
		{derived("louislam/uptime-kuma"), "louislam/uptime-kuma", false},
		// Parts of the app under the project's name, and registries.
		{derived("pi-hole/pi-hole"), "pi-hole/FTL", false},
		{derived("actualbudget/actual"), "@actual-app/sync-server", false},
		{derived("immich-app/immich"), "ghcr.io/immich-app/immich-server", false},
		{derived("dani-garcia/vaultwarden"), "vaultwarden/server", false},
		// Free text and file names may be the app.
		{derived("redis/redis"), "redis-server", false},
		{derived("advplyr/audiobookshelf"), "FileSystemController.js", false},
		{derived("0xJacky/nginx-ui"), "api/settings/settings.go,internal/logrotate/logrotate.go", false},
		{derived("home-assistant/core"), "Home Assistant Core", false},
		{derived("keycloak/keycloak"), "org.keycloak:keycloak-services", false},
		{derived("open-webui/open-webui"), "", false},
	}
	for _, c := range cases {
		if got := newIdentity(c.app).foreign(c.pkg); got != c.foreign {
			t.Errorf("%s: foreign(%q) = %v, want %v", c.app.ID, c.pkg, got, c.foreign)
		}
	}
}

func named(id, pkg, vuln, patched string) Advisory {
	a := ghsa(id, nil, vuln, patched)
	a.Vuln.Affected[0].Package = advisory.Package{Ecosystem: "go", Name: pkg}
	return a
}

// An advisory about a runner must neither alert for the server nor name
// the runner's version as the server's update.
func TestOtherProjectIsUnverifiedAndNoTarget(t *testing.T) {
	a := &catalog.App{ID: "gitea", Name: "Gitea", Version: catalog.VersionSpec{Scheme: version.SemVer},
		Advisories: catalog.Advisories{GitHubRepos: []string{"go-gitea/gitea"}}}
	advs := []Advisory{
		named("GHSA-runner", "gitea.com/gitea/runner", "< 3.0.0", "3.0.0"),
		named("GHSA-server", "code.gitea.io/gitea", "< 1.27.1", "1.27.1"),
	}
	fs := Match(Input{App: a, Version: "1.20.0"}, advs, Enrichment{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %v", fs)
	}
	runner, server := fs[0], fs[1]
	if runner.State != Unverified || runner.FixedIn != "" || runner.Target != nil {
		t.Errorf("runner: state=%s fixed=%q target=%v", runner.State, runner.FixedIn, runner.Target)
	}
	if !strings.Contains(runner.Evidence.Reason, "go/gitea.com/gitea/runner, not Gitea") {
		t.Errorf("runner reason: %q", runner.Evidence.Reason)
	}
	if server.State != Affected || server.FixedIn != "1.27.1" {
		t.Errorf("server: state=%s fixed=%q", server.State, server.FixedIn)
	}
	if server.Target == nil || server.Target.Version != "1.27.1" || server.Target.Total != 1 {
		t.Errorf("target: %+v", server.Target)
	}
	// Outside the other project's range there is nothing to check.
	if fs := Match(Input{App: a, Version: "3.0.0"}, advs[:1], Enrichment{}); len(fs) != 0 {
		t.Errorf("above the range: %v", fs)
	}
}

// With the app's own package beside it, the other project's entry is left
// out and decides nothing.
func TestOtherProjectBesideOwnPackage(t *testing.T) {
	a := &catalog.App{ID: "traefik", Name: "Traefik", Version: catalog.VersionSpec{Scheme: version.SemVer},
		Advisories: catalog.Advisories{GitHubRepos: []string{"traefik/traefik"}}}
	adv := named("GHSA-both", "github.com/traefik/traefik/v3", "< 3.6.2", "3.6.2")
	lib := named("x", "golang.org/x/oauth2/jws", "< 0.27.0", "0.27.0").Vuln.Affected[0]
	adv.Vuln.Affected = append([]advisory.Affected{lib}, adv.Vuln.Affected...)

	f := one(t, Match(Input{App: a, Version: "3.6.0"}, []Advisory{adv}, Enrichment{}))
	if f.State != Affected || f.FixedIn != "3.6.2" || f.Evidence.Package != "go/github.com/traefik/traefik/v3" {
		t.Errorf("state=%s fixed=%q package=%q", f.State, f.FixedIn, f.Evidence.Package)
	}
	// The library's range (< 0.27.0) must not keep a fixed version affected.
	if fs := Match(Input{App: a, Version: "3.6.2"}, []Advisory{adv}, Enrichment{}); len(fs) != 0 {
		t.Errorf("fixed version still reported: %v", fs)
	}
}

// A renamed project publishes under its old module path: doubted, not lost.
func TestRenamedProjectIsKept(t *testing.T) {
	a := &catalog.App{ID: "gh-moby-moby", Name: "moby/moby", Version: catalog.VersionSpec{Scheme: version.SemVer},
		Advisories: catalog.Advisories{GitHubRepos: []string{"moby/moby"}}}
	adv := named("GHSA-old", "github.com/docker/docker", "< 25.0.2", "25.0.2")
	f := one(t, Match(Input{App: a, Version: "24.0.0"}, []Advisory{adv}, Enrichment{}))
	if f.State != Unverified {
		t.Errorf("state=%s", f.State)
	}
}

// A reviewed list of the app's packages stays the only rule where it exists.
func TestPackageFilterOverrulesNames(t *testing.T) {
	a := app(version.SemVer, catalog.PackageFilter{Name: "gitea.com/gitea/runner"})
	adv := named("GHSA-runner", "gitea.com/gitea/runner", "< 3.0.0", "3.0.0")
	f := one(t, Match(Input{App: a, Version: "1.20.0"}, []Advisory{adv}, Enrichment{}))
	if f.State != Affected || f.FixedIn != "3.0.0" {
		t.Errorf("state=%s fixed=%q", f.State, f.FixedIn)
	}
}

// A record of the data package read from a second source ranks below what
// the project published, whatever the IDs: the project's range decides.
func TestOriginRanksBelowTheProject(t *testing.T) {
	a := app(version.SemVer)
	project := ghsa("GHSA-zzzz", []string{"CVE-2026-0001"}, "< 1.2.0", "1.2.0")
	project.Source = "feed"
	nvd := ghsa("CVE-2026-0001", nil, "< 9.0.0", "9.0.0")
	nvd.Source = "feed"
	nvd.Vuln = advisory.WithOrigin(nvd.Vuln, "nvd:cpe:2.3:a:acme:app")

	f := one(t, Match(Input{App: a, Version: "1.1.0"}, []Advisory{nvd, project}, Enrichment{}))
	if f.AdvisoryID != "GHSA-zzzz" || f.FixedIn != "1.2.0" || f.Evidence.Origin != "" {
		t.Errorf("best = %s fixed %s origin %q", f.AdvisoryID, f.FixedIn, f.Evidence.Origin)
	}
	// Alone, the second source's record is the finding and says where it
	// was read from.
	f = one(t, Match(Input{App: a, Version: "1.1.0"}, []Advisory{nvd}, Enrichment{}))
	if f.AdvisoryID != "CVE-2026-0001" || f.Evidence.Origin != "nvd:cpe:2.3:a:acme:app" {
		t.Errorf("alone = %s origin %q", f.AdvisoryID, f.Evidence.Origin)
	}
}

// A project advisory that only says from which version a flaw exists is
// given its end by a second record of the same flaw: patched versions are
// no longer affected for ever, and the others get an update to name.
func TestOpenRangeIsCompleted(t *testing.T) {
	a := app(version.SemVer)
	project := Advisory{Source: "feed", CVSS: 7, Vuln: advisory.Vulnerability{ID: "GHSA-open", Aliases: []string{"CVE-2026-0002"},
		Affected: []advisory.Affected{{Package: advisory.Package{Name: "redis-server"},
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "2.8"}}}}}}}}
	line := func(from, fixed string) advisory.Range {
		return advisory.Range{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: from}, {Fixed: fixed}}}
	}
	second := func(ranges ...advisory.Range) Advisory {
		v := advisory.Vulnerability{ID: "CVE-2026-0002", Affected: []advisory.Affected{{Package: advisory.Package{Name: "redis"}, Ranges: ranges}}}
		return Advisory{Source: "feed", Vuln: advisory.WithOrigin(v, "nvd:cpe:2.3:a:redis:redis")}
	}
	nvd := second(line("2.8", "6.2.19"), line("7.2.0", "7.2.10"), line("7.4.0", "7.4.5"), line("8.0.0", "8.0.3"))

	// Alone, the project's record keeps every version affected, without a fix.
	f := one(t, Match(Input{App: a, Version: "8.2.2"}, []Advisory{project}, Enrichment{}))
	if f.State != Affected || f.FixedIn != "" || f.Step != nil {
		t.Fatalf("alone: %s fixed %q step %v", f.State, f.FixedIn, f.Step)
	}

	cases := []struct {
		version, fixed string // fixed "" with affected false: no finding
		affected       bool
	}{
		{"6.2.5", "6.2.19", true}, // in a range of the second record
		{"7.0.0", "7.2.10", true}, // a line the second record does not list: the next fix
		{"7.2.9", "7.2.10", true}, //
		{"7.2.10", "", false},     // the fix of its own line
		{"7.2.11", "", false},     //
		{"7.4.2", "7.4.5", true},  // above 7.2.10, but its own line is fixed later
		{"8.0.3", "", false},      //
		{"8.2.2", "", false},      // above every fix
	}
	for _, c := range cases {
		fs := Match(Input{App: a, Version: c.version}, []Advisory{nvd, project}, Enrichment{})
		if !c.affected {
			if len(fs) != 0 {
				t.Errorf("%s: still reported: %v", c.version, fs)
			}
			continue
		}
		f := one(t, fs)
		// The project's record stays the finding; the end comes from the other.
		if f.AdvisoryID != "GHSA-open" || f.State != Affected || f.FixedIn != c.fixed || f.Evidence.CompletedBy != "CVE-2026-0002" {
			t.Errorf("%s: %s %s fixed %q completed by %q, want fixed %q", c.version, f.AdvisoryID, f.State, f.FixedIn, f.Evidence.CompletedBy, c.fixed)
		}
		if f.Step == nil || f.Step.Version != c.fixed || f.Target == nil || f.Target.Fixes != 1 {
			t.Errorf("%s: step %+v target %+v", c.version, f.Step, f.Target)
		}
	}

	// What the second record leaves out is not read as fixed: without the
	// 7.4 line, 7.4.2 stays affected until the next fix it does name.
	gap := second(line("2.8", "6.2.19"), line("7.2.0", "7.2.10"), line("8.0.0", "8.0.3"))
	f = one(t, Match(Input{App: a, Version: "7.4.2"}, []Advisory{gap, project}, Enrichment{}))
	if f.State != Affected || f.FixedIn != "8.0.3" {
		t.Errorf("gap: %s fixed %q", f.State, f.FixedIn)
	}

	// A project record with an end of its own is never overruled.
	closed := ghsa("GHSA-closed", []string{"CVE-2026-0002"}, "< 9.0.0", "9.0.0")
	closed.Source = "feed"
	f = one(t, Match(Input{App: a, Version: "8.2.2"}, []Advisory{nvd, closed}, Enrichment{}))
	if f.AdvisoryID != "GHSA-closed" || f.FixedIn != "9.0.0" || f.Evidence.CompletedBy != "" {
		t.Errorf("closed: %s fixed %q completed by %q", f.AdvisoryID, f.FixedIn, f.Evidence.CompletedBy)
	}
}

// releaseNote is a record the builder made from a release note (ADR 0044).
func releaseNote(id, fixed string, aliases ...string) Advisory {
	v := advisory.Vulnerability{ID: id, Aliases: aliases, Summary: "Release " + fixed + " names a security fix",
		Affected: []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeEcosystem,
			Events:           []advisory.Event{{Introduced: "0"}, {Fixed: fixed}},
			DatabaseSpecific: map[string]any{advisory.RangeInferred: true}}}}}}
	return Advisory{Source: "feed", Vuln: advisory.WithOrigin(v, advisory.OriginRelease)}
}

// A release note never makes a version affected: below the release it is
// a finding to check with the release as the fix, at or above it nothing.
func TestReleaseNoteIsNeverAffected(t *testing.T) {
	a := app(version.SemVer)
	note := releaseNote("VARDE-REL-1", "1.5.0")
	f := one(t, Match(Input{App: a, Version: "1.4.0"}, []Advisory{note}, Enrichment{}))
	if f.State != Unverified || f.FixedIn != "1.5.0" || f.Target != nil || f.Evidence.Origin != advisory.OriginRelease ||
		!strings.Contains(f.Evidence.Reason, "release notes of 1.5.0") {
		t.Errorf("below the release: %+v", f)
	}
	if fs := Match(Input{App: a, Version: "1.5.0"}, []Advisory{note}, Enrichment{}); len(fs) != 0 {
		t.Errorf("at the release: %+v", fs)
	}
	// A record that lost its inferred mark is still no more than a note.
	bare := note
	bare.Vuln.Affected = []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeEcosystem,
		Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.5.0"}}}}}}
	if f := one(t, Match(Input{App: a, Version: "1.4.0"}, []Advisory{bare}, Enrichment{})); f.State != Unverified {
		t.Errorf("without the mark: %+v", f)
	}
}

// Where the project's advisory describes the same flaw, it decides, also
// when it clears the running version.
func TestReleaseNoteRanksLast(t *testing.T) {
	a := app(version.SemVer)
	project := ghsa("GHSA-pppp", []string{"CVE-2026-0007"}, ">= 1.3.0, < 1.4.0", "1.4.0")
	note := releaseNote("VARDE-REL-2", "1.5.0", "CVE-2026-0007")
	if fs := Match(Input{App: a, Version: "1.4.2"}, []Advisory{note, project}, Enrichment{}); len(fs) != 0 {
		t.Errorf("the note outvoted the project's advisory: %+v", fs)
	}
	f := one(t, Match(Input{App: a, Version: "1.3.5"}, []Advisory{note, project}, Enrichment{}))
	if f.State != Affected || f.AdvisoryID != "GHSA-pppp" || f.FixedIn != "1.4.0" {
		t.Errorf("project's flaw: %+v", f)
	}
}
