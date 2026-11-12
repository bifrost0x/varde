// SPDX-License-Identifier: Apache-2.0

package match

import (
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
)

func distroRecord(id, cve, eco, name string, events ...advisory.Event) Advisory {
	return Advisory{Source: SourceDistro, Vuln: advisory.Vulnerability{
		ID: id, Upstream: []string{cve},
		Affected: []advisory.Affected{{
			Package: advisory.Package{Ecosystem: eco, Name: name},
			Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: events}},
		}},
	}}
}

func TestMatchDistro(t *testing.T) {
	app := &catalog.App{ID: "nginx", Version: catalog.VersionSpec{Scheme: "semver"}}
	upstream := Advisory{Source: "nvd", CVSS: 7.5, Vuln: advisory.Vulnerability{
		ID: "CVE-2026-1", Summary: "upstream text",
		Affected: []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.29.0"}}}}}},
	}}
	fixed := distroRecord("DEBIAN-CVE-2026-1", "CVE-2026-1", "Debian:12", "nginx", advisory.Event{Introduced: "0"}, advisory.Event{Fixed: "1.22.1-9+deb12u8"})
	// Events out of order and a second release, which must be ignored.
	fixed.Vuln.Affected = append(fixed.Vuln.Affected, advisory.Affected{
		Package: advisory.Package{Ecosystem: "Debian:13", Name: "nginx"},
		Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Fixed: "1.26.3-3+deb13u2"}, {Introduced: "0"}}}},
	})
	unfixed := distroRecord("DEBIAN-CVE-2026-2", "CVE-2026-2", "Debian:12", "nginx", advisory.Event{Introduced: "0"})
	introduced := distroRecord("DEBIAN-CVE-2026-3", "CVE-2026-3", "Debian:12", "nginx", advisory.Event{Introduced: "1.22.1-9+deb12u5"}, advisory.Event{Fixed: "1.22.1-9+deb12u6"})
	lastAffected := distroRecord("DEBIAN-CVE-2026-4", "CVE-2026-4", "Debian:12", "nginx", advisory.Event{Introduced: "0"}, advisory.Event{LastAffected: "1.22.1-9+deb12u7"})
	unimportant := distroRecord("DEBIAN-CVE-2026-7", "CVE-2026-7", "Debian:12", "nginx", advisory.Event{Introduced: "0"})
	unimportant.Vuln.Affected[0].EcosystemSpecific = map[string]any{"urgency": "unimportant"}
	otherPkg := distroRecord("DEBIAN-CVE-2026-5", "CVE-2026-5", "Debian:12", "nginx-legacy", advisory.Event{Introduced: "0"})
	upstreamOnly := Advisory{Source: "nvd", Vuln: advisory.Vulnerability{ID: "CVE-2026-6", Affected: []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "9.0.0"}}}}}}}}
	advs := []Advisory{upstream, fixed, unfixed, introduced, lastAffected, otherPkg, upstreamOnly, unimportant}

	run := func(v string) map[string]Finding {
		out := map[string]Finding{}
		for _, f := range Match(Input{App: app, Distro: &distro.Package{Ecosystem: "Debian:12", Name: "nginx", Version: v}}, advs, Enrichment{KEV: map[string]bool{"CVE-2026-1": true}}) {
			out[f.AdvisoryID] = f
		}
		return out
	}
	got := run("1.22.1-9+deb12u8")
	// Patched: the upstream range (below 1.29.0) does not count; the
	// unfixed record does; the upstream-only advisory stays unverified.
	if _, ok := got["DEBIAN-CVE-2026-1"]; ok {
		t.Error("patched package affected")
	}
	if _, ok := got["CVE-2026-1"]; ok {
		t.Error("upstream range decided for a distribution package")
	}
	if f := got["DEBIAN-CVE-2026-2"]; f.State != Affected || f.FixedIn != "" || !strings.Contains(f.Evidence.Reason, "not fixed") {
		t.Errorf("unfixed: %+v", f)
	}
	if f := got["CVE-2026-6"]; f.State != Unverified || !strings.Contains(f.Evidence.Reason, "no record") {
		t.Errorf("upstream only: %+v", f)
	}
	if f := got["DEBIAN-CVE-2026-7"]; f.State != Unverified || !strings.Contains(f.Evidence.Reason, "unimportant") {
		t.Errorf("unimportant: %+v", f)
	}
	if _, ok := got["DEBIAN-CVE-2026-5"]; ok {
		t.Error("record of another package used")
	}
	if _, ok := got["DEBIAN-CVE-2026-3"]; ok {
		t.Error("version after the fix affected")
	}
	if _, ok := got["DEBIAN-CVE-2026-4"]; ok {
		t.Error("version after last_affected affected")
	}

	got = run("1.22.1-9+deb12u5")
	f := got["DEBIAN-CVE-2026-1"]
	if f.State != Affected || f.FixedIn != "1.22.1-9+deb12u8" || !f.KEV || f.Summary != "upstream text" || f.CVSS != 7.5 || f.Evidence.Version != "1.22.1-9+deb12u5" {
		t.Errorf("before the fix: %+v", f)
	}
	if !strings.Contains(strings.Join(f.Aliases, " "), "CVE-2026-1") {
		t.Errorf("CVE alias missing: %v", f.Aliases)
	}
	if got["DEBIAN-CVE-2026-3"].State != Affected || got["DEBIAN-CVE-2026-4"].State != Affected {
		t.Errorf("introduced or last_affected range: %+v", got)
	}
	if _, ok := run("1.22.1-9+deb12u4")["DEBIAN-CVE-2026-3"]; ok {
		t.Error("version before introduced affected")
	}

	// An unconfirmed version is never affected.
	for _, f := range Match(Input{App: app, Doubt: "test", Distro: &distro.Package{Ecosystem: "Debian:12", Name: "nginx", Version: "1.22.1-9"}}, advs, Enrichment{}) {
		if f.State == Affected {
			t.Errorf("doubt ignored: %+v", f)
		}
	}
	// A version the ecosystem cannot order is unverified.
	alpine := []Advisory{distroRecord("ALPINE-CVE-2026-1", "CVE-2026-1", "Alpine:v3.22", "nginx", advisory.Event{Introduced: "0"}, advisory.Event{Fixed: "1.28.3-r2"})}
	fs := Match(Input{App: app, Distro: &distro.Package{Ecosystem: "Alpine:v3.22", Name: "nginx", Version: "custom build"}}, alpine, Enrichment{})
	if len(fs) != 1 || fs[0].State != Unverified {
		t.Errorf("not comparable: %+v", fs)
	}
}

// A notice listing several CVEs is not grouped by its upstream list; a
// per-CVE record joins its CVE.
func TestRecordIDs(t *testing.T) {
	perCVE := Advisory{Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2026-1", Upstream: []string{"CVE-2026-1"}}}
	notice := Advisory{Vuln: advisory.Vulnerability{ID: "DSA-1-1", Upstream: []string{"CVE-2026-1", "CVE-2026-2"}}}
	if got := strings.Join(recordIDs(perCVE), " "); got != "DEBIAN-CVE-2026-1 CVE-2026-1" {
		t.Errorf("per CVE: %s", got)
	}
	if got := strings.Join(recordIDs(notice), " "); got != "DSA-1-1" {
		t.Errorf("notice: %s", got)
	}
}

// A notice covering several CVEs gives one finding per CVE, which joins
// the CVE's upstream advisory; the notice is the linked reference.
func TestMatchDistroNotices(t *testing.T) {
	app := &catalog.App{ID: "nginx", Version: catalog.VersionSpec{Scheme: "semver"}}
	notice := distroRecord("ALSA-2026:7343", "CVE-2026-1", "AlmaLinux:9", "nginx", advisory.Event{Introduced: "0"}, advisory.Event{Fixed: "2:1.26.3-2.el9.1"})
	notice.Vuln.Upstream = []string{"CVE-2026-1", "CVE-2026-2"}
	// An older stream's notice for the same CVE says nothing about this one.
	old := distroRecord("ALSA-2024:1", "CVE-2026-1", "AlmaLinux:9", "nginx", advisory.Event{Introduced: "0"}, advisory.Event{Fixed: "1:1.20.1-1.el9"})
	old.Vuln.Upstream = []string{"CVE-2026-1"}
	upstream := Advisory{Source: "nvd", CVSS: 9.1, Vuln: advisory.Vulnerability{ID: "CVE-2026-2"}}
	fs := Match(Input{App: app, Distro: &distro.Package{Ecosystem: "AlmaLinux:9", Name: "nginx", Version: "2:1.26.3-2.el9"}}, []Advisory{notice, old, upstream}, Enrichment{})
	if len(fs) != 2 {
		t.Fatalf("findings: %+v", fs)
	}
	for _, f := range fs {
		if f.State != Affected || f.FixedIn != "2:1.26.3-2.el9.1" || f.URL != "https://osv.dev/vulnerability/ALSA-2026:7343" {
			t.Errorf("%s: %+v", f.AdvisoryID, f)
		}
	}
	if fs[1].AdvisoryID != "CVE-2026-2" || fs[1].CVSS != 9.1 {
		t.Errorf("CVE-2026-2 not joined with its upstream advisory: %+v", fs[1])
	}
	if fs := Match(Input{App: app, Distro: &distro.Package{Ecosystem: "AlmaLinux:9", Name: "nginx", Version: "2:1.26.3-2.el9.1"}}, []Advisory{notice, old}, Enrichment{}); len(fs) != 0 {
		t.Errorf("patched: %+v", fs)
	}
}

// Debian 11 has notices only. DLA-3942-1 fixed six CVEs in
// 1.1.1n-0+deb11u6; DLA-3942-2 fixes them again in 1.1.1w-0+deb11u2. The
// installed 1.1.1w-0+deb11u1 is past the first and before the second: it
// is affected, as Debian's tracker (and Trivy and Grype) say.
func TestMatchDistroFollowUpNotice(t *testing.T) {
	app := &catalog.App{ID: "openssl", Version: catalog.VersionSpec{Scheme: "semver"}}
	first := distroRecord("DLA-3942-1", "CVE-2023-5678", "Debian:11", "openssl", advisory.Event{Introduced: "0"}, advisory.Event{Fixed: "1.1.1n-0+deb11u6"})
	first.Vuln.Upstream = []string{"CVE-2023-5678"}
	second := distroRecord("DLA-3942-2", "CVE-2023-5678", "Debian:11", "openssl", advisory.Event{Introduced: "0"}, advisory.Event{Fixed: "1.1.1w-0+deb11u2"})
	second.Vuln.Upstream = []string{"CVE-2023-5678"}
	fs := Match(Input{App: app, Distro: &distro.Package{Ecosystem: "Debian:11", Name: "openssl", Version: "1.1.1w-0+deb11u1"}}, []Advisory{first, second}, Enrichment{})
	if len(fs) != 1 || fs[0].AdvisoryID != "CVE-2023-5678" || fs[0].State != Affected || fs[0].FixedIn != "1.1.1w-0+deb11u2" {
		t.Fatalf("findings: %+v", fs)
	}
}
