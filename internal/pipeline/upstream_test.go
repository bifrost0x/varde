// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/upstream"
)

const (
	runDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// lab is one container with image packages, the advisories of those
// packages and a KEV list, analysed by a real pipeline over a real store.
type lab struct {
	t   *testing.T
	st  *store.Store
	p   *Pipeline
	now time.Time
	wid string
}

func deb(name, v string) inventory.Package {
	return inventory.Package{Manager: "dpkg", Name: name, Version: v, Source: name}
}

// debRecord is a Debian record of pkg fixed in fixed, with its CVE alias.
func debRecord(id, cve, pkg, fixed string) store.AdvisoryRecord {
	return store.AdvisoryRecord{Source: match.SourceDistro, Vuln: advisory.Vulnerability{ID: id, Aliases: []string{cve}, Modified: time.Now(),
		Affected: []advisory.Affected{{Package: advisory.Package{Ecosystem: "Debian:12", Name: pkg},
			Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}}}}}}
}

// newLab stores the container c with pkgs, records per package and the KEV
// CVEs; registryOn is the registry setting.
func newLab(t *testing.T, c inventory.Container, pkgs []inventory.Package, records map[string][]store.AdvisoryRecord, kev []string, registryOn bool) *lab {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	cat, err := catalog.Load(fstest.MapFS{"immich.yaml": {Data: []byte(entry)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.UpsertHost(ctx, inventory.Host{ID: "docker", Name: "docker", Kind: inventory.HostDocker, Source: inventory.SourceLocal, Arch: "x86_64", LastContact: now}); err != nil {
		t.Fatal(err)
	}
	c.ImageID = "sha256:img"
	if _, err := st.ApplySnapshot(ctx, "docker", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "app-1", Container: &c}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "sha256:img", Distro: "debian-12", Read: now, Packages: pkgs}); err != nil {
		t.Fatal(err)
	}
	for pkg, recs := range records {
		if err := st.ReplaceAdvisories(ctx, "os:Debian:12/"+pkg, match.SourceDistro, recs, now); err != nil {
			t.Fatal(err)
		}
	}
	var entries []store.KEVEntry
	for _, cve := range kev {
		entries = append(entries, store.KEVEntry{CVE: cve})
	}
	if err := st.ReplaceKEV(ctx, entries); err != nil {
		t.Fatal(err)
	}
	p := New(cat, st, slog.New(slog.DiscardHandler), Options{RegistryChecks: func() bool { return registryOn }})
	p.now = func() time.Time { return now }
	return &lab{t: t, st: st, p: p, now: now, wid: inventory.WorkloadID("docker", inventory.KindContainer, "c1")}
}

// check stores a registry answer for the lab's container.
func (l *lab) check(c inventory.Container, ck store.UpstreamCheck) {
	l.t.Helper()
	key, ok := upstream.KeyOf(&c, remedy.HostPlatform("x86_64"))
	if !ok {
		l.t.Fatal("no check key")
	}
	ck.UpstreamKey, ck.Checked = key, l.now
	if err := l.st.RecordUpstreamCheck(l.t.Context(), ck); err != nil {
		l.t.Fatal(err)
	}
}

// run analyses and returns the findings by package and the status.
func (l *lab) run() (map[string]store.Finding, upstream.Status, bool) {
	l.t.Helper()
	if _, err := l.p.Run(l.t.Context()); err != nil {
		l.t.Fatal(err)
	}
	fs, err := l.st.Findings(l.t.Context(), store.FindingFilter{})
	if err != nil {
		l.t.Fatal(err)
	}
	out := map[string]store.Finding{}
	for _, f := range fs {
		out[strings.TrimPrefix(f.AppID, "os:Debian:12/")] = f
	}
	raw, err := l.st.UpstreamStatus(l.t.Context())
	if err != nil {
		l.t.Fatal(err)
	}
	b, ok := raw[l.wid]
	var st upstream.Status
	if ok {
		if err := json.Unmarshal(b, &st); err != nil {
			l.t.Fatal(err)
		}
	}
	return out, st, ok
}

func encode(t *testing.T, c remedy.Candidate) []byte {
	t.Helper()
	b, err := upstream.EncodeCandidate(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var (
	nginxCommand = []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}
	published    = []inventory.Port{{PrivatePort: 80, PublicPort: 8080, Protocol: "tcp"}}
	chefPackages = []inventory.Package{deb("nginx", "1.22.1-9"), deb("openssl", "3.0.11-1~deb12u2"), deb("busybox", "1:1.35.0-4")}
	chefRecords  = map[string][]store.AdvisoryRecord{
		"busybox": {debRecord("DEBIAN-CVE-2099-1", "CVE-2099-1", "busybox", "1:1.35.0-5")},
		"openssl": {debRecord("DEBIAN-CVE-2099-2", "CVE-2099-2", "openssl", "3.0.15-1~deb12u1")},
	}
)

// chef is a CyberChef-like container: a floating tag, nginx serving
// published port 8080.
func chef() inventory.Container {
	return inventory.Container{ImageRef: "mpepping/cyberchef:latest", RepoDigests: []string{"mpepping/cyberchef@" + runDigest},
		Ports: published, Runtime: &inventory.Runtime{Command: nginxCommand}}
}

// A known-exploited flaw in a bundled tool of an exposed container is not
// urgent, and the floating tag pointing to the running image means no
// newer image exists.
func TestCyberChefBundledKEVIsNotUrgent(t *testing.T) {
	c := chef()
	l := newLab(t, c, chefPackages, map[string][]store.AdvisoryRecord{"busybox": chefRecords["busybox"]}, []string{"CVE-2099-1"}, true)
	l.check(c, store.UpstreamCheck{HeadDigest: runDigest})
	fs, st, ok := l.run()
	f, found := fs["busybox"]
	if !found {
		t.Fatalf("no busybox finding: %v", fs)
	}
	if f.Priority == string(policy.P1) {
		t.Errorf("bundled KEV is P1: %s", f.PriorityReason)
	}
	if !strings.Contains(f.PriorityReason, "busybox is a package in the image") {
		t.Errorf("reason %q", f.PriorityReason)
	}
	if !ok || st.Kind != upstream.NoUpstreamFix || st.Source != upstream.SourceRegistry {
		t.Errorf("status %+v", st)
	}
}

// The same with the flaw in openssl, a library nginx loads: urgent, and no
// image fixes it.
func TestCyberChefServedKEVStaysUrgent(t *testing.T) {
	c := chef()
	l := newLab(t, c, chefPackages, map[string][]store.AdvisoryRecord{"openssl": chefRecords["openssl"]}, []string{"CVE-2099-2"}, true)
	l.check(c, store.UpstreamCheck{HeadDigest: runDigest})
	fs, st, _ := l.run()
	if f := fs["openssl"]; f.Priority != string(policy.P1) {
		t.Errorf("served KEV is %s: %s", f.Priority, f.PriorityReason)
	}
	if st.Kind != upstream.NoUpstreamFix || st.Actionable() {
		t.Errorf("status %+v", st)
	}
}

// An Immich-ML-like container: pinned tag, no newer tag on its track, a
// KEV in glibc, nothing published.
func TestImmichMLPinnedWithoutNewerTag(t *testing.T) {
	c := inventory.Container{ImageRef: "ghcr.io/immich-app/immich-machine-learning:v3.4.1",
		RepoDigests: []string{"ghcr.io/immich-app/immich-machine-learning@" + runDigest},
		Runtime:     &inventory.Runtime{Command: []string{"tini", "--", "python", "-m", "immich_ml"}}}
	recs := map[string][]store.AdvisoryRecord{"glibc": {debRecord("DEBIAN-CVE-2099-3", "CVE-2099-3", "glibc", "2.36-9+deb12u10")}}
	l := newLab(t, c, []inventory.Package{deb("glibc", "2.36-9+deb12u4"), deb("python3.11", "3.11.2-6")}, recs, []string{"CVE-2099-3"}, true)
	l.check(c, store.UpstreamCheck{HeadDigest: runDigest})
	fs, st, _ := l.run()
	if f := fs["glibc"]; f.Priority == string(policy.P1) {
		t.Errorf("unexposed KEV is P1: %s", f.PriorityReason)
	}
	if st.Kind != upstream.NoUpstreamFix {
		t.Errorf("status %+v", st)
	}
}

// A newer tag whose image fixes the KEV finding is an update.
func TestNewerTagThatFixesIsAnUpdate(t *testing.T) {
	c := chef()
	c.ImageRef, c.RepoDigests = "mpepping/cyberchef:v10.19.0", []string{"mpepping/cyberchef@" + runDigest}
	l := newLab(t, c, chefPackages, chefRecords, []string{"CVE-2099-2"}, true)
	cand := remedy.Candidate{Distro: "debian-12", Packages: []inventory.Package{deb("nginx", "1.22.1-9"), deb("openssl", "3.0.15-1~deb12u1"), deb("busybox", "1:1.35.0-4")}}
	l.check(c, store.UpstreamCheck{HeadDigest: runDigest, CandidateTag: "v10.20.0", CandidateDigest: newDigest, Candidate: encode(t, cand), CandidateReadAt: l.now})
	fs, st, _ := l.run()
	if f := fs["openssl"]; f.Priority != string(policy.P1) {
		t.Errorf("served KEV is %s", f.Priority)
	}
	if st.Kind != upstream.UpdateAvailable || st.TargetTag != "v10.20.0" || st.TargetDigest != newDigest || st.Rebuilt {
		t.Fatalf("status %+v", st)
	}
	if len(st.Fixed) != 1 || st.Fixed[0].AdvisoryID != "DEBIAN-CVE-2099-2" || len(st.Remaining) != 1 || st.Total() != 2 {
		t.Errorf("fixed %v remaining %v", st.Fixed, st.Remaining)
	}
	if !st.Fixes("DEBIAN-CVE-2099-2", "Debian:12/openssl") {
		t.Error("Fixes does not name the openssl finding")
	}
}

// A candidate that brings a flaw of its own says so.
func TestCandidateIntroducesFlaw(t *testing.T) {
	c := chef()
	recs := map[string][]store.AdvisoryRecord{
		"openssl": chefRecords["openssl"],
		"libxml2": {debRecord("DEBIAN-CVE-2099-4", "CVE-2099-4", "libxml2", "2.9.14+dfsg-1.4")},
	}
	l := newLab(t, c, chefPackages, recs, nil, true)
	cand := remedy.Candidate{Distro: "debian-12", Packages: []inventory.Package{deb("nginx", "1.22.1-9"), deb("openssl", "3.0.15-1~deb12u1"), deb("libxml2", "2.9.14+dfsg-1.3")}}
	l.check(c, store.UpstreamCheck{HeadDigest: newDigest, CandidateTag: "latest", CandidateDigest: newDigest, Candidate: encode(t, cand), CandidateReadAt: l.now})
	_, st, _ := l.run()
	if st.Kind != upstream.UpdateAvailable || !st.Rebuilt || len(st.Introduced) != 1 || st.Introduced[0].AdvisoryID != "DEBIAN-CVE-2099-4" {
		t.Errorf("status %+v", st)
	}
}

// A rebuilt image that fixes nothing is no update.
func TestNewerDigestWithoutEffect(t *testing.T) {
	c := chef()
	l := newLab(t, c, chefPackages, chefRecords, []string{"CVE-2099-2"}, true)
	l.check(c, store.UpstreamCheck{HeadDigest: newDigest, CandidateTag: "latest", CandidateDigest: newDigest,
		Candidate: encode(t, remedy.Candidate{Distro: "debian-12", Packages: chefPackages}), CandidateReadAt: l.now})
	_, st, _ := l.run()
	if st.Kind != upstream.UpdateNoEffect || st.Actionable() || len(st.Remaining) != 2 {
		t.Errorf("status %+v", st)
	}
}

// A registry that refused, an image never read, and registry checks that
// are off are unknown, with the reason.
func TestUnknownUpstream(t *testing.T) {
	c := chef()
	cases := []struct {
		name       string
		ck         *store.UpstreamCheck
		registryOn bool
		reason     string
	}{
		{"rate limited", &store.UpstreamCheck{Error: registry.ReasonRateLimited}, true, registry.ReasonRateLimited},
		{"timeout", &store.UpstreamCheck{Error: registry.ReasonTimeout}, true, registry.ReasonTimeout},
		{"needs credentials", &store.UpstreamCheck{Error: registry.ReasonCredentials}, true, registry.ReasonCredentials},
		{"candidate not read", &store.UpstreamCheck{HeadDigest: newDigest, CandidateTag: "latest", CandidateDigest: newDigest}, true, upstream.ReasonCandidate},
		{"not asked yet", nil, true, upstream.ReasonNotChecked},
		{"registry checks off", nil, false, upstream.ReasonOff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t, c, chefPackages, chefRecords, []string{"CVE-2099-2"}, tc.registryOn)
			if tc.ck != nil {
				l.check(c, *tc.ck)
			}
			_, st, _ := l.run()
			if st.Kind != upstream.Unknown || st.Reason != tc.reason || st.Actionable() {
				t.Errorf("status %+v", st)
			}
		})
	}
}

// A locally built image has no registry digest to compare.
func TestLocallyBuiltImageIsUnknown(t *testing.T) {
	c := chef()
	c.ImageRef, c.RepoDigests = "cyberchef-local:dev", nil
	l := newLab(t, c, chefPackages, chefRecords, []string{"CVE-2099-2"}, true)
	_, st, ok := l.run()
	if !ok || st.Kind != upstream.Unknown || st.Reason != upstream.ReasonLocal {
		t.Errorf("status %+v", st)
	}
}

// A finding snoozed until a fixed image appears opens again once one does.
func TestUpstreamSnoozeWakes(t *testing.T) {
	c := chef()
	l := newLab(t, c, chefPackages, chefRecords, []string{"CVE-2099-2"}, true)
	l.check(c, store.UpstreamCheck{HeadDigest: runDigest})
	fs, _, _ := l.run()
	ids := []string{fs["openssl"].ID, fs["busybox"].ID}
	if n, err := l.st.SnoozeUntilUpstream(t.Context(), l.wid, ids, l.now); err != nil || n != 2 {
		t.Fatalf("snoozed %d: %v", n, err)
	}
	// A newer image fixes openssl only.
	cand := remedy.Candidate{Distro: "debian-12", Packages: []inventory.Package{deb("nginx", "1.22.1-9"), deb("openssl", "3.0.15-1~deb12u1"), deb("busybox", "1:1.35.0-4")}}
	l.check(c, store.UpstreamCheck{HeadDigest: newDigest, CandidateTag: "latest", CandidateDigest: newDigest, Candidate: encode(t, cand), CandidateReadAt: l.now})
	fs, st, _ := l.run()
	if st.Kind != upstream.UpdateAvailable {
		t.Fatalf("status %+v", st)
	}
	if f := fs["openssl"]; f.State != store.StateOpen || f.SnoozeUpstream {
		t.Errorf("fixed finding still snoozed: %+v", f)
	}
	if f := fs["busybox"]; f.State != store.StateSnoozed || !f.SnoozeUpstream {
		t.Errorf("unfixed finding woke: %+v", f)
	}
}

func TestComponentPriority(t *testing.T) {
	kev := match.Finding{Image: true, KEV: true}
	served := &inventory.Container{Runtime: &inventory.Runtime{Command: nginxCommand}}
	cases := []struct {
		name     string
		m        match.Finding
		pkg      string
		c        *inventory.Container
		exposure inventory.Exposure
		want     policy.Priority
	}{
		{"served program", kev, "nginx", served, inventory.ExposureLAN, policy.P1},
		{"served library", kev, "openssl", served, inventory.ExposurePublic, policy.P1},
		{"bundled tool", kev, "busybox", served, inventory.ExposureLAN, policy.P2},
		{"not exposed", kev, "nginx", served, inventory.ExposureInternal, policy.P2},
		{"unknown exposure", kev, "nginx", served, inventory.ExposureUnknown, policy.P2},
		{"no command known", kev, "openssl", &inventory.Container{}, inventory.ExposureLAN, policy.P2},
		{"not an image finding", match.Finding{KEV: true}, "", served, inventory.ExposureInternal, policy.P1},
	}
	for _, c := range cases {
		if got, reason := componentPriority(policy.P1, "known exploited (CISA KEV)", c.m, c.pkg, c.c, c.exposure); got != c.want || reason == "" {
			t.Errorf("%s: %s (%s), want %s", c.name, got, reason, c.want)
		}
	}
	// Lower priorities are never raised.
	if got, _ := componentPriority(policy.P2, "high severity", kev, "nginx", served, inventory.ExposureLAN); got != policy.P2 {
		t.Errorf("P2 became %s", got)
	}
}

// A digest pin is changed, not pulled again.
func TestImageActionOfPinnedImage(t *testing.T) {
	st := upstream.Status{Kind: upstream.UpdateAvailable, TargetTag: "1.2", TargetDigest: newDigest, Rebuilt: true,
		Fixed: []remedy.Flaw{{AdvisoryID: "A", Package: "Debian:12/openssl"}}}
	m := match.Finding{AdvisoryID: "A", Image: true, Evidence: match.Evidence{Package: "Debian:12/openssl"}}
	if a, _ := imageAction(st, m, true); !strings.Contains(a, "digest pin to 1.2@"+newDigest) {
		t.Errorf("pinned: %q", a)
	}
	if a, _ := imageAction(st, m, false); !strings.Contains(a, "pull the rebuilt image") {
		t.Errorf("not pinned: %q", a)
	}
}
