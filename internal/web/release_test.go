// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// A container's image findings name the release that fixes them, compared
// with the release's image for the host's platform.
func TestFindingPageShowsReleaseFix(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "pi", Name: "pi", Kind: inventory.HostDocker, Source: inventory.SourceLocal, Arch: "aarch64", LastContact: now})
	runs := func(tag string) {
		t.Helper()
		if _, err := h.store.ApplySnapshot(ctx, "pi", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich_server",
			Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:" + tag}}}, now); err != nil {
			t.Fatal(err)
		}
	}
	runs("v1.120.0")
	wid := inventory.WorkloadID("pi", inventory.KindContainer, "c1")
	identifyAs := func(v string) {
		t.Helper()
		if err := h.store.ReplaceIdentifications(ctx, []identify.Result{{WorkloadID: wid, AppID: "immich", Confidence: identify.Exact, Version: v}}, now); err != nil {
			t.Fatal(err)
		}
	}
	identifyAs("1.120.0")

	pkgs := map[string]struct{ id, running, fixed string }{
		"openssl": {"DEBIAN-CVE-2026-1", "3.0.11-1~deb12u2", "3.0.15-1~deb12u1"},
		"zlib":    {"DEBIAN-CVE-2026-2", "1:1.2.13.dfsg-1", "1:1.2.13.dfsg-2"},
	}
	var inputs []store.FindingInput
	findingID := map[string]string{}
	for name, p := range pkgs {
		appID := distro.SystemAppID("Debian:12", name)
		rec := store.AdvisoryRecord{Source: match.SourceDistro, Vuln: advisory.Vulnerability{ID: p.id, Modified: now, Affected: []advisory.Affected{{
			Package: advisory.Package{Ecosystem: "Debian:12", Name: name},
			Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: p.fixed}}}},
		}}}}
		if err := h.store.ReplaceAdvisories(ctx, appID, match.SourceDistro, []store.AdvisoryRecord{rec}, now); err != nil {
			t.Fatal(err)
		}
		in := store.FindingInput{WorkloadID: wid, AppID: appID, AdvisoryID: p.id, MatchState: "affected", FixedIn: p.fixed,
			Detail: match.Finding{AdvisoryID: p.id, State: match.Affected, FixedIn: p.fixed, Image: true,
				Evidence: match.Evidence{Source: match.SourceDistro, RecordID: p.id, Package: "Debian:12/" + name, Version: p.running}}}
		inputs = append(inputs, in)
		findingID[name] = in.ID()
	}
	if _, err := h.store.SyncFindings(ctx, inputs, now); err != nil {
		t.Fatal(err)
	}

	// The amd64 image of the release has both fixes, the arm64 one only
	// openssl's: the arm64 host gets the arm64 answer.
	deb := func(name, v string) inventory.Package {
		return inventory.Package{Manager: "dpkg", Name: name, Version: v}
	}
	read := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	keep := func(lines ...feed.ReleaseLine) {
		t.Helper()
		var rows []store.ReleasePackageRow
		for _, l := range lines {
			l.AppID, l.Image, l.Tag, l.Version, l.Read, l.Distro = "immich", "ghcr.io/immich-app/immich-server", "v1.121.0", "1.121.0", read, "debian-12"
			l.IndexDigest = "sha256:" + strings.Repeat("1", 64)
			l.ManifestDigest = "sha256:" + strings.Repeat("2", 64)
			data, err := json.Marshal(l)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, store.ReleasePackageRow{AppID: l.AppID, Image: l.Image, Platform: l.Platform.Key(), Tag: l.Tag, Version: l.Version, Line: data})
		}
		if err := h.store.ReplaceReleasePackages(ctx, "test", rows); err != nil {
			t.Fatal(err)
		}
	}
	x86 := feed.ReleaseLine{Platform: feed.ReleasePlatform{OS: "linux", Arch: "amd64"}, Packages: []inventory.Package{deb("openssl", "3.0.15-1~deb12u1"), deb("zlib", "1:1.2.13.dfsg-2")}}
	arm := feed.ReleaseLine{Platform: feed.ReleasePlatform{OS: "linux", Arch: "arm64", Variant: "v8"}, Packages: []inventory.Package{deb("openssl", "3.0.15-1~deb12u1"), deb("zlib", "1:1.2.13.dfsg-1")}}
	keep(x86, arm)

	_, body := h.do(t, "GET", "/findings/"+findingID["zlib"], nil, nil)
	if !strings.Contains(body, `Release <span class="mono">v1.121.0</span> fixes 1 of 2`) || !strings.Contains(body, "this one is not fixed in any release yet") {
		t.Errorf("zlib finding without the release that leaves it open:\n%s", body)
	}
	if !strings.Contains(body, "read "+read.Local().Format("2006-01-02")) {
		t.Error("finding page without the read date")
	}
	_, body = h.do(t, "GET", "/findings/"+findingID["openssl"], nil, nil)
	if !strings.Contains(body, `fixes 1 of 2</strong> flaws in the image's packages of immich_server, this one among them`) {
		t.Errorf("openssl finding without the release that fixes it:\n%s", body)
	}
	_, body = h.do(t, "GET", "/findings", nil, nil)
	if !strings.Contains(body, `Release <span class="mono">v1.121.0</span> fixes 1 of 2`) || !strings.Contains(body, `Not fixed in any release yet: <span class="mono">DEBIAN-CVE-2026-2</span>`) {
		t.Errorf("container group without the release fix:\n%s", body)
	}

	// The container runs another variant of the image: its packages are
	// not the release's, nothing is claimed.
	runs("v1.120.0-alpine")
	_, body = h.do(t, "GET", "/findings", nil, nil)
	if strings.Contains(body, "fixes 1 of 2") || !strings.Contains(body, `Newest release: <span class="mono">v1.121.0</span>`) {
		t.Errorf("other variant claims a fix:\n%s", body)
	}
	// The container runs that release already: no fix is claimed.
	runs("v1.121.0")
	_, body = h.do(t, "GET", "/findings/"+findingID["zlib"], nil, nil)
	if strings.Contains(body, "fixes 1 of 2") || !strings.Contains(body, `already runs the newest release (<span class="mono">v1.121.0</span>)`) {
		t.Errorf("newest release not said:\n%s", body)
	}
	// A floating tag the registry has not resolved: the release is named,
	// nothing is claimed.
	runs("latest")
	_, body = h.do(t, "GET", "/findings", nil, nil)
	if strings.Contains(body, "fixes 1 of 2") || !strings.Contains(body, `Newest release: <span class="mono">v1.121.0</span>`) {
		t.Errorf("unknown version claims a fix:\n%s", body)
	}

	// A read of the arm64 image that stopped early and lacks zlib: Varde
	// cannot tell, which is not "not fixed".
	runs("v1.120.0")
	arm.Partial, arm.Packages = true, arm.Packages[:1]
	keep(x86, arm)
	_, body = h.do(t, "GET", "/findings", nil, nil)
	if !strings.Contains(body, `fixes 1 of 2`) || !strings.Contains(body, `Varde cannot tell for: <span class="mono">DEBIAN-CVE-2026-2</span>`) || strings.Contains(body, "Not fixed in any release yet") {
		t.Errorf("partial read not told apart:\n%s", body)
	}
}
