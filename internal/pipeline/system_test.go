// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// A system package is matched against its distribution's records without a
// catalog entry; a finding is reported only where an update fixes it.
func TestSystemPackageFindings(t *testing.T) {
	ctx := t.Context()
	cat, err := catalog.Load(fstest.MapFS{"immich.yaml": {Data: []byte(entry)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	if err := st.UpsertHost(ctx, inventory.Host{ID: "web", Name: "web", Kind: inventory.HostLinux, Source: inventory.SourceAgent, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	pkg := func(name, version string) inventory.Workload {
		return inventory.Workload{Kind: inventory.KindPackage, RuntimeID: "os:dpkg:" + name, Name: name,
			Package: &inventory.Package{Manager: "dpkg", Name: name, Version: version, Distro: "debian-13", Source: name, System: true}}
	}
	if _, err := st.ApplySnapshot(ctx, "web", inventory.KindPackage, []inventory.Workload{pkg("openssl", "3.5.1-1"), pkg("glibc", "2.41-12")}, now); err != nil {
		t.Fatal(err)
	}
	rec := func(id, name, fixed string) store.AdvisoryRecord {
		events := []advisory.Event{{Introduced: "0"}}
		if fixed != "" {
			events = append(events, advisory.Event{Fixed: fixed})
		}
		return store.AdvisoryRecord{Source: match.SourceDistro, Vuln: advisory.Vulnerability{ID: id, Modified: now, Upstream: []string{"CVE-" + id[len("DEBIAN-CVE-"):]},
			Affected: []advisory.Affected{{Package: advisory.Package{Ecosystem: "Debian:13", Name: name},
				Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: events}}}}}}
	}
	if err := st.ReplaceAdvisories(ctx, distro.SystemAppID("Debian:13", "openssl"), match.SourceDistro, []store.AdvisoryRecord{
		rec("DEBIAN-CVE-2026-1", "openssl", "3.5.1-1+deb13u1"), // fixed by an update
		rec("DEBIAN-CVE-2026-2", "openssl", "3.5.0-1"),         // fixed before the installed version
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceAdvisories(ctx, distro.SystemAppID("Debian:13", "glibc"), match.SourceDistro, []store.AdvisoryRecord{
		rec("DEBIAN-CVE-2026-3", "glibc", ""), // no fix yet
	}, now); err != nil {
		t.Fatal(err)
	}

	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	sum, err := p.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.SystemPackages != 2 || sum.Workloads != 0 || sum.Affected != 1 {
		t.Fatalf("summary %+v", sum)
	}
	fs, err := st.Findings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].AppID != distro.SystemAppID("Debian:13", "openssl") || fs[0].FixedIn != "3.5.1-1+deb13u1" || fs[0].MatchState != string(match.Affected) {
		t.Fatalf("findings %+v", fs)
	}
	// The issue without a fix is counted with the package, not reported.
	ids, err := st.Identifications(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := ids[inventory.WorkloadID("web", inventory.KindPackage, "os:dpkg:glibc")].Unfixed; n != 1 {
		t.Fatalf("glibc unfixed = %d", n)
	}
	if n := ids[inventory.WorkloadID("web", inventory.KindPackage, "os:dpkg:openssl")].Unfixed; n != 0 {
		t.Fatalf("openssl unfixed = %d", n)
	}
	// System packages are not offered to the app sources.
	apps, _ := p.Apps(ctx)
	for _, a := range apps {
		if distro.SystemPrefix == a.ID[:min(len(a.ID), 3)] {
			t.Fatalf("system package handed to the app sources: %s", a.ID)
		}
	}
}

// The packages of a container's image are matched like system packages
// and reported on the container, as fixed by a newer image (ADR 0033);
// notifications name the package, not its app ID.
func TestImagePackageFindings(t *testing.T) {
	ctx := t.Context()
	cat, err := catalog.Load(fstest.MapFS{"immich.yaml": {Data: []byte(entry)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	if err := st.UpsertHost(ctx, inventory.Host{ID: "nas", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	image := "sha256:" + strings.Repeat("d", 64)
	if _, err := st.ApplySnapshot(ctx, "nas", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich_server",
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", ImageID: image}}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: image, Distro: "debian-12", Read: now, Packages: []inventory.Package{
		{Manager: "dpkg", Name: "libc6", Version: "2.36-9", Source: "glibc"},
		{Manager: "dpkg", Name: "libc-bin", Version: "2.36-9", Source: "glibc"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceAdvisories(ctx, distro.SystemAppID("Debian:12", "glibc"), match.SourceDistro, []store.AdvisoryRecord{{Source: match.SourceDistro,
		Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2023-4911", Modified: now, Upstream: []string{"CVE-2023-4911"}, Affected: []advisory.Affected{{
			Package: advisory.Package{Ecosystem: "Debian:12", Name: "glibc"},
			Ranges:  []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.36-9+deb12u3"}}}}}}}}}, now); err != nil {
		t.Fatal(err)
	}
	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	sum, err := p.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.ImagePackages != 1 {
		t.Fatalf("summary %+v", sum)
	}
	fs, _ := st.Findings(ctx, store.FindingFilter{})
	var found *store.Finding
	for i := range fs {
		if fs[i].AdvisoryID == "DEBIAN-CVE-2023-4911" {
			found = &fs[i]
		}
	}
	if found == nil || found.WorkloadID != inventory.WorkloadID("nas", inventory.KindContainer, "c1") || found.FixedIn != "2.36-9+deb12u3" {
		t.Fatalf("image finding %+v", found)
	}
	// An issue no image fixes yet is counted with the container.
	if err := st.ReplaceAdvisories(ctx, distro.SystemAppID("Debian:12", "glibc"), match.SourceDistro, []store.AdvisoryRecord{
		{Source: match.SourceDistro, Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2023-4911", Modified: now, Affected: []advisory.Affected{{
			Package: advisory.Package{Ecosystem: "Debian:12", Name: "glibc"},
			Ranges:  []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.36-9+deb12u3"}}}}}}}},
		{Source: match.SourceDistro, Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2026-9", Modified: now, Affected: []advisory.Affected{{
			Package: advisory.Package{Ecosystem: "Debian:12", Name: "glibc"},
			Ranges:  []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}}}}}}}},
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	ids, _ := st.Identifications(ctx)
	if n := ids[inventory.WorkloadID("nas", inventory.KindContainer, "c1")].Unfixed; n != 1 {
		t.Fatalf("container unfixed = %d", n)
	}
	cands, err := p.Candidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.Item.AdvisoryID == "DEBIAN-CVE-2023-4911" && (c.Item.AppName != "glibc (Debian 12 package)" || !c.Item.Image) {
			t.Fatalf("notification item %+v", c.Item)
		}
	}
}
