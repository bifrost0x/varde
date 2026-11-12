// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// BenchmarkRun100 measures a full analysis pass (identification, matching,
// prioritisation) for 100 workloads with the full seed catalog and 30
// advisories per identified app (budget: under 5 s, docs/performance.md).
func BenchmarkRun100(b *testing.B) {
	ctx := context.Background()
	cat, err := catalog.Load(catalogdata.FS(), nil)
	if err != nil {
		b.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(b.TempDir(), "v.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	if err := st.UpsertHost(ctx, inventory.Host{ID: "local", Name: "n", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		b.Fatal(err)
	}
	apps := cat.Apps()
	var ws []inventory.Workload
	for i := range 100 {
		image := fmt.Sprintf("example/unknown-%d:1.0", i)
		if i < 60 { // 60 % catalog apps, the rest unknown images
			a := apps[i%len(apps)]
			if len(a.Images) == 0 {
				continue
			}
			image = a.Images[0].Match + ":1.0.0"
		}
		ws = append(ws, inventory.Workload{Kind: inventory.KindContainer, RuntimeID: fmt.Sprint(i), Name: fmt.Sprint("w", i),
			Container: &inventory.Container{ImageRef: image, Labels: map[string]string{"varde.version": "1.0.0"}}})
	}
	if _, err := st.ApplySnapshot(ctx, "local", inventory.KindContainer, ws, now); err != nil {
		b.Fatal(err)
	}
	ranges, _, err := advisory.ParseGitHubRange(">= 0.1.0, < 2.0.0", "2.0.0")
	if err != nil {
		b.Fatal(err)
	}
	for _, a := range apps {
		var recs []store.AdvisoryRecord
		for j := range 30 {
			recs = append(recs, store.AdvisoryRecord{CVSS: 7.5, Vuln: advisory.Vulnerability{ID: fmt.Sprintf("GHSA-%s-%d", a.ID, j), Modified: now,
				Affected: []advisory.Affected{{Package: advisory.Package{Name: a.ID}, Ranges: ranges}}}})
		}
		if err := st.ReplaceAdvisories(ctx, a.ID, "github:bench", recs, now); err != nil {
			b.Fatal(err)
		}
	}
	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	b.ReportAllocs()
	for b.Loop() {
		if _, err := p.Run(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRunSystemPackages measures an analysis pass over ten hosts with
// 400 system packages each, a tenth of them with five distribution records
// (ADR 0032).
func BenchmarkRunSystemPackages(b *testing.B) {
	ctx := context.Background()
	cat, err := catalog.Load(catalogdata.FS(), nil)
	if err != nil {
		b.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(b.TempDir(), "v.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	for h := range 10 {
		host := fmt.Sprintf("h%d", h)
		if err := st.UpsertHost(ctx, inventory.Host{ID: host, Name: host, Kind: inventory.HostLinux, Source: inventory.SourceAgent, LastContact: now}); err != nil {
			b.Fatal(err)
		}
		var ws []inventory.Workload
		for i := range 400 {
			name := fmt.Sprintf("pkg%d", i)
			ws = append(ws, inventory.Workload{Kind: inventory.KindPackage, RuntimeID: "os:dpkg:" + name, Name: name,
				Package: &inventory.Package{Manager: "dpkg", Name: name, Version: "1.0-1", Distro: "debian-12", Source: name, System: true}})
		}
		if _, err := st.ApplySnapshot(ctx, host, inventory.KindPackage, ws, now); err != nil {
			b.Fatal(err)
		}
	}
	for i := range 40 {
		name := fmt.Sprintf("pkg%d", i*10)
		var recs []store.AdvisoryRecord
		for j := range 5 {
			recs = append(recs, store.AdvisoryRecord{Source: "distro", Vuln: advisory.Vulnerability{ID: fmt.Sprintf("DEBIAN-CVE-2026-%d", i*10+j), Modified: now,
				Affected: []advisory.Affected{{Package: advisory.Package{Ecosystem: "Debian:12", Name: name},
					Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-1+deb12u1"}}}}}}}})
		}
		if err := st.ReplaceAdvisories(ctx, "os:Debian:12/"+name, "distro", recs, now); err != nil {
			b.Fatal(err)
		}
	}
	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	b.ReportAllocs()
	for b.Loop() {
		if _, err := p.Run(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
