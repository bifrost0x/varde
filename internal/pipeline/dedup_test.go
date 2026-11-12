// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"log/slog"
	"path/filepath"
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

func TestRunDeduplicatesAppAndImageAdvisory(t *testing.T) {
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
	const image = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if _, err := st.ApplySnapshot(ctx, "nas", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich",
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", ImageID: image}}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: image, Distro: "debian-12", Read: now,
		Packages: []inventory.Package{{Manager: "dpkg", Name: "libc6", Source: "glibc", Version: "2.36-9"}}}); err != nil {
		t.Fatal(err)
	}
	ranges, _, err := advisory.ParseGitHubRange("< 1.121.0", "1.121.0")
	if err != nil {
		t.Fatal(err)
	}
	const cve = "CVE-2026-12345"
	if err := st.ReplaceAdvisories(ctx, "immich", "github:immich-app/immich", []store.AdvisoryRecord{{
		Vuln: advisory.Vulnerability{ID: cve, Modified: now, Affected: []advisory.Affected{{Package: advisory.Package{Name: "immich"}, Ranges: ranges}}},
	}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceAdvisories(ctx, distro.SystemAppID("Debian:12", "glibc"), match.SourceDistro, []store.AdvisoryRecord{{
		Vuln: advisory.Vulnerability{ID: cve, Modified: now, Affected: []advisory.Affected{{Package: advisory.Package{Ecosystem: "Debian:12", Name: "glibc"},
			Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.36-9+deb12u3"}}}}}}},
	}}, now); err != nil {
		t.Fatal(err)
	}
	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	sum, err := p.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := st.Findings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].AppID != "immich" || sum.Affected != 1 || len(sum.Changes.New) != 1 {
		t.Fatalf("app/image overlap counted twice: summary=%+v findings=%+v", sum, fs)
	}
}
