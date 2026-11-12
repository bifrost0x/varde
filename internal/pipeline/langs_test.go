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

// A distroless Go image: no package database, but the program's build
// information names the toolchain and its modules, which are checked
// against the Go advisories (semantic version ranges).
func TestGoModuleFindings(t *testing.T) {
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
	image := "sha256:" + strings.Repeat("e", 64)
	if _, err := st.ApplySnapshot(ctx, "nas", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "proxy",
		Container: &inventory.Container{ImageRef: "example/proxy:1.0", ImageID: image}}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: image, Read: now, Packages: []inventory.Package{
		{Manager: "go", Name: "stdlib", Version: "1.22.1", Path: "/proxy"},
		{Manager: "go", Name: "golang.org/x/net", Version: "v0.20.0", Path: "/proxy"},
	}}); err != nil {
		t.Fatal(err)
	}
	semver := func(id, eco, name, fixed string) store.AdvisoryRecord {
		return store.AdvisoryRecord{Source: match.SourceDistro, CVSS: 7.5, Vuln: advisory.Vulnerability{ID: id, Modified: now, Aliases: []string{"CVE-2024-1"},
			Affected: []advisory.Affected{{Package: advisory.Package{Ecosystem: eco, Name: name},
				Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}}}}}}
	}
	if err := st.ReplaceAdvisories(ctx, distro.SystemAppID("Go", "golang.org/x/net"), match.SourceDistro,
		[]store.AdvisoryRecord{semver("GO-2024-2687", "Go", "golang.org/x/net", "0.23.0")}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceAdvisories(ctx, distro.SystemAppID("Go", "stdlib"), match.SourceDistro,
		[]store.AdvisoryRecord{semver("GO-2024-2599", "Go", "stdlib", "1.21.8")}, now); err != nil {
		t.Fatal(err)
	}
	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	sum, err := p.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.ImagePackages != 2 {
		t.Fatalf("summary %+v", sum)
	}
	fs, _ := st.Findings(ctx, store.FindingFilter{})
	got := map[string]store.Finding{}
	for _, f := range fs {
		got[f.AdvisoryID] = f
	}
	if f, ok := got["GO-2024-2687"]; !ok || f.FixedIn != "0.23.0" || f.AppID != "os:Go/golang.org/x/net" || f.MatchState != string(match.Affected) {
		t.Fatalf("x/net: %+v", got)
	}
	// 1.22.1 is above the fixed 1.21.8: not affected.
	if _, ok := got["GO-2024-2599"]; ok {
		t.Fatalf("stdlib reported although fixed: %+v", got["GO-2024-2599"])
	}
	cands, err := p.Candidates(ctx)
	if err != nil || len(cands) != 1 || cands[0].Item.AppName != "golang.org/x/net (Go module)" {
		t.Fatalf("candidates: %+v %v", cands, err)
	}
}
