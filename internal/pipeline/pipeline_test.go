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
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

const entry = `id: immich
name: Immich
homepage: https://immich.app
images: [{match: ghcr.io/immich-app/immich-server}]
version: {scheme: semver}
advisories: {coverage: full, github_repos: [immich-app/immich]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`

func TestRunStoresIdentifications(t *testing.T) {
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
	if err := st.UpsertHost(ctx, inventory.Host{ID: "local", Name: "n", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	ws := []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "a", Name: "immich", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}},
		{Kind: inventory.KindContainer, RuntimeID: "b", Name: "immich-latest", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:release"}},
		{Kind: inventory.KindContainer, RuntimeID: "c", Name: "random", Container: &inventory.Container{ImageRef: "someone/thing:1"}},
	}
	if _, err := st.ApplySnapshot(ctx, "local", inventory.KindContainer, ws, now); err != nil {
		t.Fatal(err)
	}

	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	sum, err := p.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Workloads != 3 || sum.Identified != 2 || sum.VersionUnknown != 1 || sum.Affected != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	ids, err := st.Identifications(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := ids[inventory.WorkloadID("local", inventory.KindContainer, "a")]
	if a.AppID != "immich" || a.Version != "1.120.0" || a.Confidence != identify.Exact {
		t.Errorf("a: %+v", a)
	}
	if c := ids[inventory.WorkloadID("local", inventory.KindContainer, "c")]; c.Confidence != identify.None {
		t.Errorf("c: %+v", c)
	}

	// Advisories arrive: the pinned workload is affected, the floating one
	// unverified, the unknown image gets nothing.
	ranges, _, err := advisory.ParseGitHubRange("< 1.121.0", "1.121.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceAdvisories(ctx, "immich", "github:immich-app/immich", []store.AdvisoryRecord{{
		Vuln: advisory.Vulnerability{ID: "GHSA-test", Aliases: []string{"CVE-2026-9"}, Modified: now,
			Affected: []advisory.Affected{{Package: advisory.Package{Name: "immich"}, Ranges: ranges}}},
		CVSS: 9.1,
	}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceKEV(ctx, []store.KEVEntry{{CVE: "CVE-2026-9"}}); err != nil {
		t.Fatal(err)
	}
	sum, err = p.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Affected != 1 || sum.Unverified != 1 || len(sum.Changes.New) != 2 {
		t.Fatalf("matching summary: %+v", sum)
	}
	found, _ := st.Findings(ctx, store.FindingFilter{})
	var affected store.Finding
	for _, f := range found {
		if f.MatchState == "affected" {
			affected = f
		}
	}
	if affected.FixedIn != "1.121.0" || affected.WorkloadID != inventory.WorkloadID("local", inventory.KindContainer, "a") ||
		!strings.Contains(string(affected.Detail), `"kev":true`) || !strings.Contains(string(affected.Detail), `"cvss":9.1`) {
		t.Fatalf("affected finding: %+v %s", affected, affected.Detail)
	}
	// KEV-listed, but no published port and no route: background noise,
	// kept at P2 because it is known to be exploited (ADR 0034).
	// Known exploited: its place never lowers it (ADR 0034).
	if affected.Priority != "P1" || affected.Exposure != "internal" || affected.PathClass != "noise" || !strings.HasPrefix(affected.PriorityReason, "known exploited") {
		t.Fatalf("assessment: %+v", affected)
	}
	cands, err := p.Candidates(ctx)
	if err != nil || len(cands) != 2 {
		t.Fatalf("candidates: %d %v", len(cands), err)
	}
	for _, c := range cands {
		if c.Item.MatchState == "affected" && (c.Item.AppName != "Immich" || c.Item.HostName != "n" || c.Item.Version != "1.120.0" || c.Item.Priority != "P1") {
			t.Fatalf("candidate item: %+v", c.Item)
		}
	}
	// Unverified findings never get a priority.
	for _, f := range found {
		if f.MatchState == "unverified" {
			uf, _ := st.GetFinding(ctx, f.ID)
			if uf.Priority != "" {
				t.Fatalf("unverified finding prioritised: %+v", uf)
			}
		}
	}

	// The user updates: the finding resolves.
	ws[0].Container.ImageRef = "ghcr.io/immich-app/immich-server:v1.121.0"
	if _, err := st.ApplySnapshot(ctx, "local", inventory.KindContainer, ws, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	sum, err = p.Run(ctx)
	if err != nil || len(sum.Changes.Resolved) != 1 || sum.Affected != 0 {
		t.Fatalf("after update: %+v %v", sum, err)
	}

	// Removed workloads lose their identification on the next run.
	if _, err := st.ApplySnapshot(ctx, "local", inventory.KindContainer, ws[:1], now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	ids, _ = st.Identifications(ctx)
	if len(ids) != 1 {
		t.Fatalf("after removal: %d identifications", len(ids))
	}
}
