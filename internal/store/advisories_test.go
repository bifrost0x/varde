// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/inventory"
)

func TestAdvisoriesAndEnrichment(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	recs := []AdvisoryRecord{
		{Vuln: advisory.Vulnerability{ID: "GHSA-1", Aliases: []string{"CVE-2026-1"}, Modified: now, Summary: "one"}, CVSS: 9.8, SeverityLabel: "critical"},
		{Vuln: advisory.Vulnerability{ID: "GHSA-2", Modified: now}},
	}
	if err := s.ReplaceAdvisories(ctx, "immich", "github", recs, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceAdvisories(ctx, "immich", "nvd", []AdvisoryRecord{{Vuln: advisory.Vulnerability{ID: "CVE-2026-2", Modified: now}}}, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.Advisories(ctx, "immich")
	if err != nil || len(got) != 3 || got[0].Vuln.Summary != "one" || got[0].CVSS != 9.8 || got[1].CVSS != 0 {
		t.Fatalf("advisories: %+v %v", got, err)
	}
	// Replacing one source leaves the other untouched.
	if err := s.ReplaceAdvisories(ctx, "immich", "github", recs[:1], now); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Advisories(ctx, "immich"); len(got) != 2 {
		t.Fatalf("after replace: %d", len(got))
	}
	cves, err := s.AdvisoryCVEs(ctx)
	if err != nil || len(cves) != 2 {
		t.Fatalf("cves: %v %v", cves, err)
	}

	if err := s.ReplaceAdvisories(ctx, "system:Debian:12/openssl", "distro", []AdvisoryRecord{{Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2026-3", Modified: now}}}, now); err != nil {
		t.Fatal(err)
	}
	byApp, err := s.AdvisoriesFor(ctx, []string{"immich", "system:Debian:12/openssl", "absent"})
	if err != nil || len(byApp) != 2 || len(byApp["immich"]) != 2 || len(byApp["system:Debian:12/openssl"]) != 1 || byApp["immich"][0].AppID != "immich" {
		t.Fatalf("advisories for apps: %+v %v", byApp, err)
	}
	if none, err := s.AdvisoriesFor(ctx, nil); err != nil || len(none) != 0 {
		t.Fatalf("no apps: %v %v", none, err)
	}
	if err := s.ReplaceKEV(ctx, []KEVEntry{{CVE: "CVE-2026-1", DateAdded: "2026-11-01"}}); err != nil {
		t.Fatal(err)
	}
	if kev, _ := s.KEV(ctx); !kev["CVE-2026-1"] || len(kev) != 1 {
		t.Fatalf("kev: %v", kev)
	}
	if err := s.UpsertEPSS(ctx, []EPSSEntry{{CVE: "CVE-2026-1", Score: 0.3}, {CVE: "CVE-2026-1", Score: 0.4}}); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.EPSS(ctx); e["CVE-2026-1"] != 0.4 {
		t.Fatalf("epss: %v", e)
	}

	st := SourceState{Source: "github", Key: "immich-app/immich", ETag: `W/"x"`, LastSuccess: now, NextRun: now.Add(time.Hour)}
	if err := s.PutSourceState(ctx, st); err != nil {
		t.Fatal(err)
	}
	back, err := s.SourceState(ctx, "github", "immich-app/immich")
	if err != nil || back.ETag != st.ETag || !back.NextRun.Equal(st.NextRun) || !back.LastAttempt.IsZero() {
		t.Fatalf("source state: %+v %v", back, err)
	}
	if empty, err := s.SourceState(ctx, "github", "other/repo"); err != nil || empty.ETag != "" {
		t.Fatalf("missing state: %+v %v", empty, err)
	}
}

func TestSyncFindings(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.UpsertHost(ctx, localHost(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer, []inventory.Workload{container("a", "immich", "x")}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "a")
	in := []FindingInput{
		{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected", FixedIn: "1.2.0", Detail: map[string]any{"x": 1}},
		{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-2", MatchState: "unverified", Detail: nil},
	}
	ch, err := s.SyncFindings(ctx, in, now)
	if err != nil || len(ch.New) != 2 || len(ch.Resolved) != 0 {
		t.Fatalf("first sync: %+v %v", ch, err)
	}
	// Unchanged: nothing reported.
	if ch, _ := s.SyncFindings(ctx, in, now.Add(time.Minute)); len(ch.New)+len(ch.Changed)+len(ch.Resolved) != 0 {
		t.Fatalf("idempotent sync: %+v", ch)
	}
	// GHSA-2 disappears, GHSA-1 changes fixed version.
	in2 := []FindingInput{in[0]}
	in2[0].FixedIn = "1.2.1"
	ch, err = s.SyncFindings(ctx, in2, now.Add(2*time.Minute))
	if err != nil || len(ch.Changed) != 1 || len(ch.Resolved) != 1 {
		t.Fatalf("change+resolve: %+v %v", ch, err)
	}
	open, _ := s.Findings(ctx, FindingFilter{})
	all, _ := s.Findings(ctx, FindingFilter{IncludeResolved: true})
	if len(open) != 1 || len(all) != 2 || open[0].FixedIn != "1.2.1" || string(open[0].Detail) != `{"x":1}` {
		t.Fatalf("open=%+v all=%d", open, len(all))
	}
	// GHSA-2 reappears: reopened and reported as new.
	ch, _ = s.SyncFindings(ctx, in, now.Add(3*time.Minute))
	if len(ch.New) != 1 {
		t.Fatalf("reopen: %+v", ch)
	}
	f, err := s.GetFinding(ctx, FindingID(wid, "GHSA-2"))
	if err != nil || f.State != "open" || f.ResolvedAt != nil {
		t.Fatalf("reopened: %+v %v", f, err)
	}
}
