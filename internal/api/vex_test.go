// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

func TestVEX(t *testing.T) {
	srv, st, fid, _ := setupLifecycle(t, nil)
	ctx := t.Context()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	purl := "pkg:docker/ghcr.io/immich-app/immich-server@v1.120.0"
	if err := st.ReplaceIdentifications(ctx, []identify.Result{{WorkloadID: wid, AppID: "immich", Confidence: identify.Exact, PURL: purl}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SyncFindings(ctx, []store.FindingInput{
		{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected", FixedIn: "1.121.0",
			Detail: match.Finding{AdvisoryID: "GHSA-1", Aliases: []string{"CVE-2026-1"}}},
		{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-2", MatchState: "unverified",
			Detail: match.Finding{AdvisoryID: "GHSA-2", Evidence: match.Evidence{Reason: "running version unknown"}}},
		{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-3", MatchState: "affected",
			Detail: match.Finding{AdvisoryID: "GHSA-3"}},
	}, now); err != nil {
		t.Fatal(err)
	}
	gid3 := store.FindingID(wid, "GHSA-3")
	if resp, b := do(t, srv, "POST", "/api/v1/findings/"+gid3+"/suppress", testToken, "application/json", `{"reason":"not reachable from outside"}`); resp.StatusCode != 201 {
		t.Fatalf("suppress: %d %s", resp.StatusCode, b)
	}
	_ = fid
	// The analysis applies suppressions to findings.
	if err := st.ApplySuppressions(ctx, now); err != nil {
		t.Fatal(err)
	}

	get := func() vexDocument {
		resp, b := do(t, srv, "GET", "/api/v1/vex", testToken, "", "")
		if resp.StatusCode != 200 || resp.Header.Get("Content-Disposition") == "" {
			t.Fatalf("vex: %d %s", resp.StatusCode, b)
		}
		var doc vexDocument
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	doc := get()
	if doc.Context != vexContext || doc.Version != 1 || len(doc.Statements) != 3 || doc.ID == "" {
		t.Fatalf("document: %+v", doc)
	}
	by := map[string]vexStatement{}
	for _, s := range doc.Statements {
		by[s.Vulnerability.Name] = s
	}
	// The CVE names the vulnerability; the advisory ID is an alias.
	s := by["CVE-2026-1"]
	if s.Status != "affected" || s.ActionStatement != "Update to 1.121.0 or later." || len(s.Vulnerability.Aliases) != 1 || s.Vulnerability.Aliases[0] != "GHSA-1" {
		t.Errorf("affected: %+v", s)
	}
	if s.Products[0].ID != purl || s.Products[0].Identifiers["purl"] != purl {
		t.Errorf("product: %+v", s.Products)
	}
	if s := by["GHSA-2"]; s.Status != "under_investigation" || s.StatusNotes != "The finding is unverified: running version unknown" {
		t.Errorf("unverified: %+v", s)
	}
	if s := by["GHSA-3"]; s.Status != "not_affected" || s.ImpactStatement != "Suppressed by the operator: not reachable from outside" {
		t.Errorf("suppressed: %+v", s)
	}
	// Same state, same ID.
	if again := get(); again.ID != doc.ID {
		t.Errorf("ID changed without a change: %s %s", doc.ID, again.ID)
	}
	if resp, _ := do(t, srv, "GET", "/api/v1/vex", "", "", ""); resp.StatusCode != 401 {
		t.Errorf("unauthenticated: %d", resp.StatusCode)
	}
}
