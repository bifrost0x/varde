// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// The history shows what an update fixed, with the versions before and
// after, on its own page, on the finding's page and in the CSV export.
func TestHistoryShowsFixes(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx := t.Context()
	now := time.Now().Add(-time.Hour)
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "=node64",
		Container: &inventory.Container{ImageRef: "ghcr.io/ipv64net/node64:latest"}}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	in := store.FindingInput{WorkloadID: wid, AppID: "os:Go/github.com/andybalholm/brotli", AdvisoryID: "GO-2026-6888", MatchState: "affected", FixedIn: "1.2.8",
		Detail: map[string]any{"evidence": map[string]any{"version": "1.2.7"}}}
	if _, err := h.store.SyncFindingsSeen(ctx, []store.FindingInput{in}, nil, now.Add(-72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetAssessments(ctx, []store.Assessment{{ID: in.ID(), Priority: "P1", Exposure: "lan"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SyncFindingsSeen(ctx, nil, map[string]string{store.SeenKey(wid, in.AppID): "1.2.8"}, now); err != nil {
		t.Fatal(err)
	}

	resp, body := h.do(t, "GET", "/findings/history?days=7", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("history: %d %s", resp.StatusCode, body)
	}
	for _, want := range []string{"New image", "=node64 on nas", "GO-2026-6888", "1.2.7", "1.2.8", "Fixed by an update", "3 days"} {
		if !strings.Contains(body, want) {
			t.Errorf("history without %q", want)
		}
	}
	_, body = h.do(t, "GET", "/findings/"+in.ID(), nil, nil)
	if !strings.Contains(body, `id="history-title"`) || !strings.Contains(body, "New image") {
		t.Error("finding page without its history")
	}
	resp, body = h.do(t, "GET", "/findings/history.csv?days=7", nil, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(body, "resolved,updated,nas,'=node64,") || !strings.Contains(body, ",1.2.7,1.2.8,1.2.8,3.0") {
		t.Errorf("csv rows:\n%s", body)
	}
}

// An acknowledged urgent finding does not make an update urgent again
// because another, minor finding of the same container is new.
func TestOverviewUrgencyFromNewFindings(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "web",
		Container: &inventory.Container{ImageRef: "nginx:1.24"}}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	urgent := store.FindingInput{WorkloadID: wid, AppID: "os:Debian:12/glibc", AdvisoryID: "DEBIAN-CVE-1", MatchState: "affected", FixedIn: "2"}
	minor := store.FindingInput{WorkloadID: wid, AppID: "os:Debian:12/zlib", AdvisoryID: "DEBIAN-CVE-2", MatchState: "affected", FixedIn: "2"}
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{urgent, minor}, now); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetAssessments(ctx, []store.Assessment{{ID: urgent.ID(), Priority: "P1", Exposure: "lan"}, {ID: minor.ID(), Priority: "P3", Exposure: "lan"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Acknowledge(ctx, urgent.ID(), now); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/", nil, nil)
	if strings.Contains(body, `id="urgent-title"`) || strings.Contains(body, "urgent update") {
		t.Errorf("acknowledged P1 listed as an urgent update:\n%s", body)
	}
}
