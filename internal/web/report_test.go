// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

func reportFinding(t *testing.T, app, id, fixed string, m match.Finding) store.Finding {
	t.Helper()
	m.AdvisoryID, m.FixedIn = id, fixed
	if m.State == "" {
		m.State = match.Affected
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return store.Finding{ID: app + id, AppID: app, AdvisoryID: id, FixedIn: fixed, MatchState: string(m.State), State: store.StateOpen,
		Detail: b, FirstSeen: time.Date(2026, 11, 28, 7, 0, 0, 0, time.UTC)}
}

func TestBuildReport(t *testing.T) {
	vim := "os:Debian:13/vim"
	brotli := "os:Debian:13/brotli"
	fs := []store.Finding{
		reportFinding(t, vim, "DEBIAN-CVE-2025-2", "2:9.1.1230-2+deb13u2", match.Finding{Aliases: []string{"CVE-2025-2"}, SeverityLabel: "medium",
			Evidence: match.Evidence{Version: "2:9.1.1230-2"}}),
		reportFinding(t, vim, "DEBIAN-CVE-2025-1", "2:9.1.1230-2+deb13u10", match.Finding{Aliases: []string{"CVE-2025-1"}, CVSS: 7.5,
			Evidence: match.Evidence{Version: "2:9.1.1230-2"}}),
		reportFinding(t, vim, "DEBIAN-CVE-2025-3", "", match.Finding{Aliases: []string{"CVE-2025-3"}, Evidence: match.Evidence{Version: "2:9.1.1230-2"}}),
		reportFinding(t, brotli, "DEBIAN-CVE-2026-9", "1.1.0-2+deb13u1", match.Finding{Aliases: []string{"CVE-2026-9"}, CVSS: 9.2, KEV: true,
			Evidence: match.Evidence{Version: "1.1.0-2"}}),
		reportFinding(t, brotli, "DEBIAN-CVE-2026-8", "", match.Finding{State: match.Unverified}),
	}
	r := buildReport(fs, "app")
	if r.Total != 4 || r.Fixable != 3 || r.Exploited != 1 || r.Unconfirmed != 1 {
		t.Fatalf("counts %+v", r)
	}
	if len(r.Packages) != 2 || r.Packages[0].Name != "brotli" || !r.Packages[0].KEV {
		t.Fatalf("an exploited package comes first: %+v", r.Packages)
	}
	v := r.Packages[1]
	// "+deb13u10" is above "+deb13u2" in Debian's order, not in a string
	// comparison.
	if v.Name != "vim" || v.Kind != "Debian 13 package" || v.Installed != "2:9.1.1230-2" || v.FixedIn != "2:9.1.1230-2+deb13u10" || v.Unfixed != 1 || v.Worst != "high" {
		t.Errorf("vim %+v", v)
	}
	if v.Flaws[0].ID != "CVE-2025-1" || v.Flaws[0].Severity != "high" || v.Flaws[2].Severity != "unrated" {
		t.Errorf("flaws by severity, under their CVE: %+v", v.Flaws)
	}
	var sevs []string
	for _, c := range r.Counts {
		sevs = append(sevs, c.Severity)
	}
	if strings.Join(sevs, ",") != "critical,high,medium,unrated" || r.Counts[0].Width != 25 || r.Counts[1].Offset != 25 {
		t.Errorf("severity counts %+v", r.Counts)
	}
	// The unconfirmed flaw is listed with its package, not counted.
	if b := r.Packages[0]; len(b.Flaws) != 2 || b.Flaws[1].State != "unverified" {
		t.Errorf("brotli %+v", b)
	}
}

func TestFlawIDAndDataset(t *testing.T) {
	cases := []struct{ id, want, dataset string }{
		{"DEBIAN-CVE-2025-1", "CVE-2025-1", "Debian security tracker"},
		{"UBUNTU-CVE-2025-1", "CVE-2025-1", "Ubuntu security data (Canonical)"},
		{"ALPINE-GHSA-2wp2-chmh-r934", "GHSA-2wp2-chmh-r934", "Alpine secdb"},
		{"WOLFI-CVE-2025-1", "CVE-2025-1", "Wolfi security data"},
		{"GHSA-aaaa-bbbb-cccc", "CVE-2025-9", "GitHub advisory database"},
		{"GO-2025-1", "CVE-2025-9", "Go vulnerability database"},
		{"CVE-2025-7", "CVE-2025-7", ""},
	}
	for _, c := range cases {
		if got := flawID(c.id, []string{"GHSA-x", "CVE-2025-9"}); got != c.want {
			t.Errorf("flawID(%s) = %s, want %s", c.id, got, c.want)
		}
		if got := datasetOf(c.id); got != c.dataset {
			t.Errorf("datasetOf(%s) = %q", c.id, got)
		}
	}
	if severityOf("MODERATE", 0) != "medium" || severityOf("", 9.8) != "critical" || severityOf("unimportant", 7) != "negligible" || severityOf("", 0) != "unrated" {
		t.Error("severityOf")
	}
}

func TestCSVRowNeutralisesFormulas(t *testing.T) {
	got := csvRow("=HYPERLINK(\"x\")", "+1", "-2", "@SUM(A1)", "\tx", "plain", "")
	want := []string{"'=HYPERLINK(\"x\")", "'+1", "'-2", "'@SUM(A1)", "'\tx", "plain", ""}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cell %d = %q, want %q", i, got[i], want[i])
		}
	}
	if safeFilename("my app/../x") != "my-app-..-x" || safeFilename("") != "app" {
		t.Error("safeFilename")
	}
}

// The report of an app downloads as CSV, for a signed-in user only.
func TestReportCSV(t *testing.T) {
	h := newHarness(t)
	ctx, now := t.Context(), time.Now()
	if err := h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "docker", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "cc", Name: "chef",
		Container: &inventory.Container{ImageRef: "mpepping/cyberchef:latest"}}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, "cc")
	detail := match.Finding{AdvisoryID: "ALPINE-CVE-2026-1", Aliases: []string{"CVE-2026-1"}, Image: true, State: match.Affected, FixedIn: "1.2.1-r0",
		Summary: "=cmd|' /C calc'!A0", CVSS: 9.8, Evidence: match.Evidence{Version: "1.2.0-r1", Package: "Alpine:v3.24/brotli", RecordID: "ALPINE-CVE-2026-1"}}
	if _, err := h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "os:Alpine:v3.24/brotli", AdvisoryID: "ALPINE-CVE-2026-1",
		MatchState: "affected", FixedIn: "1.2.1-r0", Detail: detail}}, now); err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.do(t, "GET", "/apps/"+wid+"/report.csv", nil, nil); resp.StatusCode == http.StatusOK {
		t.Fatal("the report is served without a sign-in")
	}
	h.signIn(t)
	resp, body := h.do(t, "GET", "/apps/"+wid+"/report.csv", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), `filename="chef-security-report.csv"`) {
		t.Fatalf("status %d, headers %v", resp.StatusCode, resp.Header)
	}
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][0] != "brotli" || rows[1][4] != "CVE-2026-1" || rows[1][7] != "critical" || rows[1][3] != "1.2.1-r0" {
		t.Fatalf("rows %q", rows)
	}
	if !strings.HasPrefix(rows[1][14], "'=") {
		t.Errorf("formula not neutralised: %q", rows[1][14])
	}
}

// Containers of one image that need the same update are one card on the
// front page; a different image or another update keeps its own.
func TestMergeSameImage(t *testing.T) {
	wl := func(id, name, image string) inventory.Workload {
		return inventory.Workload{ID: id, Name: name, HostID: "h", Container: &inventory.Container{ImageID: image}}
	}
	s := &snapshot{byID: map[string]inventory.Workload{
		"a": wl("a", "ssh-bastion", "sha256:1"), "b": wl("b", "ssh-inner", "sha256:1"), "c": wl("c", "ldap", "sha256:2"), "d": wl("d", "ts", "sha256:1"),
	}}
	cards := []appCard{
		{Key: "a", State: appLater, Action: "Rebuild the image", Count: 6, Command: "docker compose build 'ssh-bastion'"},
		{Key: "b", State: appLater, Action: "Rebuild the image", Count: 6, Command: "docker compose build 'ssh-inner'"},
		{Key: "c", State: appLater, Action: "Rebuild the image", Count: 6},
		{Key: "d", State: appSoon, Action: "Rebuild the image", Count: 6},
	}
	got := mergeSameImage(cards, s)
	if len(got) != 3 || got[0].Key != "a" || strings.Join(got[0].Others, ",") != "ssh-inner" {
		t.Fatalf("merged %+v", got)
	}
	if got[0].Command != "" {
		t.Error("a command naming one service must not stand for another")
	}
}
