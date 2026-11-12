// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

type fakeNotifier struct{ fail bool }

func (f *fakeNotifier) Test(_ context.Context, channel string) error {
	if f.fail {
		return errors.New("ntfy: status 401")
	}
	if channel == "nope" {
		return errors.New(`channel "nope" is not configured`)
	}
	return nil
}

func setupLifecycle(t *testing.T, n Notifier) (*httptest.Server, *store.Store, string, *atomic.Int32) {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	ctx := t.Context()
	if err := st.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich", Container: &inventory.Container{ImageRef: "x"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	if _, err := st.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-1", MatchState: "affected"}}, now); err != nil {
		t.Fatal(err)
	}
	var changed atomic.Int32
	h := New(Options{Store: st, Token: testToken, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now },
		Changed: func(context.Context) { changed.Add(1) }, Notifier: n})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, st, store.FindingID(wid, "GHSA-1"), &changed
}

func TestFindingLifecycleAPI(t *testing.T) {
	srv, st, fid, changed := setupLifecycle(t, nil)
	base := "/api/v1/findings/" + fid

	resp, b := do(t, srv, "POST", base+"/ack", testToken, "", "")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"state":"acknowledged"`) {
		t.Fatalf("ack: %d %s", resp.StatusCode, b)
	}
	if resp, _ := do(t, srv, "POST", base+"/ack", testToken, "", ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("double ack: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "POST", base+"/snooze", testToken, "application/json", `{"days":0}`); resp.StatusCode != 400 {
		t.Errorf("snooze 0 days: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "POST", base+"/snooze", testToken, "application/json", `{"days":400}`); resp.StatusCode != 400 {
		t.Errorf("snooze 400 days: %d", resp.StatusCode)
	}
	resp, b = do(t, srv, "POST", base+"/snooze", testToken, "application/json", `{"days":7}`)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"state":"snoozed"`) {
		t.Fatalf("snooze: %d %s", resp.StatusCode, b)
	}
	if resp, _ := do(t, srv, "POST", base+"/reopen", testToken, "", ""); resp.StatusCode != 200 {
		t.Errorf("reopen: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "POST", "/api/v1/findings/nope/ack", testToken, "", ""); resp.StatusCode != 404 {
		t.Errorf("missing finding: %d", resp.StatusCode)
	}

	// Suppression requires a reason and a valid scope.
	for _, body := range []string{`{}`, `{"reason":"  "}`, `{"reason":"x","scope":"host"}`, `{"reason":"x","expires_at":"2020-01-01T00:00:00Z"}`, `{"reason":"x","extra":1}`} {
		if resp, b := do(t, srv, "POST", base+"/suppress", testToken, "application/json", body); resp.StatusCode != 400 {
			t.Errorf("suppress %s: %d %s", body, resp.StatusCode, b)
		}
	}
	resp, b = do(t, srv, "POST", base+"/suppress", testToken, "application/json", `{"reason":"not reachable from outside","scope":"app"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("suppress: %d %s", resp.StatusCode, b)
	}
	var sup store.Suppression
	_ = json.Unmarshal(b, &sup)
	if sup.WorkloadID != "" || sup.AppID != "immich" || sup.CreatedBy != "static-token" {
		t.Errorf("suppression: %+v", sup)
	}
	if err := st.ApplySuppressions(t.Context(), time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFinding(t.Context(), fid); f.State != store.StateSuppressed {
		t.Errorf("not suppressed: %s", f.State)
	}
	if resp, b := do(t, srv, "GET", "/api/v1/suppressions", testToken, "", ""); resp.StatusCode != 200 || !strings.Contains(string(b), sup.ID) {
		t.Errorf("list suppressions: %s", b)
	}
	if resp, _ := do(t, srv, "DELETE", "/api/v1/suppressions/"+sup.ID, testToken, "", ""); resp.StatusCode != 204 {
		t.Errorf("delete suppression: %d", resp.StatusCode)
	}

	_, b = do(t, srv, "GET", "/api/v1/audit", testToken, "", "")
	for _, action := range []string{"finding.acknowledge", "finding.snooze", "finding.reopen", "suppression.create", "suppression.delete"} {
		if !strings.Contains(string(b), action) {
			t.Errorf("audit lacks %s: %s", action, b)
		}
	}
	if changed.Load() < 5 {
		t.Errorf("changes not signalled: %d", changed.Load())
	}
}

func TestNotificationTestAPI(t *testing.T) {
	srv, _, _, _ := setupLifecycle(t, nil)
	if resp, _ := do(t, srv, "POST", "/api/v1/notifications/test", testToken, "", ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("no notifier: %d", resp.StatusCode)
	}
	srv, _, _, _ = setupLifecycle(t, &fakeNotifier{})
	if resp, b := do(t, srv, "POST", "/api/v1/notifications/test", testToken, "", ""); resp.StatusCode != 200 {
		t.Errorf("test all: %d %s", resp.StatusCode, b)
	}
	if resp, b := do(t, srv, "POST", "/api/v1/notifications/test", testToken, "application/json", `{"channel":"nope"}`); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("unknown channel: %d %s", resp.StatusCode, b)
	}
	srv, _, _, _ = setupLifecycle(t, &fakeNotifier{fail: true})
	if resp, b := do(t, srv, "POST", "/api/v1/notifications/test", testToken, "", ""); resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(b), "401") {
		t.Errorf("failing channel: %d %s", resp.StatusCode, b)
	}
	if resp, _ := do(t, srv, "GET", "/api/v1/notifications", testToken, "", ""); resp.StatusCode != 200 {
		t.Errorf("notification log: %d", resp.StatusCode)
	}
}
