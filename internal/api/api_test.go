// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

const testToken = "0123456789abcdef0123456789abcdef-test" // gitleaks:allow (synthetic)

func setup(t *testing.T, token string) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	h := New(Options{Store: st, Token: token, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, st
}

func do(t *testing.T, srv *httptest.Server, method, path, token, contentType, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestAuthentication(t *testing.T) {
	disabled, _ := setup(t, "")
	if resp, _ := do(t, disabled, "GET", "/api/v1/workloads", testToken, "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("disabled API: %d", resp.StatusCode)
	}
	if resp, _ := do(t, disabled, "GET", "/api/v1/workloads", "", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("disabled API, empty token: %d", resp.StatusCode)
	}

	srv, _ := setup(t, testToken)
	for _, tok := range []string{"", "wrong", testToken + "x", strings.ToUpper(testToken)} {
		resp, body := do(t, srv, "GET", "/api/v1/workloads", tok, "", "")
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("token %q: %d %s", tok, resp.StatusCode, body)
		}
	}
	// Unknown routes are not revealed before authentication.
	if resp, _ := do(t, srv, "GET", "/api/v1/nope", "", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated unknown route: %d", resp.StatusCode)
	}
	resp, body := do(t, srv, "GET", "/api/v1/workloads", testToken, "", "")
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != `{"workloads":[]}` {
		t.Fatalf("authorised: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("missing Cache-Control: no-store")
	}
}

func TestManualRoundTrip(t *testing.T) {
	srv, _ := setup(t, testToken)
	body := `{"host_name":"Synology NAS","name":"DSM","app_id":"synology-dsm","version":"7.2.2-72806","exposure":"lan","note":"check quarterly"}`
	resp, b := do(t, srv, "POST", "/api/v1/workloads", testToken, "application/json; charset=utf-8", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var created inventory.Workload
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatal(err)
	}
	if created.Manual == nil || created.Manual.Version != "7.2.2-72806" || created.Manual.Exposure != inventory.ExposureLAN {
		t.Fatalf("created: %s", b)
	}
	loc := resp.Header.Get("Location")
	if loc != "/api/v1/workloads/"+created.ID {
		t.Fatalf("Location %q", loc)
	}

	// Second entry on the same host name reuses the host.
	resp, b = do(t, srv, "POST", "/api/v1/workloads", testToken, "application/json",
		`{"host_name":"synology nas","name":"Photo Station","app_id":"synology-photos","version":"1.7.0"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("second create: %d %s", resp.StatusCode, b)
	}
	resp, b = do(t, srv, "GET", "/api/v1/hosts", testToken, "", "")
	var hosts struct{ Hosts []inventory.Host }
	if err := json.Unmarshal(b, &hosts); err != nil || resp.StatusCode != 200 || len(hosts.Hosts) != 1 || hosts.Hosts[0].Name != "Synology NAS" {
		t.Fatalf("hosts: %d %s", resp.StatusCode, b)
	}

	resp, b = do(t, srv, "GET", loc, testToken, "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `"synology-dsm"`) {
		t.Fatalf("get: %d %s", resp.StatusCode, b)
	}

	// Creating by host_id works too.
	resp, b = do(t, srv, "POST", "/api/v1/workloads", testToken, "application/json",
		`{"host_id":"`+hosts.Hosts[0].ID+`","name":"Hyper Backup","app_id":"hyper-backup","version":"4.1"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create by host_id: %d %s", resp.StatusCode, b)
	}

	if resp, _ := do(t, srv, "DELETE", loc, testToken, "", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "DELETE", loc, testToken, "", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete: %d", resp.StatusCode)
	}
	_, b = do(t, srv, "GET", "/api/v1/workloads", testToken, "", "")
	var list struct{ Workloads []inventory.Workload }
	if err := json.Unmarshal(b, &list); err != nil || len(list.Workloads) != 2 {
		t.Fatalf("active after delete: %s", b)
	}
	_, b = do(t, srv, "GET", "/api/v1/workloads?include_removed=true&kind=manual", testToken, "", "")
	if err := json.Unmarshal(b, &list); err != nil || len(list.Workloads) != 3 {
		t.Fatalf("including removed: %s", b)
	}
}

func TestManualValidation(t *testing.T) {
	srv, _ := setup(t, testToken)
	valid := `"name":"x","app_id":"app","version":"1.0"`
	cases := map[string]struct {
		ct, body string
		status   int
	}{
		"wrong content type": {"text/plain", `{"host_name":"h",` + valid + `}`, 415},
		"no content type":    {"", `{"host_name":"h",` + valid + `}`, 415},
		"malformed":          {"application/json", `{"host_name":`, 400},
		"unknown field":      {"application/json", `{"host_name":"h","admin":true,` + valid + `}`, 400},
		"trailing data":      {"application/json", `{"host_name":"h",` + valid + `}{}`, 400},
		"no host":            {"application/json", `{` + valid + `}`, 400},
		"both hosts":         {"application/json", `{"host_id":"local","host_name":"h",` + valid + `}`, 400},
		"missing host_id":    {"application/json", `{"host_id":"nope",` + valid + `}`, 400},
		"bad app id":         {"application/json", `{"host_name":"h","name":"x","app_id":"../etc","version":"1"}`, 400},
		"bad version":        {"application/json", `{"host_name":"h","name":"x","app_id":"a","version":"1 && rm"}`, 400},
		"bad exposure":       {"application/json", `{"host_name":"h","exposure":"world",` + valid + `}`, 400},
		"control chars":      {"application/json", `{"host_name":"h\u0000","name":"x","app_id":"a","version":"1"}`, 400},
		"too large":          {"application/json", `{"host_name":"h","note":"` + strings.Repeat("a", maxBodyBytes) + `",` + valid + `}`, 413},
	}
	for name, c := range cases {
		resp, b := do(t, srv, "POST", "/api/v1/workloads", testToken, c.ct, c.body)
		if resp.StatusCode != c.status {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
}

func TestObservedWorkloadsCannotBeDeleted(t *testing.T) {
	srv, st := setup(t, testToken)
	now := time.Now()
	if err := st.UpsertHost(t.Context(), inventory.Host{ID: inventory.LocalHostID, Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplySnapshot(t.Context(), inventory.LocalHostID, inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich", Container: &inventory.Container{ImageRef: "x"},
	}}, now); err != nil {
		t.Fatal(err)
	}
	id := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "c1")
	if err := st.ReplaceIdentifications(t.Context(), []identify.Result{{
		WorkloadID: id, AppID: "immich", Confidence: identify.Exact, Rule: "image x", Version: "1.2.3", VersionSource: "tag v1.2.3",
	}}, now); err != nil {
		t.Fatal(err)
	}
	resp, b := do(t, srv, "GET", "/api/v1/workloads/"+id, testToken, "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `"identification":{"app_id":"immich","confidence":"exact"`) {
		t.Fatalf("identification not served: %s", b)
	}
	if resp, b := do(t, srv, "DELETE", "/api/v1/workloads/"+id, testToken, "", ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("delete container: %d %s", resp.StatusCode, b)
	}
	if resp, _ := do(t, srv, "GET", "/api/v1/workloads/"+id, testToken, "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("container gone after refused delete: %d", resp.StatusCode)
	}
}

func TestListFilters(t *testing.T) {
	srv, _ := setup(t, testToken)
	for _, q := range []string{"include_removed=yes", "kind=vm"} {
		if resp, _ := do(t, srv, "GET", "/api/v1/workloads?"+q, testToken, "", ""); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", q, resp.StatusCode)
		}
	}
	if resp, _ := do(t, srv, "GET", "/api/v1/workloads/doesnotexist", testToken, "", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing workload: %d", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "PUT", "/api/v1/workloads", testToken, "", ""); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", resp.StatusCode)
	}
}

// countingReader counts how much of a request body was read.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestSessionCSRFBodyIsBounded: the form fallback of the CSRF check must not
// read an unbounded body before authorisation.
func TestSessionCSRFBodyIsBounded(t *testing.T) {
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	h := New(Options{Store: st, Log: slog.New(slog.DiscardHandler), Authenticate: func(*http.Request) (auth.Principal, bool) {
		return auth.Principal{Actor: "u", Write: true, Session: &auth.Current{CSRFToken: "tok"}}, true
	}})
	body := &countingReader{r: strings.NewReader("csrf=" + strings.Repeat("a", 1<<20))}
	req := httptest.NewRequest(http.MethodPost, Prefix+"scan", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	if body.n > maxBodyBytes+1 {
		t.Fatalf("read %d bytes before rejecting", body.n)
	}
}
