// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/api"
	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
)

const setupToken = "test-setup-token-0123456789"

type harness struct {
	srv   *httptest.Server
	store *store.Store
	c     *http.Client
}

func newHarness(t *testing.T, opts ...func(*Deps)) *harness {
	t.Helper()
	deps := testDeps(t, opts...)
	h, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &harness{srv: srv, store: deps.Store, c: c}
}

// testDeps are the dependencies of the test server.
func testDeps(t *testing.T, opts ...func(*Deps)) Deps {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now()
	if err := st.CreateSetupToken(ctx, auth.HashToken(setupToken), now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(fstest.MapFS{"immich.yaml": {Data: []byte(`id: immich
name: Immich
homepage: https://immich.app
images: [{match: ghcr.io/immich-app/immich-server}]
version: {scheme: semver}
advisories: {coverage: full, github_repos: [immich-app/immich]}
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	set, err := settings.New(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	proxies, _ := auth.NewProxies(nil, false)
	sessions := auth.NewSessions(st, auth.CookieAuto, proxies)
	apiAuth := &auth.APIAuth{Tokens: st, Sessions: sessions}
	log := slog.New(slog.DiscardHandler)
	deps := Deps{
		Store: st, Catalog: catalog.NewLive(cat), Settings: set, Sessions: sessions, Throttle: auth.NewThrottle(), Proxies: proxies, APIAuth: apiAuth,
		API: api.New(api.Options{Store: st, Authenticate: apiAuth.Authenticate, Log: log}),
		Log: log,
	}
	for _, o := range opts {
		o(&deps)
	}
	return deps
}

// formToken returns the pre-session form token, loading a form page first
// when the cookie jar has none.
func (h *harness) formToken(t *testing.T) string {
	t.Helper()
	u, _ := url.Parse(h.srv.URL)
	find := func() string {
		if h.c.Jar == nil {
			return ""
		}
		for _, c := range h.c.Jar.Cookies(u) {
			if c.Name == auth.FormCookieName {
				return c.Value
			}
		}
		return ""
	}
	if tok := find(); tok != "" {
		return tok
	}
	for _, p := range []string{"/setup", "/login"} {
		h.do(t, "GET", p, nil, nil)
	}
	return find()
}

// do sends a request. Posts to /login and /setup get the form token unless
// the form sets csrf to "omit".
func (h *harness) do(t *testing.T, method, path string, form url.Values, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	if method == "POST" && form != nil && (strings.HasPrefix(path, "/login") || strings.HasPrefix(path, "/setup")) {
		switch form.Get("csrf") {
		case "omit":
			form.Del("csrf")
		case "":
			form.Set("csrf", h.formToken(t))
		}
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, h.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var csrfMeta = regexp.MustCompile(`name="csrf-token" content="([^"]+)"`)

// signIn completes setup and returns the CSRF token of the session.
func (h *harness) signIn(t *testing.T) string {
	t.Helper()
	resp, _ := h.do(t, "POST", "/setup", url.Values{"token": {setupToken}, "username": {"admin"}, "password": {"correct horse battery"}, "password2": {"correct horse battery"}}, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("setup: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body := h.do(t, "GET", "/", nil, nil)
	m := csrfMeta.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token on overview:\n%s", body)
	}
	return m[1]
}

func TestSecurityHeadersAndCSP(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/healthz", "/login", "/setup", "/static/css/varde.css", "/nope", "/api/v1/status"} {
		resp, _ := h.do(t, "GET", path, nil, nil)
		csp := resp.Header.Get("Content-Security-Policy")
		if csp != ContentSecurityPolicy || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP %q", path, csp)
		}
		for hdr, want := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY"} {
			if resp.Header.Get(hdr) != want {
				t.Errorf("%s: %s=%q", path, hdr, resp.Header.Get(hdr))
			}
		}
		if resp.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS over plain HTTP", path)
		}
	}
}

// TestTemplatesHaveNoInlineCode keeps the strict CSP achievable.
func TestTemplatesHaveNoInlineCode(t *testing.T) {
	inlineScript := regexp.MustCompile(`<script(?:\s[^>]*)?>\s*[^<\s]`)
	for _, dir := range []string{"templates", "static"} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") && !strings.HasSuffix(p, ".svg") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := string(b)
			for _, bad := range []string{" style=", "<style", " onclick=", " onload=", " onerror=", " onsubmit=", "javascript:"} {
				if strings.Contains(s, bad) {
					t.Errorf("%s contains %q", p, bad)
				}
			}
			if inlineScript.MatchString(s) {
				t.Errorf("%s contains an inline script", p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSetupFlow(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.do(t, "GET", "/", nil, nil); resp.Header.Get("Location") != "/setup" {
		t.Fatalf("no users: redirect %q", resp.Header.Get("Location"))
	}
	if resp, _ := h.do(t, "GET", "/login", nil, nil); resp.Header.Get("Location") != "/setup" {
		t.Fatalf("login before setup: %q", resp.Header.Get("Location"))
	}
	bad := []url.Values{
		{"token": {"wrong"}, "username": {"admin"}, "password": {"correct horse battery"}, "password2": {"correct horse battery"}},
		{"token": {setupToken}, "username": {"admin"}, "password": {"short"}, "password2": {"short"}},
		{"token": {setupToken}, "username": {"admin"}, "password": {"correct horse battery"}, "password2": {"different horse battery"}},
		{"token": {setupToken}, "username": {"<script>"}, "password": {"correct horse battery"}, "password2": {"correct horse battery"}},
	}
	for i, f := range bad {
		if resp, _ := h.do(t, "POST", "/setup", f, nil); resp.StatusCode < 400 {
			t.Errorf("bad setup %d accepted: %d", i, resp.StatusCode)
		}
	}
	if resp, _ := h.do(t, "POST", "/setup", bad[0], map[string]string{"Origin": "http://evil.example"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin setup: %d", resp.StatusCode)
	}
	h.signIn(t)
	// Setup is closed now, and the token cannot be reused.
	if resp, _ := h.do(t, "GET", "/setup", nil, nil); resp.Header.Get("Location") != "/login" {
		t.Errorf("setup after completion: %d", resp.StatusCode)
	}
	if n, _ := h.store.CountUsers(t.Context()); n != 1 {
		t.Fatalf("users: %d", n)
	}
}

func TestLoginLogoutAndThrottle(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	if resp, _ := h.do(t, "POST", "/logout", url.Values{"csrf": {csrf}}, nil); resp.Header.Get("Location") != "/login" {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "GET", "/findings", nil, nil); !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Fatalf("after logout: %q", resp.Header.Get("Location"))
	}
	resp, body := h.do(t, "POST", "/login", url.Values{"username": {"admin"}, "password": {"wrong password!!"}}, nil)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "Invalid username or password") {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	if resp, body := h.do(t, "POST", "/login", url.Values{"username": {"nobody"}, "password": {"wrong password!!"}}, nil); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "Invalid username or password") {
		t.Fatal("unknown user must look like a wrong password")
	}
	resp, _ = h.do(t, "POST", "/login?next=//evil.example/x", url.Values{"username": {"admin"}, "password": {"correct horse battery"}}, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("login with foreign next: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for range 6 {
		h.do(t, "POST", "/login", url.Values{"username": {"admin"}, "password": {"wrong password!!"}}, nil)
	}
	if resp, _ := h.do(t, "POST", "/login", url.Values{"username": {"admin"}, "password": {"correct horse battery"}}, nil); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("throttle: %d", resp.StatusCode)
	}
	audit, _ := h.store.AuditLog(t.Context(), 50)
	var failed int
	for _, e := range audit {
		if e.Action == "login.failed" {
			failed++
		}
	}
	if failed < 2 {
		t.Errorf("failed logins not audited: %d", failed)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/findings?x=1": "/findings?x=1", "//evil.example": "/", "https://evil.example": "/", "/\\evil": "/", "": "/", "/a\r\nb": "/",
		"/\t/evil.example": "/", "/\x7f": "/", "/%09/evil.example": "/%09/evil.example", "/findings#x": "/findings#x"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	form := url.Values{"PUBLIC_DOMAINS": {"example.com"}}
	if resp, _ := h.do(t, "POST", "/settings", form, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("missing csrf: %d", resp.StatusCode)
	}
	form.Set("csrf", "forged")
	if resp, _ := h.do(t, "POST", "/settings", form, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong csrf: %d", resp.StatusCode)
	}
	form.Set("csrf", csrf)
	if resp, _ := h.do(t, "POST", "/settings", form, map[string]string{"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "POST", "/settings", form, map[string]string{"Origin": h.srv.URL, "Sec-Fetch-Site": "same-origin"}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("valid post: %d", resp.StatusCode)
	}
}

func TestPagesRenderForSignedInUser(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	ctx := t.Context()
	now := time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{{
		Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich_server",
		Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"},
	}}, now)
	for _, path := range []string{"/", "/findings", "/systems/apps", "/systems/gaps", "/systems", "/settings/sources", "/settings", "/findings?state=all&priority=P1"} {
		resp, body := h.do(t, "GET", path, nil, nil)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<main") {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
	// A container no app could be identified in: nothing is checked, so
	// the overview does not claim that all is clear.
	_, body := h.do(t, "GET", "/", nil, nil)
	if strings.Contains(body, "All clear") || !strings.Contains(body, "Nothing checked yet") || !strings.Contains(body, "mark-unlit.svg") {
		t.Error("unassessed state not rendered")
	}
	// A P1 finding lights the beacon.
	wid := inventory.WorkloadID("local", inventory.KindContainer, "c1")
	_, _ = h.store.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "immich", AdvisoryID: "GHSA-test", MatchState: "affected", FixedIn: "1.121.0", Detail: map[string]any{"summary": "<b>x</b>"}}}, now)
	_ = h.store.SetAssessments(ctx, []store.Assessment{{ID: store.FindingID(wid, "GHSA-test"), Priority: "P1", Exposure: "public"}})
	_, body = h.do(t, "GET", "/", nil, nil)
	if !strings.Contains(body, "1 urgent update to do") || !strings.Contains(body, "1 new urgent finding on 1 container or system") || !strings.Contains(body, `class="todo todo--p1"`) || !strings.Contains(body, "hero--alert") || strings.Contains(body, "<b>x</b>") {
		t.Error("P1 state not rendered or upstream text not escaped")
	}
	resp, body := h.do(t, "GET", "/findings/"+store.FindingID(wid, "GHSA-test"), nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "1.121.0") {
		t.Errorf("finding detail: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "GET", "/findings/nope", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing finding: %d", resp.StatusCode)
	}
	// By default one card per update to do on a system, with the app
	// versions behind it.
	_, body = h.do(t, "GET", "/findings", nil, nil)
	if !strings.Contains(body, `class="todo todo--p1"`) || !strings.Contains(body, "1 update to do") || !strings.Contains(body, "Pull a newer image and recreate the container") || !strings.Contains(body, "docker compose pull") ||
		!strings.Contains(body, `class="group group--p1"`) {
		t.Error("findings not grouped by what fixes them")
	}
	_, body = h.do(t, "GET", "/findings?view=package", nil, nil)
	if !strings.Contains(body, `class="group group--p1"`) || !strings.Contains(body, "1 app or package version") || strings.Contains(body, `class="todo`) {
		t.Error("findings not grouped by app version")
	}
	if _, body = h.do(t, "GET", "/findings?view=list", nil, nil); strings.Contains(body, `class="group`) || !strings.Contains(body, "GHSA-test") {
		t.Error("list view not rendered")
	}
	// Acknowledged findings leave the alert but stay visible as still open.
	if err := h.store.Acknowledge(ctx, store.FindingID(wid, "GHSA-test"), now); err != nil {
		t.Fatal(err)
	}
	_, body = h.do(t, "GET", "/", nil, nil)
	if strings.Contains(body, "hero--alert") || !strings.Contains(body, "Nothing new") || !strings.Contains(body, "Acknowledged, still open") {
		t.Error("acknowledged finding not separated from new ones")
	}
}

func TestAPITokensAndMetrics(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	createToken := func(scope string) string {
		_, body := h.do(t, "POST", "/settings/tokens", url.Values{"csrf": {csrf}, "name": {scope + "-token"}, "scope": {scope}}, nil)
		m := regexp.MustCompile(`id="new-token">(varde_[A-Za-z0-9_-]+)<`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("token not shown once:\n%s", body)
		}
		return m[1]
	}
	read, write := createToken("read"), createToken("write")
	bearer := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

	anon := &harness{srv: h.srv, store: h.store, c: &http.Client{}}
	if resp, _ := anon.do(t, "GET", "/api/v1/workloads", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous API: %d", resp.StatusCode)
	}
	if resp, _ := anon.do(t, "GET", "/api/v1/workloads", nil, bearer(read)); resp.StatusCode != http.StatusOK {
		t.Errorf("read token GET: %d", resp.StatusCode)
	}
	if resp, _ := anon.do(t, "POST", "/api/v1/scan", nil, bearer(read)); resp.StatusCode != http.StatusForbidden {
		t.Errorf("read token POST: %d", resp.StatusCode)
	}
	if resp, _ := anon.do(t, "POST", "/api/v1/scan", nil, bearer(write)); resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("write token POST: %d", resp.StatusCode)
	}
	if resp, _ := anon.do(t, "GET", "/api/v1/workloads", nil, bearer(read+"x")); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged token: %d", resp.StatusCode)
	}
	// Session-authenticated API writes need the CSRF header.
	if resp, _ := h.do(t, "POST", "/api/v1/scan", nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("session API POST without CSRF: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "POST", "/api/v1/scan", nil, map[string]string{"X-CSRF-Token": csrf}); resp.StatusCode == http.StatusForbidden {
		t.Errorf("session API POST with CSRF: %d", resp.StatusCode)
	}

	if resp, _ := anon.do(t, "GET", "/metrics", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous metrics: %d", resp.StatusCode)
	}
	resp, body := anon.do(t, "GET", "/metrics", nil, bearer(read))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "varde_build_info") || !strings.Contains(body, "varde_workloads 0") {
		t.Errorf("metrics: %d\n%s", resp.StatusCode, body)
	}

	tokens, _ := h.store.APITokens(t.Context())
	for _, tk := range tokens {
		if strings.Contains(tk.TokenHash, read) {
			t.Fatal("raw token stored")
		}
	}
}

func TestBrandAssetsInSync(t *testing.T) {
	for _, f := range []string{"mark.svg", "mark-unlit.svg", "mark-mono.svg", "favicon.svg"} {
		a, err := os.ReadFile(filepath.Join("..", "..", "assets", "brand", f))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join("static", "brand", f))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Errorf("%s differs between assets/brand and internal/web/static/brand", f)
		}
	}
}

func TestHealthAndReady(t *testing.T) {
	h := newHarness(t)
	if resp, body := h.do(t, "GET", "/healthz", nil, nil); resp.StatusCode != 200 || body != "ok\n" {
		t.Errorf("healthz: %d %q", resp.StatusCode, body)
	}
	if resp, _ := h.do(t, "HEAD", "/healthz", nil, nil); resp.StatusCode != 200 {
		t.Errorf("healthz HEAD: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "POST", "/healthz", url.Values{}, nil); resp.StatusCode == http.StatusOK {
		t.Errorf("healthz POST: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "GET", "/readyz", nil, nil); resp.StatusCode != 200 {
		t.Errorf("readyz: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "GET", "/static/", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("static directory listing: %d", resp.StatusCode)
	}
}

func TestSetupRejectsExpiredToken(t *testing.T) {
	h := newHarness(t)
	past := time.Now().Add(-48 * time.Hour)
	if err := h.store.CreateSetupToken(t.Context(), auth.HashToken(setupToken), past, past.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	resp, _ := h.do(t, "POST", "/setup", url.Values{"token": {setupToken}, "username": {"admin"}, "password": {"correct horse battery"}, "password2": {"correct horse battery"}}, nil)
	if resp.StatusCode < 400 {
		t.Fatalf("expired setup token accepted: %d", resp.StatusCode)
	}
	if n, _ := h.store.CountUsers(t.Context()); n != 0 {
		t.Fatalf("account created with expired token: %d", n)
	}
}

// TestPreSessionFormToken covers plain-HTTP LAN browsers: no fetch metadata
// and Origin "null" on same-origin posts. The form token decides.
func TestPreSessionFormToken(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	_, _ = h.do(t, "POST", "/logout", url.Values{"csrf": {csrfOf(t, h)}}, nil)
	creds := func() url.Values {
		return url.Values{"username": {"admin"}, "password": {"correct horse battery"}}
	}
	nullOrigin := map[string]string{"Origin": "null"}

	f := creds()
	f.Set("csrf", "omit")
	if resp, _ := h.do(t, "POST", "/login", f, nullOrigin); resp.StatusCode != http.StatusForbidden {
		t.Errorf("login without form token: %d", resp.StatusCode)
	}
	f = creds()
	f.Set("csrf", strings.Repeat("x", 43))
	if resp, _ := h.do(t, "POST", "/login", f, nullOrigin); resp.StatusCode != http.StatusForbidden {
		t.Errorf("login with forged form token: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "POST", "/login", creds(), map[string]string{"Origin": "null", "Sec-Fetch-Site": "cross-site"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site login: %d", resp.StatusCode)
	}
	resp, _ := h.do(t, "POST", "/login", creds(), nullOrigin)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("plain-HTTP LAN login with Origin null: %d", resp.StatusCode)
	}
	// After login, session posts with Origin null still need the session CSRF token.
	if resp, _ := h.do(t, "POST", "/settings", url.Values{"PUBLIC_DOMAINS": {"example.com"}}, nullOrigin); resp.StatusCode != http.StatusForbidden {
		t.Errorf("session post without csrf: %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, "POST", "/settings", url.Values{"PUBLIC_DOMAINS": {"example.com"}, "csrf": {csrfOf(t, h)}}, nullOrigin); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("session post with csrf and Origin null: %d", resp.StatusCode)
	}
}

func csrfOf(t *testing.T, h *harness) string {
	t.Helper()
	_, body := h.do(t, "GET", "/", nil, nil)
	m := csrfMeta.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token")
	}
	return m[1]
}

func TestHostsEnrollmentAndRevoke(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	h := newHarness(t, func(d *Deps) { d.AgentCAPin, d.AgentListenAddr = pin, ":8443" })
	csrf := h.signIn(t)
	ctx := t.Context()

	resp, body := h.do(t, "POST", "/connections/agents/tokens", url.Values{"csrf": {csrf}, "name": {"nas"}}, nil)
	m := regexp.MustCompile(`id="new-token">(varde-enroll-v1\.[A-Za-z0-9_-]+\.([0-9a-f]{64}))<`).FindStringSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil || m[2] != pin || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token not shown once with the CA pin: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "8443") {
		t.Error("listener port not shown")
	}
	_, body = h.do(t, "GET", "/connections/agents", nil, nil)
	if strings.Contains(body, m[1]) || !strings.Contains(body, "Unused tokens") {
		t.Error("token shown again or pending list missing")
	}
	if resp, _ := h.do(t, "POST", "/connections/agents/tokens", url.Values{"csrf": {csrf}, "name": {""}}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty name: %d", resp.StatusCode)
	}

	// Only agents can be revoked.
	now := time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "server", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	if resp, _ := h.do(t, "POST", "/connections/agents/local/revoke", url.Values{"csrf": {csrf}}, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoke local host: %d", resp.StatusCode)
	}
	if err := h.store.EnrollAgent(ctx, auth.HashToken("unused"), inventory.Host{ID: strings.Repeat("1", 32), Name: "nas", Kind: inventory.HostDocker}, store.AgentCert{}, now); err == nil {
		t.Fatal("enrolled with an unknown token")
	}
	_ = h.store.CreateEnrollmentToken(ctx, store.EnrollmentToken{ID: "t1", Name: "nas", TokenHash: auth.HashToken("s"), CreatedBy: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	agentID := strings.Repeat("1", 32)
	if err := h.store.EnrollAgent(ctx, auth.HashToken("s"), inventory.Host{ID: agentID, Name: "nas", Kind: inventory.HostDocker, ReportInterval: 15 * time.Minute}, store.AgentCert{Fingerprint: "f", Expires: now.Add(90 * 24 * time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.do(t, "POST", "/connections/agents/"+agentID+"/revoke", url.Values{"csrf": {csrf}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if st, _, _, _ := h.store.AgentPins(ctx, agentID); st != inventory.HostRevoked {
		t.Fatalf("state %s", st)
	}
	_, body = h.do(t, "GET", "/connections/agents", nil, nil)
	if !strings.Contains(body, "revoked") {
		t.Error("revoked state not shown")
	}
}

func TestHostsWithoutAgentListener(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	_, body := h.do(t, "GET", "/connections/agents", nil, nil)
	if !strings.Contains(body, "agent listener is switched off") {
		t.Error("off state not explained")
	}
	if resp, _ := h.do(t, "POST", "/connections/agents/tokens", url.Values{"csrf": {csrf}, "name": {"nas"}}, nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("enroll while off: %d", resp.StatusCode)
	}
}

func TestOverviewShowsBlindSpots(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	_ = h.store.SyncNotices(t.Context(), store.NoticeHostStale, []store.Notice{{Key: "host-stale:x", Subject: "x", Title: "Host <nas> is not reporting", Detail: "Last contact yesterday."}}, time.Now())
	_, body := h.do(t, "GET", "/", nil, nil)
	if !strings.Contains(body, "Blind spots") || !strings.Contains(body, "Host &lt;nas&gt; is not reporting") || strings.Contains(body, "No action needed") {
		t.Errorf("blind spots not shown or not escaped:\n%s", body)
	}
}

// TestLoginReturnsToRequestedPage: the login form carries the return path,
// and only a local one survives.
func TestLoginReturnsToRequestedPage(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	h.do(t, "POST", "/logout", url.Values{"csrf": {csrf}}, nil)
	resp, _ := h.do(t, "GET", "/findings?priority=P1", nil, nil)
	loc := resp.Header.Get("Location")
	_, body := h.do(t, "GET", loc, nil, nil)
	if !strings.Contains(body, `name="next" value="/findings?priority=P1"`) {
		t.Fatalf("return path not in the form (%s):\n%s", loc, body)
	}
	resp, _ = h.do(t, "POST", "/login", url.Values{"username": {"admin"}, "password": {"correct horse battery"}, "next": {"/findings?priority=P1"}}, nil)
	if resp.Header.Get("Location") != "/findings?priority=P1" {
		t.Fatalf("redirect after login: %q", resp.Header.Get("Location"))
	}
	h.do(t, "POST", "/logout", url.Values{"csrf": {csrfOf(t, h)}}, nil)
	resp, _ = h.do(t, "POST", "/login", url.Values{"username": {"admin"}, "password": {"correct horse battery"}, "next": {"/\t/evil.example"}}, nil)
	if resp.Header.Get("Location") != "/" {
		t.Fatalf("foreign return path: %q", resp.Header.Get("Location"))
	}
}

func TestNotAnAppMark(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	ctx := t.Context()
	now := time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
		{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "db", Container: &inventory.Container{ImageRef: "pgvector/pgvector:pg16"}},
		{Kind: inventory.KindContainer, RuntimeID: "c2", Name: "tool", Container: &inventory.Container{ImageRef: "ghcr.io/acme/tool:1.0"}},
		{Kind: inventory.KindContainer, RuntimeID: "c3", Name: "tool-worker", Container: &inventory.Container{ImageRef: "ghcr.io/acme/tool:1.0"}},
	}, now)
	_, body := h.do(t, "GET", "/systems/gaps", nil, nil)
	if strings.Count(body, `action="/systems/gaps/not-an-app"`) != 1 || !strings.Contains(body, "tool, tool-worker") {
		t.Error("containers of one image not listed as one row")
	}
	if !strings.Contains(body, "1 supporting container</a>") || !strings.Contains(body, "database or cache") || !strings.Contains(body, "their packages are checked all the same") {
		t.Fatal("built-in helper not left out of the gaps")
	}
	post := func(path, repo string) int {
		resp, _ := h.do(t, "POST", path, url.Values{"csrf": {csrf}, "repository": {repo}}, nil)
		return resp.StatusCode
	}
	if code := post("/systems/gaps/not-an-app", "ghcr.io/acme/other"); code != http.StatusBadRequest {
		t.Errorf("unknown repository: %d", code)
	}
	if code := post("/systems/gaps/not-an-app", "ghcr.io/acme/tool"); code != http.StatusSeeOther {
		t.Fatalf("mark: %d", code)
	}
	_, body = h.do(t, "GET", "/systems/gaps", nil, nil)
	if !strings.Contains(body, "3 supporting containers</a>") || !strings.Contains(body, "Count again") || !strings.Contains(body, "Every workload matches a catalog entry") {
		t.Error("marked container still counted as a gap")
	}
	if code := post("/systems/gaps/not-an-app/delete", "ghcr.io/acme/tool"); code != http.StatusSeeOther {
		t.Errorf("unmark: %d", code)
	}
	if code := post("/systems/gaps/not-an-app/delete", "ghcr.io/acme/tool"); code != http.StatusNotFound {
		t.Errorf("unmark twice: %d", code)
	}
	log, _ := h.store.AuditLog(ctx, 10)
	actions := ""
	for _, e := range log {
		actions += e.Action + " "
	}
	if !strings.Contains(actions, "coverage.not-an-app") || !strings.Contains(actions, "coverage.is-an-app") {
		t.Errorf("audit log: %s", actions)
	}
}

// Opened over plain http while cookies are HTTPS-only, the sign-in cannot
// work: the answer says so instead of asking to reload.
func TestHTTPSOnlyCookiesOverHTTPExplained(t *testing.T) {
	h := newHarness(t, func(d *Deps) {
		proxies, _ := auth.NewProxies(nil, true)
		d.Proxies = proxies
		d.Sessions = auth.NewSessions(d.Store, auth.CookieAlways, proxies)
	})
	// A browser does not keep a Secure cookie of a plain-http address in
	// the network. The test client would, for the loopback address of the
	// test server, so it gets no jar.
	h.c.Jar = nil
	form := url.Values{"token": {setupToken}, "username": {"admin"}, "password": {"correct horse battery"}, "password2": {"correct horse battery"}}
	resp, body := h.do(t, "POST", "/setup", form, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d (Location %q), want 403", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, want := range []string{"https address", "VARDE_BEHIND_TLS_PROXY", "plain http"} {
		if !strings.Contains(body, want) {
			t.Errorf("answer lacks %q:\n%s", want, body)
		}
	}
	// A cross-site post in the default setup keeps the short answer.
	h = newHarness(t)
	_, body = h.do(t, "POST", "/setup", form, map[string]string{"Origin": "http://evil.example"})
	if strings.Contains(body, "VARDE_BEHIND_TLS_PROXY") || !strings.Contains(body, "Request blocked") {
		t.Errorf("cross-site answer: %s", body)
	}
}
