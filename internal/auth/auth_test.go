// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/store"
)

func TestPasswordHashing(t *testing.T) {
	ctx := context.Background()
	h, err := HashPassword(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("hash format %q", h)
	}
	if err := VerifyPassword(ctx, "correct horse battery", h); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyPassword(ctx, "correct horse batterY", h); !errors.Is(err, ErrMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	h2, _ := HashPassword(ctx, "correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"short", strings.Repeat("a", 11), strings.Repeat("a", 257), "\xff\xfe" + strings.Repeat("a", 12)} {
		if _, err := HashPassword(ctx, bad); !errors.Is(err, ErrWeakPassword) {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := HashPassword(ctx, "zwölf zeichen"); err != nil {
		t.Errorf("unicode password rejected: %v", err)
	}
	for _, enc := range []string{"", "$2b$10$abc", "$argon2id$v=19$m=999999999,t=3,p=4$AAAA$AAAA", "$argon2id$v=19$m=65536,t=3,p=4$!!$AAAA"} {
		if err := VerifyPassword(ctx, "whatever-password", enc); err == nil {
			t.Errorf("%q verified", enc)
		}
	}
	VerifyDummy(ctx, "anything") // must not panic or block
}

func TestTokens(t *testing.T) {
	a, err := RandomToken(32)
	if err != nil || len(a) != 43 {
		t.Fatalf("token %q %v", a, err)
	}
	b, _ := RandomToken(32)
	if a == b || HashToken(a) == HashToken(b) || len(HashToken(a)) != 64 {
		t.Fatal("tokens not unique")
	}
	if !EqualTokens(a, a) || EqualTokens(a, b) {
		t.Fatal("EqualTokens")
	}
}

func TestThrottle(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	th := NewThrottle()
	th.now = func() time.Time { return now }
	for range 5 {
		if ok, _ := th.Allowed("admin", "10.0.0.1"); !ok {
			t.Fatal("blocked within free attempts")
		}
		th.Failure("admin", "10.0.0.1")
	}
	th.Failure("admin", "10.0.0.1") // 6th
	ok, wait := th.Allowed("Admin", "10.0.0.9")
	if ok || wait != time.Second {
		t.Fatalf("account not throttled: %v %v", ok, wait)
	}
	if ok, _ := th.Allowed("other", "10.0.0.1"); ok {
		t.Fatal("IP not throttled for other accounts")
	}
	th.Failure("admin", "10.0.0.1")
	if _, wait := th.Allowed("admin", "x"); wait != 2*time.Second {
		t.Fatalf("delay not doubling: %v", wait)
	}
	for range 30 {
		th.Failure("admin", "10.0.0.1")
	}
	if _, wait := th.Allowed("admin", "x"); wait != 15*time.Minute {
		t.Fatalf("delay not capped: %v", wait)
	}
	th.Success("admin", "10.0.0.1")
	if ok, _ := th.Allowed("admin", "10.0.0.2"); !ok {
		t.Fatal("success did not clear account")
	}
	if ok, _ := th.Allowed("someone", "10.0.0.1"); ok {
		t.Fatal("success cleared the IP")
	}
}

func TestProxies(t *testing.T) {
	p, err := NewProxies([]string{"10.0.0.0/8", "192.168.1.5"}, false)
	if err != nil {
		t.Fatal(err)
	}
	req := func(remote, xff, proto string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		return r
	}
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.7:5000", "1.2.3.4", "203.0.113.7"},         // untrusted peer: header ignored
		{"10.1.1.1:5000", "1.2.3.4", "1.2.3.4"},                // trusted proxy
		{"10.1.1.1:5000", "1.2.3.4, 10.2.2.2", "1.2.3.4"},      // chain of trusted proxies
		{"10.1.1.1:5000", "6.6.6.6, 1.2.3.4", "1.2.3.4"},       // spoofed left entry ignored
		{"192.168.1.5:1", "garbage", "192.168.1.5"},            // malformed header
		{"[::ffff:10.0.0.1]:80", "2001:db8::1", "2001:db8::1"}, // mapped IPv4 peer
	}
	for _, c := range cases {
		if got := p.ClientIP(req(c.remote, c.xff, "")); got != c.want {
			t.Errorf("%s / %s: %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	if !p.IsTLS(req("10.1.1.1:1", "", "https")) || p.IsTLS(req("203.0.113.7:1", "", "https")) {
		t.Error("X-Forwarded-Proto trust")
	}
	tlsReq := req("203.0.113.7:1", "", "")
	tlsReq.TLS = &tls.ConnectionState{}
	if !p.IsTLS(tlsReq) {
		t.Error("direct TLS")
	}
	if _, err := NewProxies([]string{"not-a-cidr"}, false); err == nil {
		t.Error("bad CIDR accepted")
	}
}

func TestCheckOriginAndCSRF(t *testing.T) {
	mk := func(site, origin string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://varde.lan/settings", nil)
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	for _, c := range []struct {
		site, origin string
		ok           bool
	}{
		{"", "", true},
		{"same-origin", "http://varde.lan", true},
		{"cross-site", "", false},
		{"same-site", "http://other.lan", false},
		{"", "http://evil.example", false},
		{"", "null", true}, // no fetch metadata: decided by the CSRF tokens
		// Browsers send Origin "null" on form posts under strict referrer
		// policies; fetch metadata decides then.
		{"same-origin", "null", true},
		{"cross-site", "http://varde.lan", false},
	} {
		if got := CheckOrigin(mk(c.site, c.origin)); got != c.ok {
			t.Errorf("site=%q origin=%q: %v", c.site, c.origin, got)
		}
	}
	cur := &Current{CSRFToken: "tok"}
	r := mk("", "")
	r.Header.Set(CSRFHeader, "tok")
	if !CheckCSRF(r, cur) {
		t.Error("valid header token rejected")
	}
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("csrf=tok"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !CheckCSRF(r, cur) {
		t.Error("valid form token rejected")
	}
	r = mk("", "")
	r.Header.Set(CSRFHeader, "other")
	if CheckCSRF(r, cur) || CheckCSRF(mk("", ""), cur) || CheckCSRF(r, nil) {
		t.Error("invalid token accepted")
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.CreateUser(ctx, store.User{ID: "u1", Username: "admin", PasswordHash: "x", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	p, _ := NewProxies(nil, false)
	s := NewSessions(st, CookieAuto, p)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	rec := httptest.NewRecorder()
	if err := s.Start(ctx, rec, httptest.NewRequest(http.MethodPost, "/login", nil), "u1"); err != nil {
		t.Fatal(err)
	}
	c := rec.Result().Cookies()[0]
	if c.Name != CookieName || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure {
		t.Fatalf("cookie %+v", c)
	}
	withCookie := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(c)
		return r
	}
	cur, err := s.Load(ctx, withCookie())
	if err != nil || cur == nil || cur.User.Username != "admin" || cur.CSRFToken == "" {
		t.Fatalf("load: %+v %v", cur, err)
	}
	// Idle timeout.
	now = now.Add(IdleTimeout + time.Minute)
	if cur, _ := s.Load(ctx, withCookie()); cur != nil {
		t.Fatal("idle session accepted")
	}
	// Forged cookie.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "forged"})
	if cur, _ := s.Load(ctx, r); cur != nil {
		t.Fatal("forged session accepted")
	}
	// Secure attribute follows TLS in auto mode, always in "always".
	tlsReq := httptest.NewRequest(http.MethodPost, "https://varde/login", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	if err := s.Start(ctx, rec, tlsReq, "u1"); err != nil {
		t.Fatal(err)
	}
	if !rec.Result().Cookies()[0].Secure {
		t.Error("cookie over TLS not Secure")
	}
	if !NewSessions(st, CookieAlways, p).Secure(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("always mode")
	}
}

// TestThrottleBeginIsAtomic: parallel attempts cannot all pass the check
// before the first failure is recorded.
func TestThrottleBeginIsAtomic(t *testing.T) {
	th := NewThrottle()
	var wg sync.WaitGroup
	var passed atomic.Int32
	for range 200 {
		wg.Go(func() {
			if ok, _ := th.Begin("admin", "10.0.0.1"); ok {
				passed.Add(1)
			}
		})
	}
	wg.Wait()
	if n := passed.Load(); n != 6 {
		t.Fatalf("%d parallel attempts passed, want 6 (5 free plus the one that starts the delay)", n)
	}
}

func TestThrottleSuccessRefundsIP(t *testing.T) {
	th := NewThrottle()
	for i := range 20 {
		user := fmt.Sprint("user", i)
		if ok, _ := th.Begin(user, "10.0.0.1"); !ok {
			t.Fatalf("successful logins throttled the IP at %d", i)
		}
		th.Success(user, "10.0.0.1")
	}
	for range 3 {
		th.Begin("x", "10.0.0.2")
		th.Refund("x", "10.0.0.2")
	}
	if ok, _ := th.Begin("x", "10.0.0.2"); !ok {
		t.Fatal("refunded attempts still counted")
	}
}

func TestHashingBusyIsBounded(t *testing.T) {
	old := hashWait
	hashWait = 50 * time.Millisecond
	defer func() { hashWait = old }()
	hashSlots <- struct{}{} // occupy the only slot
	defer func() { <-hashSlots }()
	start := time.Now()
	err := VerifyPassword(context.Background(), "correct horse battery", dummyHash)
	if !errors.Is(err, ErrBusy) || time.Since(start) > time.Second {
		t.Fatalf("busy: %v after %s", err, time.Since(start))
	}
}
