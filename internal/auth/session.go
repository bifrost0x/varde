// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/store"
)

// CookieName is the session cookie.
const CookieName = "varde_session"

// FormCookieName holds the token that protects the login and setup forms,
// which are posted before a session exists.
const FormCookieName = "varde_form"

// Session lifetimes.
const (
	IdleTimeout     = 24 * time.Hour
	AbsoluteTimeout = 7 * 24 * time.Hour
	touchInterval   = time.Minute
)

// Store is the persistence sessions need.
type Store interface {
	CreateSession(ctx context.Context, s store.Session, userAgent, ip string) error
	SessionByHash(ctx context.Context, idHash string) (store.Session, error)
	TouchSession(ctx context.Context, idHash string, now time.Time) error
	DeleteSession(ctx context.Context, idHash string) error
	UserByID(ctx context.Context, id string) (store.User, error)
}

// CookieMode decides the Secure attribute.
type CookieMode string

// Cookie modes.
const (
	CookieAuto   CookieMode = "auto"   // Secure when the request arrived over TLS
	CookieAlways CookieMode = "always" // always Secure
	CookieNever  CookieMode = "never"  // plain-HTTP LAN use; the UI warns
)

// Sessions manages server-side sessions.
type Sessions struct {
	store   Store
	mode    CookieMode
	proxies *Proxies
	now     func() time.Time
}

// NewSessions returns a session manager.
func NewSessions(st Store, mode CookieMode, proxies *Proxies) *Sessions {
	return &Sessions{store: st, mode: mode, proxies: proxies, now: time.Now}
}

// Current is the authenticated session of a request.
type Current struct {
	User      store.User
	IDHash    string
	CSRFToken string
}

// Start creates a new session (a fresh ID on every login prevents fixation)
// and sets the cookie.
func (s *Sessions) Start(ctx context.Context, w http.ResponseWriter, r *http.Request, userID string) error {
	raw, err := RandomToken(32)
	if err != nil {
		return err
	}
	csrf, err := RandomToken(32)
	if err != nil {
		return err
	}
	now := s.now()
	sess := store.Session{IDHash: HashToken(raw), UserID: userID, CSRFToken: csrf, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(AbsoluteTimeout)}
	if err := s.store.CreateSession(ctx, sess, r.UserAgent(), s.proxies.ClientIP(r)); err != nil {
		return err
	}
	http.SetCookie(w, s.cookie(r, raw, int(AbsoluteTimeout.Seconds())))
	return nil
}

// Load returns the request's session or nil. Expired sessions are deleted.
func (s *Sessions) Load(ctx context.Context, r *http.Request) (*Current, error) {
	c, err := r.Cookie(CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if c.Value == "" || len(c.Value) > 128 {
		return nil, nil
	}
	hash := HashToken(c.Value)
	sess, err := s.store.SessionByHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeen) > IdleTimeout {
		_ = s.store.DeleteSession(ctx, hash)
		return nil, nil
	}
	u, err := s.store.UserByID(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if now.Sub(sess.LastSeen) > touchInterval {
		if err := s.store.TouchSession(ctx, hash, now); err != nil {
			return nil, err
		}
	}
	return &Current{User: u, IDHash: hash, CSRFToken: sess.CSRFToken}, nil
}

// End deletes the session and clears the cookie.
func (s *Sessions) End(ctx context.Context, w http.ResponseWriter, r *http.Request, cur *Current) error {
	if cur != nil {
		if err := s.store.DeleteSession(ctx, cur.IDHash); err != nil {
			return err
		}
	}
	http.SetCookie(w, s.cookie(r, "", -1))
	return nil
}

func (s *Sessions) cookie(r *http.Request, value string, maxAge int) *http.Cookie {
	// Secure depends on VARDE_COOKIE_SECURE (auto, always, never); HttpOnly
	// and SameSite=Strict are fixed.
	return &http.Cookie{ //nolint:gosec // Secure is set per request, see Secure
		Name: CookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.Secure(r),
	}
}

// UntrustedTLSProxy is Proxies.UntrustedTLSProxy, empty when the cookie
// mode decides on its own.
func (s *Sessions) UntrustedTLSProxy(r *http.Request) string {
	if s.mode != CookieAuto || s.proxies == nil {
		return ""
	}
	return s.proxies.UntrustedTLSProxy(r)
}

// Secure reports whether the cookie gets the Secure attribute.
func (s *Sessions) Secure(r *http.Request) bool {
	switch s.mode {
	case CookieAlways:
		return true
	case CookieNever:
		return false
	}
	return s.proxies.IsTLS(r)
}

// Proxies knows which peers may set X-Forwarded-* headers.
type Proxies struct {
	trusted []netip.Prefix
	// behindTLS marks a deployment behind a TLS-terminating proxy.
	behindTLS bool
}

// NewProxies parses CIDRs (or single addresses).
func NewProxies(cidrs []string, behindTLS bool) (*Proxies, error) {
	p := &Proxies{behindTLS: behindTLS}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			a, err := netip.ParseAddr(c)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", c, err)
			}
			c = netip.PrefixFrom(a, a.BitLen()).String()
		}
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", c, err)
		}
		p.trusted = append(p.trusted, pfx.Masked())
	}
	return p, nil
}

func (p *Proxies) peerTrusted(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, t := range p.trusted {
		if t.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the client address: the peer, or the right-most
// untrusted entry of X-Forwarded-For when the peer is a trusted proxy.
func (p *Proxies) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !p.peerTrusted(r) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		a, err := netip.ParseAddr(ip)
		if err != nil {
			break
		}
		trusted := false
		for _, t := range p.trusted {
			trusted = trusted || t.Contains(a.Unmap())
		}
		if !trusted {
			return ip
		}
	}
	return host
}

// UntrustedTLSProxy returns the peer address when a request says it came
// over HTTPS (X-Forwarded-Proto) from a peer that is not a trusted proxy.
// The header is still ignored, since anyone can send it; the address lets
// the UI tell the user which proxy to trust.
func (p *Proxies) UntrustedTLSProxy(r *http.Request) string {
	if p.IsTLS(r) || !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// IsTLS reports whether the client connection was encrypted.
func (p *Proxies) IsTLS(r *http.Request) bool {
	if r.TLS != nil || p.behindTLS {
		return true
	}
	return p.peerTrusted(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// FormToken returns the pre-session form token, setting the cookie when the
// request carries none. The same value goes into the form; FormTokenValid
// compares both. SameSite=Strict keeps the cookie off cross-site posts.
func (s *Sessions) FormToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(FormCookieName); err == nil && validFormToken(c.Value) {
		return c.Value, nil
	}
	tok, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set per request, see Secure
		Name: FormCookieName, Value: tok, Path: "/", MaxAge: int(IdleTimeout.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.Secure(r),
	})
	return tok, nil
}

// FormTokenValid reports whether the posted form token matches the cookie.
func FormTokenValid(r *http.Request) bool {
	c, err := r.Cookie(FormCookieName)
	if err != nil || !validFormToken(c.Value) {
		return false
	}
	got := r.PostFormValue(CSRFField)
	return got != "" && EqualTokens(got, c.Value)
}

func validFormToken(v string) bool {
	return len(v) >= 32 && len(v) <= 128
}
