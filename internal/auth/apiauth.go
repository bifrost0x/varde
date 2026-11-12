// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/store"
)

// Token scopes.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

// TokenPrefix marks Varde API tokens so secret scanners can find leaks.
const TokenPrefix = "varde_"

// Principal is an authenticated API caller.
type Principal struct {
	Actor string
	Write bool
	// Session is set for cookie authentication; state-changing requests
	// then also need a valid CSRF token and a same-origin request.
	Session *Current
}

// TokenStore looks up API tokens.
type TokenStore interface {
	APITokenByHash(ctx context.Context, hash string) (store.APIToken, error)
	TouchAPIToken(ctx context.Context, id string, now time.Time) error
}

// APIAuth authenticates API requests by bearer token or session.
type APIAuth struct {
	Tokens   TokenStore
	Static   string // optional VARDE_API_TOKEN, write scope
	Sessions *Sessions
	Now      func() time.Time
}

// Authenticate returns the principal or false.
func (a *APIAuth) Authenticate(r *http.Request) (Principal, bool) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); h != "" {
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || tok == "" || len(tok) > 256 {
			return Principal{}, false
		}
		if a.Static != "" && EqualTokens(tok, a.Static) {
			return Principal{Actor: "static-token", Write: true}, true
		}
		t, err := a.Tokens.APITokenByHash(ctx, HashToken(tok))
		if err != nil {
			return Principal{}, false
		}
		now := time.Now()
		if a.Now != nil {
			now = a.Now()
		}
		if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
			return Principal{}, false
		}
		if t.LastUsed == nil || now.Sub(*t.LastUsed) > time.Minute {
			_ = a.Tokens.TouchAPIToken(ctx, t.ID, now)
		}
		return Principal{Actor: "token:" + t.Name, Write: t.Scope == ScopeWrite}, true
	}
	if a.Sessions == nil {
		return Principal{}, false
	}
	cur, err := a.Sessions.Load(ctx, r)
	if err != nil || cur == nil {
		return Principal{}, false
	}
	return Principal{Actor: cur.User.Username, Write: true, Session: cur}, true
}

// Authorize checks scope and, for sessions, CSRF on state-changing
// requests. It returns an HTTP status (0 when allowed).
func Authorize(r *http.Request, p Principal) int {
	if SafeMethod(r.Method) {
		return 0
	}
	if !p.Write {
		return http.StatusForbidden
	}
	if p.Session != nil && (!CheckOrigin(r) || !CheckCSRF(r, p.Session)) {
		return http.StatusForbidden
	}
	return 0
}
