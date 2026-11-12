// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/store"
)

type loginData struct {
	Error    string
	Username string
	Insecure bool
	// Proxy is an HTTPS proxy Varde does not trust yet.
	Proxy string
	// Next is the local page to return to after login.
	Next string
}

func (a *app) loginForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if n, err := a.d.Store.CountUsers(ctx); err == nil && n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if cur, _ := a.d.Sessions.Load(ctx, r); cur != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tok, ok := a.formToken(w, r)
	if !ok {
		return
	}
	a.r.render(w, http.StatusOK, "login", view{Title: "Sign in", CSRF: tok, Data: loginData{
		Insecure: !a.d.Sessions.Secure(r), Proxy: a.d.Sessions.UntrustedTLSProxy(r), Next: nextOf(r),
	}})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if !a.sameOrigin(w, r) {
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	ip := a.d.Proxies.ClientIP(r)
	data := loginData{Username: username, Insecure: !a.d.Sessions.Secure(r), Proxy: a.d.Sessions.UntrustedTLSProxy(r), Next: nextOf(r)}

	if ok, wait := a.d.Throttle.Begin(username, ip); !ok {
		data.Error = fmt.Sprintf("Too many failed attempts. Try again in %s.", wait.Round(time.Second))
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		a.r.render(w, http.StatusTooManyRequests, "login", view{Title: "Sign in", CSRF: r.PostFormValue("csrf"), Data: data})
		return
	}
	u, err := a.d.Store.UserByName(ctx, username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		auth.VerifyDummy(ctx, password) // equal timing for unknown users
	case err != nil:
		a.d.Log.Error("login lookup failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	default:
		err = auth.VerifyPassword(ctx, password, u.PasswordHash)
	}
	if errors.Is(err, auth.ErrBusy) {
		a.d.Throttle.Refund(username, ip)
		w.Header().Set("Retry-After", "5")
		data.Error = "The server is busy. Try again in a few seconds."
		a.r.render(w, http.StatusServiceUnavailable, "login", view{Title: "Sign in", CSRF: r.PostFormValue("csrf"), Data: data})
		return
	}
	if err != nil {
		// The attempt was already counted by Begin.
		a.auditAs(r, "anonymous", "login.failed", truncate(username, 64), "from "+ip)
		data.Error = "Invalid username or password."
		a.r.render(w, http.StatusUnauthorized, "login", view{Title: "Sign in", CSRF: r.PostFormValue("csrf"), Data: data})
		return
	}
	a.d.Throttle.Success(username, ip)
	if err := a.d.Sessions.Start(ctx, w, r, u.ID); err != nil {
		a.d.Log.Error("session start failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = a.d.Store.RecordLogin(ctx, u.ID, a.d.Now())
	a.auditAs(r, u.Username, "login", u.Username, "from "+ip)
	http.Redirect(w, r, nextOf(r), http.StatusSeeOther) //nolint:gosec // safeNext allows local paths only
}

// safeNext allows only local paths, never another host.
// safeNext allows only a local path. Control characters are rejected
// outright: browsers drop tabs and newlines, so "/\t/evil" would become
// "//evil".
func safeNext(next string) string {
	if len(next) > 2048 {
		return "/"
	}
	for i := 0; i < len(next); i++ {
		if next[i] < 0x20 || next[i] == 0x7f {
			return "/"
		}
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return next
}

func (a *app) logout(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if err := a.d.Sessions.End(r.Context(), w, r, cur); err != nil {
		a.d.Log.Error("session end failed", "err", err)
	}
	a.audit(r, cur, "logout", cur.User.Username, "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *app) auditAs(r *http.Request, actor, action, target, detail string) {
	if err := a.d.Store.Audit(r.Context(), store.AuditEntry{At: a.d.Now(), Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		a.d.Log.Error("audit log write failed", "action", action, "err", err)
	}
}

type setupData struct {
	Error    string
	Username string
	Insecure bool
	// Proxy is an HTTPS proxy Varde does not trust yet.
	Proxy string
	// Container names Varde's container in the commands that print the
	// token: its ID, which docker accepts, or a placeholder.
	Container string
}

func (a *app) setupForm(w http.ResponseWriter, r *http.Request) {
	if n, err := a.d.Store.CountUsers(r.Context()); err != nil || n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	tok, ok := a.formToken(w, r)
	if !ok {
		return
	}
	a.r.render(w, http.StatusOK, "setup", view{Title: "Set up", CSRF: tok, Data: setupData{Insecure: !a.d.Sessions.Secure(r), Proxy: a.d.Sessions.UntrustedTLSProxy(r), Container: containerName()}})
}

func (a *app) setup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if !a.sameOrigin(w, r) {
		return
	}
	if n, err := a.d.Store.CountUsers(ctx); err != nil || n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip := a.d.Proxies.ClientIP(r)
	data := setupData{Username: strings.TrimSpace(r.PostFormValue("username")), Insecure: !a.d.Sessions.Secure(r), Proxy: a.d.Sessions.UntrustedTLSProxy(r),
		Container: containerName()}
	fail := func(status int, msg string) {
		data.Error = msg
		a.r.render(w, status, "setup", view{Title: "Set up", CSRF: r.PostFormValue("csrf"), Data: data})
	}
	if msg := validUsername(data.Username); msg != "" {
		fail(http.StatusBadRequest, msg)
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		fail(http.StatusBadRequest, "The passwords do not match.")
		return
	}
	if auth.ValidatePassword(pw) != nil {
		fail(http.StatusBadRequest, "The password must have at least 12 characters.")
		return
	}
	if ok, wait := a.d.Throttle.Begin("setup", ip); !ok {
		fail(http.StatusTooManyRequests, fmt.Sprintf("Too many attempts. Try again in %s.", wait.Round(time.Second)))
		return
	}
	hash, err := auth.HashPassword(ctx, pw)
	if err != nil {
		a.d.Throttle.Refund("setup", ip)
		fail(http.StatusServiceUnavailable, "The server is busy. Try again in a few seconds.")
		return
	}
	id, err := auth.RandomToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := a.d.Now()
	err = a.d.Store.CreateFirstUser(ctx, store.User{ID: id, Username: data.Username, PasswordHash: hash, CreatedAt: now},
		auth.HashToken(strings.TrimSpace(r.PostFormValue("token"))), now)
	if errors.Is(err, store.ErrConflict) {
		a.auditAs(r, "anonymous", "setup.failed", "", "invalid setup token from "+ip)
		fail(http.StatusForbidden, "The setup token is invalid, expired or already used.")
		return
	}
	if err != nil {
		a.d.Log.Error("setup failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.d.Sessions.Start(ctx, w, r, id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.d.Throttle.Success("setup", ip)
	a.auditAs(r, data.Username, "setup.complete", data.Username, "from "+ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// validUsername returns a user-facing message, or "" when valid.
func validUsername(u string) string {
	if u == "" || len(u) > 64 {
		return "The username must have 1 to 64 characters."
	}
	for _, c := range u {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '.' && c != '_' && c != '-' && c != '@' {
			return "The username may contain letters, digits and . _ - @ only."
		}
	}
	return ""
}

// sameOrigin rejects cross-site form posts: the origin check plus the
// pre-session form token. It logs what was rejected, so
// that a misconfigured proxy or browser policy can be diagnosed.
func (a *app) sameOrigin(w http.ResponseWriter, r *http.Request) bool {
	if auth.CheckOrigin(r) && auth.FormTokenValid(r) {
		return true
	}
	a.d.Log.Warn("cross-site request blocked", "path", r.URL.Path, "host", r.Host,
		"origin", r.Header.Get("Origin"), "sec_fetch_site", r.Header.Get("Sec-Fetch-Site"),
		"form_token", auth.FormTokenValid(r))
	http.Error(w, "Request blocked. Reload the page and try again.", http.StatusForbidden)
	return false
}

func (a *app) formToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	tok, err := a.d.Sessions.FormToken(w, r)
	if err != nil {
		a.d.Log.Error("form token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return "", false
	}
	return tok, true
}

// nextOf is the sanitised return path of a login request: from the form
// field, or from the query of the login page.
func nextOf(r *http.Request) string {
	next := r.PostFormValue("next")
	if next == "" {
		next = r.URL.Query().Get("next")
	}
	return safeNext(next)
}

var containerID = regexp.MustCompile(`^[0-9a-f]{12}$`)

// containerName is the name docker accepts for Varde's own container: in a
// container the host name is the short container ID. Elsewhere it is a
// placeholder the user replaces.
func containerName() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		if h, err := os.Hostname(); err == nil && containerID.MatchString(h) {
			return h
		}
	}
	return "<varde-container>"
}
