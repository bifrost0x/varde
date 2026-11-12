// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/datapkg"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/uplink"
)

type settingsData struct {
	Values       map[string]string
	RegistryTags bool
	// ContainerPackages mirrors the setting of the same name.
	ContainerPackages bool
	// EOLData mirrors the setting of the same name.
	EOLData       bool
	ScanPeriods   []scanPeriod
	Locked        map[string]bool
	Policy        policy.Thresholds
	DigestHour    int
	DigestWeekday string
	OSV, NVD      bool
	Channels      []string
	Tokens        []store.APIToken
	Users         []store.User
	Me            string
	Audit         []store.AuditEntry
	NewToken      string
	Error         string
	// Uplink is the state of the uplink switch.
	Uplink uplink.Status
	// Package is the state of the data package; Direct the switch that
	// lets Varde ask the public sources about apps it does not cover.
	Package datapkg.Status
	Direct  bool
}

func (a *app) settingsView(r *http.Request, cur *auth.Current, newToken, errMsg string) (view, error) {
	ctx := r.Context()
	eff := a.d.Settings.Get()
	d := settingsData{
		Values: map[string]string{
			settings.KeyPublicDomains:   strings.Join(eff.PublicDomains, ", "),
			settings.KeyInternalDomains: strings.Join(eff.InternalDomains, ", "),
			settings.KeyNetworks:        a.d.Settings.UIValue(settings.KeyNetworks),
			settings.KeyScanEvery:       scanEveryValue(a.d.Settings),
		},
		RegistryTags: eff.RegistryTags, ContainerPackages: eff.ContainerPackages, EOLData: eff.EOLData,
		ScanPeriods: scanPeriods, Locked: map[string]bool{}, Policy: eff.Policy, DigestHour: eff.DigestHour,
		DigestWeekday: strings.ToLower(eff.DigestWeekday.String()), OSV: eff.DirectOSV, NVD: eff.DirectNVD,
		Channels: a.d.Channels, Me: cur.User.ID, NewToken: newToken, Error: errMsg,
		Uplink: a.uplinkStatus(), Package: a.packageStatus(ctx), Direct: eff.DirectQueries,
	}
	for _, k := range settings.Keys {
		d.Locked[k] = a.d.Settings.Locked(k)
	}
	var err error
	if d.Tokens, err = a.d.Store.APITokens(ctx); err != nil {
		return view{}, err
	}
	if d.Users, err = a.d.Store.Users(ctx); err != nil {
		return view{}, err
	}
	if d.Audit, err = a.d.Store.AuditLog(ctx, 50); err != nil {
		return view{}, err
	}
	return view{Title: "Settings", Nav: "settings", Tabs: tabs("settings", "/settings"), Data: d}, nil
}

func (a *app) settingsPage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	a.renderSettings(w, r, cur, http.StatusOK, "", "")
}

func (a *app) renderSettings(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, newToken, errMsg string) {
	v, err := a.settingsView(r, cur, newToken, errMsg)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.page(w, r, cur, status, "settings", v)
}

func (a *app) saveSettings(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if err := r.ParseForm(); err != nil {
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "The form could not be read.")
		return
	}
	values := map[string]string{}
	for _, k := range settings.Keys {
		vs, ok := r.PostForm[k]
		if !ok || a.d.Settings.Locked(k) {
			continue
		}
		// Checkboxes post a hidden "false" followed by "true" when ticked.
		values[k] = strings.TrimSpace(vs[len(vs)-1])
	}
	if len(values) == 0 {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	nets, scopeChanged := values[settings.KeyNetworks]
	if scopeChanged {
		if err := checkScope(nets); err != nil {
			a.renderSettings(w, r, cur, http.StatusBadRequest, "", "Not saved: "+err.Error())
			return
		}
	}
	if err := a.d.Settings.Update(r.Context(), values, cur.User.Username, a.d.Now()); err != nil {
		msg := err.Error()
		if errors.Is(err, settings.ErrLocked) {
			msg = "A setting is fixed by an environment variable."
		}
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "Not saved: "+msg)
		return
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	a.audit(r, cur, "settings.update", "", strings.Join(keys, ", "))
	if scopeChanged {
		// The same audit entry as on the network page.
		a.audit(r, cur, "network.scope", "", nets)
	}
	a.d.Analyze(r.Context())
	if r.PostFormValue("return") == "network" {
		http.Redirect(w, r, "/connections?ok=saved#scan", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?ok=saved", http.StatusSeeOther)
}

func (a *app) createToken(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	scope := r.PostFormValue("scope")
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n\x00") || (scope != auth.ScopeRead && scope != auth.ScopeWrite) {
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "A token needs a name (up to 64 characters) and a scope.")
		return
	}
	now := a.d.Now()
	t := store.APIToken{Name: name, Scope: scope, CreatedBy: cur.User.Username, CreatedAt: now}
	if v := strings.TrimSpace(r.PostFormValue("days")); v != "" {
		days, err := strconv.Atoi(v)
		if err != nil || days < 1 || days > 3650 {
			a.renderSettings(w, r, cur, http.StatusBadRequest, "", "Expiry must be 1 to 3650 days.")
			return
		}
		exp := now.Add(time.Duration(days) * 24 * time.Hour)
		t.ExpiresAt = &exp
	}
	secret, err := auth.RandomToken(32)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	raw := auth.TokenPrefix + secret
	if t.ID, err = auth.RandomToken(12); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	t.TokenHash = auth.HashToken(raw)
	if err := a.d.Store.CreateAPIToken(r.Context(), t); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "token.create", t.ID, name+" ("+scope+")")
	// Rendered directly (not redirected) so the secret never appears in a URL
	// or history entry.
	a.renderSettings(w, r, cur, http.StatusOK, raw, "")
}

func (a *app) deleteToken(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	id := r.PathValue("id")
	if err := a.d.Store.DeleteAPIToken(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "token.delete", id, "")
	http.Redirect(w, r, "/settings?ok=token-revoked#tokens", http.StatusSeeOther)
}

func (a *app) createUser(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	username := strings.TrimSpace(r.PostFormValue("username"))
	if msg := validUsername(username); msg != "" {
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", msg)
		return
	}
	hash, err := auth.HashPassword(ctx, r.PostFormValue("password"))
	if err != nil {
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "The password must have at least 12 characters.")
		return
	}
	id, err := auth.RandomToken(16)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	err = a.d.Store.CreateUser(ctx, store.User{ID: id, Username: username, PasswordHash: hash, CreatedAt: a.d.Now()})
	if errors.Is(err, store.ErrConflict) {
		a.renderSettings(w, r, cur, http.StatusConflict, "", "This username is taken.")
		return
	}
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "user.create", username, "")
	http.Redirect(w, r, "/settings?ok=user-added#users", http.StatusSeeOther)
}

func (a *app) deleteUser(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	id := r.PathValue("id")
	if id == cur.User.ID {
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "You cannot delete your own account.")
		return
	}
	u, _ := a.d.Store.UserByID(r.Context(), id)
	err := a.d.Store.DeleteUser(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Redirect(w, r, "/settings#users", http.StatusSeeOther)
		return
	case errors.Is(err, store.ErrInvalidState):
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "The last account cannot be deleted.")
		return
	case err != nil:
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "user.delete", u.Username, "")
	http.Redirect(w, r, "/settings?ok=user-deleted#users", http.StatusSeeOther)
}

func (a *app) changePassword(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	ip := a.d.Proxies.ClientIP(r)
	if ok, _ := a.d.Throttle.Begin(cur.User.Username, ip); !ok {
		a.renderSettings(w, r, cur, http.StatusTooManyRequests, "", "Too many failed attempts. Try again later.")
		return
	}
	err := auth.VerifyPassword(ctx, r.PostFormValue("current"), cur.User.PasswordHash)
	if errors.Is(err, auth.ErrBusy) {
		a.d.Throttle.Refund(cur.User.Username, ip)
		a.renderSettings(w, r, cur, http.StatusServiceUnavailable, "", "The server is busy. Try again in a few seconds.")
		return
	}
	if err != nil {
		a.audit(r, cur, "password.change.failed", cur.User.Username, "")
		a.renderSettings(w, r, cur, http.StatusForbidden, "", "The current password is wrong.")
		return
	}
	a.d.Throttle.Success(cur.User.Username, ip)
	hash, err := auth.HashPassword(ctx, r.PostFormValue("password"))
	if err != nil {
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "The new password must have at least 12 characters.")
		return
	}
	// Ends every session of the user, then starts a fresh one here.
	if err := a.d.Store.SetPassword(ctx, cur.User.ID, hash); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	if err := a.d.Sessions.Start(ctx, w, r, cur.User.ID); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "password.change", cur.User.Username, "")
	http.Redirect(w, r, "/settings?ok=password", http.StatusSeeOther)
}

func (a *app) testNotification(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if a.d.Notifier == nil {
		http.Redirect(w, r, "/settings#notifications", http.StatusSeeOther)
		return
	}
	a.audit(r, cur, "notification.test", "", "")
	if err := a.d.Notifier.Test(r.Context(), ""); err != nil {
		a.d.Log.Warn("test notification failed", "err", err)
		http.Redirect(w, r, "/settings?ok=test-failed#notifications", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?ok=test-sent#notifications", http.StatusSeeOther)
}
