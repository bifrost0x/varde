// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/api"
	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func (a *app) scan(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	a.d.Scan()
	a.audit(r, cur, "scan.trigger", "", "")
	http.Redirect(w, r, "/?ok=scan", http.StatusSeeOther)
}

func (a *app) findingAction(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	id := r.PathValue("id")
	now := a.d.Now()
	var err error
	var code, detail string
	switch r.PathValue("action") {
	case "ack":
		err, code = a.d.Store.Acknowledge(ctx, id, now), "ack"
	case "reopen":
		err, code = a.d.Store.Reopen(ctx, id, now), "reopened"
	case "snooze":
		days, convErr := strconv.Atoi(r.PostFormValue("days"))
		if convErr != nil || days < 1 || days > 365 {
			a.renderError(w, r, cur, http.StatusBadRequest, "Invalid snooze", "Snooze for 1 to 365 days.")
			return
		}
		until := now.Add(time.Duration(days) * 24 * time.Hour)
		err, code, detail = a.d.Store.Snooze(ctx, id, until, now), "snoozed", "until "+until.UTC().Format(time.RFC3339)
	case "suppress":
		err = a.suppress(r, cur, id, now)
		code = "suppressed"
	case "unsuppress":
		err, code = a.unsuppress(ctx, id, now), "unsuppressed"
	default:
		a.renderError(w, r, cur, http.StatusNotFound, "Not found", "Unknown action.")
		return
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		a.renderError(w, r, cur, http.StatusNotFound, "Finding not found", "It may have been resolved.")
		return
	case errors.Is(err, store.ErrInvalidState), errors.Is(err, errBadInput):
		a.renderError(w, r, cur, http.StatusBadRequest, "Not possible", strings.TrimPrefix(err.Error(), errBadInput.Error()+": "))
		return
	case err != nil:
		a.fail(w, r, cur, err)
		return
	}
	if code != "suppressed" {
		a.audit(r, cur, "finding."+r.PathValue("action"), id, detail)
	}
	a.d.Analyze(ctx)
	// Local path: the id is path-escaped and code is a fixed keyword.
	http.Redirect(w, r, "/findings/"+url.PathEscape(id)+"?ok="+code, http.StatusSeeOther) //nolint:gosec // local path only
}

var errBadInput = errors.New("bad input")

// unsuppress lifts the suppression a finding is under; every finding it
// covers (one workload or the app's) reopens.
func (a *app) unsuppress(ctx context.Context, id string, now time.Time) error {
	f, err := a.d.Store.GetFinding(ctx, id)
	if err != nil {
		return err
	}
	if f.State != store.StateSuppressed || f.SuppressionID == "" {
		return fmt.Errorf("%w: the finding is not suppressed", store.ErrInvalidState)
	}
	if _, err := a.d.Store.DeleteSuppression(ctx, f.SuppressionID); err != nil {
		return err
	}
	return a.d.Store.ApplySuppressions(ctx, now)
}

func (a *app) suppress(r *http.Request, cur *auth.Current, id string, now time.Time) error {
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if reason == "" || len(reason) > 512 || strings.ContainsAny(reason, "\r\n\x00") {
		return fmt.Errorf("%w: a reason of up to 512 characters is required", errBadInput)
	}
	f, err := a.d.Store.GetFinding(r.Context(), id)
	if err != nil {
		return err
	}
	sup := store.Suppression{AppID: f.AppID, AdvisoryID: f.AdvisoryID, Reason: reason, CreatedBy: cur.User.Username, CreatedAt: now}
	switch r.PostFormValue("scope") {
	case "app":
	case "workload", "":
		sup.WorkloadID = f.WorkloadID
	default:
		return fmt.Errorf("%w: unknown scope", errBadInput)
	}
	if v := strings.TrimSpace(r.PostFormValue("days")); v != "" {
		days, err := strconv.Atoi(v)
		if err != nil || days < 1 || days > 3650 {
			return fmt.Errorf("%w: expiry must be 1 to 3650 days", errBadInput)
		}
		exp := now.Add(time.Duration(days) * 24 * time.Hour)
		sup.ExpiresAt = &exp
	}
	if sup.ID, err = auth.RandomToken(12); err != nil {
		return err
	}
	if err := a.d.Store.AddSuppression(r.Context(), sup); err != nil {
		return err
	}
	scope := "app " + sup.AppID
	if sup.WorkloadID != "" {
		scope = "workload " + sup.WorkloadID
	}
	a.audit(r, cur, "suppression.create", sup.ID, sup.AdvisoryID+" for "+scope+": "+reason)
	return nil
}

func (a *app) addManual(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	req := api.ManualRequest{
		HostName: r.PostFormValue("host_name"), Name: r.PostFormValue("name"), AppID: r.PostFormValue("app_id"),
		Version: r.PostFormValue("version"), Exposure: r.PostFormValue("exposure"),
	}
	if _, ok := a.d.Catalog.Current().App(req.AppID); !ok {
		a.renderError(w, r, cur, http.StatusBadRequest, "Unknown app", "Choose an app from the catalog.")
		return
	}
	wl, err := api.CreateManual(r.Context(), a.d.Store, req, a.d.Now())
	if errors.Is(err, api.ErrInvalidRequest) {
		a.renderError(w, r, cur, http.StatusBadRequest, "Invalid entry", strings.TrimPrefix(err.Error(), api.ErrInvalidRequest.Error()+": "))
		return
	}
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "manual.create", wl.ID, req.AppID+" "+req.Version)
	a.d.Analyze(r.Context())
	http.Redirect(w, r, "/systems/apps?ok=manual-added", http.StatusSeeOther)
}

func (a *app) removeManual(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	id := r.PathValue("id")
	err := a.d.Store.RemoveWorkload(r.Context(), id, inventory.KindManual, a.d.Now())
	if errors.Is(err, store.ErrNotFound) {
		a.renderError(w, r, cur, http.StatusNotFound, "Not found", "Only manual entries can be removed.")
		return
	}
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "manual.delete", id, "")
	a.d.Analyze(r.Context())
	http.Redirect(w, r, "/systems/apps?ok=manual-gone", http.StatusSeeOther)
}

// markNotAnApp leaves an image repository out of the coverage gaps. Only
// repositories of workloads Varde has seen and cannot identify are accepted,
// so the form cannot be used to plant arbitrary rows.
func (a *app) markNotAnApp(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	repo := r.PostFormValue("repository")
	s, err := a.load(ctx, false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	known := false
	for _, wl := range s.workloads {
		if coverage.Repository(wl) == repo && !s.ids[wl.ID].Confidence.Notifiable() {
			known = true
			break
		}
	}
	if repo == "" || !known {
		a.renderError(w, r, cur, http.StatusBadRequest, "Not possible", "Only images of unidentified containers can be marked as not an app.")
		return
	}
	if err := a.d.Store.MarkNotAnApp(ctx, repo, cur.User.Username, a.d.Now()); err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "coverage.not-an-app", repo, "")
	a.d.Analyze(ctx)
	http.Redirect(w, r, "/systems/gaps?ok=not-an-app#not-apps", http.StatusSeeOther)
}

func (a *app) unmarkNotAnApp(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	repo := r.PostFormValue("repository")
	err := a.d.Store.UnmarkNotAnApp(ctx, repo)
	if errors.Is(err, store.ErrNotFound) {
		a.renderError(w, r, cur, http.StatusNotFound, "Not found", "This image is not marked.")
		return
	}
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "coverage.is-an-app", repo, "")
	a.d.Analyze(ctx)
	http.Redirect(w, r, "/systems/gaps?ok=is-an-app#unidentified", http.StatusSeeOther)
}

// setupCookie remembers that the user hid the setup reminder on the
// overview. It holds no data about the installation and is kept per
// browser: hiding is a matter of the person looking, not of Varde.
const setupCookie = "varde_setup"

// setupGuide hides or shows the setup reminder of the overview.
func (a *app) setupGuide(w http.ResponseWriter, r *http.Request, _ *auth.Current) {
	c := &http.Cookie{Name: setupCookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.d.Sessions.Secure(r)} //nolint:gosec // Secure follows the session cookie, see Sessions.Secure
	if r.PathValue("action") == "hide" {
		c.Value, c.MaxAge = "hidden", 365*24*3600
	} else {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, "/#get-started", http.StatusSeeOther)
}
