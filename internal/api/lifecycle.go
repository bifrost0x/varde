// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/store"
)

// decodeJSON decodes a small JSON body strictly. An empty body is allowed
// when optional is true.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, optional bool) bool {
	if r.ContentLength == 0 && optional {
		return true
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain a single JSON object")
		return false
	}
	return true
}

func (a *api) audit(r *http.Request, action, target, detail string) {
	if err := a.store.Audit(r.Context(), store.AuditEntry{At: a.now(), Actor: actorOf(r), Action: action, Target: target, Detail: detail}); err != nil {
		a.log.Error("audit log write failed", "action", action, "err", err)
	}
}

// transitionResult maps store errors of state changes to HTTP responses.
func (a *api) transitionResult(w http.ResponseWriter, r *http.Request, err error, action, id, detail string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "finding not found")
		return
	case errors.Is(err, store.ErrInvalidState):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		a.internalError(w, r, err)
		return
	}
	a.audit(r, action, id, detail)
	a.changed(r.Context())
	f, err := a.store.GetFinding(r.Context(), id)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (a *api) ackFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.transitionResult(w, r, a.store.Acknowledge(r.Context(), id, a.now()), "finding.acknowledge", id, "")
}

func (a *api) reopenFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.transitionResult(w, r, a.store.Reopen(r.Context(), id, a.now()), "finding.reopen", id, "")
}

func (a *api) snoozeFinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Days  int        `json:"days"`
		Until *time.Time `json:"until"`
	}
	if !decodeJSON(w, r, &req, false) {
		return
	}
	now := a.now()
	var until time.Time
	switch {
	case req.Until != nil && req.Days != 0:
		writeError(w, http.StatusBadRequest, "set either days or until")
		return
	case req.Until != nil:
		until = *req.Until
	case req.Days >= 1 && req.Days <= 365:
		until = now.Add(time.Duration(req.Days) * 24 * time.Hour)
	default:
		writeError(w, http.StatusBadRequest, "days must be between 1 and 365, or set until")
		return
	}
	if until.After(now.Add(366 * 24 * time.Hour)) {
		writeError(w, http.StatusBadRequest, "snooze for at most a year")
		return
	}
	id := r.PathValue("id")
	a.transitionResult(w, r, a.store.Snooze(r.Context(), id, until, now), "finding.snooze", id, "until "+until.UTC().Format(time.RFC3339))
}

func (a *api) suppressFinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason    string     `json:"reason"`
		Scope     string     `json:"scope"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !decodeJSON(w, r, &req, false) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if !plainText(req.Reason, 512) {
		writeError(w, http.StatusBadRequest, "reason is required (1-512 printable characters)")
		return
	}
	now := a.now()
	if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
		writeError(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}
	f, err := a.store.GetFinding(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	sup := store.Suppression{AppID: f.AppID, AdvisoryID: f.AdvisoryID, Reason: req.Reason, CreatedBy: actorOf(r), CreatedAt: now, ExpiresAt: req.ExpiresAt}
	switch req.Scope {
	case "workload", "":
		sup.WorkloadID = f.WorkloadID
	case "app":
	default:
		writeError(w, http.StatusBadRequest, "scope must be workload or app")
		return
	}
	if sup.ID, err = randomID(); err != nil {
		a.internalError(w, r, err)
		return
	}
	if err := a.store.AddSuppression(r.Context(), sup); err != nil {
		a.internalError(w, r, err)
		return
	}
	scope := "app " + sup.AppID
	if sup.WorkloadID != "" {
		scope = "workload " + sup.WorkloadID
	}
	a.audit(r, "suppression.create", sup.ID, fmt.Sprintf("%s for %s: %s", sup.AdvisoryID, scope, sup.Reason))
	a.changed(r.Context())
	writeJSON(w, http.StatusCreated, sup)
}

func (a *api) listSuppressions(w http.ResponseWriter, r *http.Request) {
	sups, err := a.store.Suppressions(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"suppressions": sups})
}

// listPaths returns the attack paths of the last analysis, most dangerous
// first (ADR 0034). Findings carry their place in path_class and
// path_reason.
func (a *api) listPaths(w http.ResponseWriter, r *http.Request) {
	ps, err := a.store.Paths(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": ps})
}

func (a *api) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sup, err := a.store.DeleteSuppression(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "suppression not found")
		return
	}
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.audit(r, "suppression.delete", id, sup.AdvisoryID)
	a.changed(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) testNotification(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Channel string `json:"channel"`
	}
	if !decodeJSON(w, r, &req, true) {
		return
	}
	if a.notifier == nil {
		writeError(w, http.StatusConflict, "no notification channel configured")
		return
	}
	a.audit(r, "notification.test", req.Channel, "")
	if err := a.notifier.Test(r.Context(), req.Channel); err != nil {
		// Delivery errors are operator-facing and contain no secrets
		// (tokens are sent in headers, never in URLs).
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "delivery failed", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (a *api) listNotifications(w http.ResponseWriter, r *http.Request) {
	entries, err := a.store.Notifications(r.Context(), 200)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notifications": entries})
}

func (a *api) listAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := a.store.AuditLog(r.Context(), 500)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}
