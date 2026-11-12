// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/bifrost0x/varde/internal/store"
)

func (a *api) listFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.FindingFilter{WorkloadID: q.Get("workload_id")}
	switch q.Get("include_resolved") {
	case "", "false":
	case "true":
		f.IncludeResolved = true
	default:
		writeError(w, http.StatusBadRequest, "include_resolved must be true or false")
		return
	}
	fs, err := a.store.Findings(r.Context(), f)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": fs})
}

func (a *api) getFinding(w http.ResponseWriter, r *http.Request) {
	f, err := a.store.GetFinding(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// sourceView is the public view of a source state. Errors are upstream
// messages (status codes, decode failures); they contain no secrets because
// tokens are never part of URLs or error texts.
type sourceView struct {
	Source      string     `json:"source"`
	Key         string     `json:"key"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	NextRun     *time.Time `json:"next_run,omitempty"`
}

func (a *api) listSources(w http.ResponseWriter, r *http.Request) {
	states, err := a.store.SourceStates(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	out := make([]sourceView, 0, len(states))
	for _, s := range states {
		out = append(out, sourceView{
			Source: s.Source, Key: s.Key, LastError: s.LastError,
			LastSuccess: optTime(s.LastSuccess), LastAttempt: optTime(s.LastAttempt), NextRun: optTime(s.NextRun),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": out})
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
