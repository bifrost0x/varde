// SPDX-License-Identifier: Apache-2.0

// Package api serves the JSON REST API under /api/v1/.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/store"
)

// Prefix is the mount point of the API.
const Prefix = "/api/v1/"

// maxBodyBytes caps request bodies; API payloads are small.
const maxBodyBytes = 16 << 10

// Store is the persistence the API needs.
type Store interface {
	Hosts(ctx context.Context) ([]inventory.Host, error)
	Host(ctx context.Context, id string) (inventory.Host, error)
	UpsertHost(ctx context.Context, h inventory.Host) error
	Workloads(ctx context.Context, f store.WorkloadFilter) ([]inventory.Workload, error)
	Workload(ctx context.Context, id string) (inventory.Workload, error)
	AddManual(ctx context.Context, w inventory.Workload, now time.Time) (inventory.Workload, error)
	RemoveWorkload(ctx context.Context, id string, kind inventory.Kind, now time.Time) error
	Identifications(ctx context.Context) (map[string]identify.Result, error)
	Findings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	GetFinding(ctx context.Context, id string) (store.Finding, error)
	SourceStates(ctx context.Context) ([]store.SourceState, error)
	Acknowledge(ctx context.Context, id string, now time.Time) error
	Snooze(ctx context.Context, id string, until, now time.Time) error
	Reopen(ctx context.Context, id string, now time.Time) error
	AddSuppression(ctx context.Context, sup store.Suppression) error
	DeleteSuppression(ctx context.Context, id string) (store.Suppression, error)
	Suppressions(ctx context.Context) ([]store.Suppression, error)
	Notifications(ctx context.Context, limit int) ([]store.NotificationEntry, error)
	Audit(ctx context.Context, e store.AuditEntry) error
	AuditLog(ctx context.Context, limit int) ([]store.AuditEntry, error)
	Devices(ctx context.Context) ([]store.StoredDevice, error)
	Integrations(ctx context.Context) ([]store.Integration, error)
	LastScanRun(ctx context.Context) (store.ScanRun, error)
	AssetIDs(ctx context.Context) (map[string]string, error)
	Paths(ctx context.Context) ([]paths.Path, error)
}

// Notifier sends test notifications.
type Notifier interface {
	Test(ctx context.Context, channel string) error
}

// Options configures the API handler.
type Options struct {
	Store Store
	// Authenticate identifies the caller (tokens, sessions). When nil, the
	// static Token is the only credential.
	Authenticate func(r *http.Request) (auth.Principal, bool)
	// Token is a static bearer token with write scope (VARDE_API_TOKEN).
	Token string
	Log   *slog.Logger
	Now   func() time.Time
	// Changed, if set, is called after the API changed the inventory.
	Changed func(ctx context.Context)
	// Notifier, if set, enables test notifications.
	Notifier Notifier
	// Status, if set, serves GET /status.
	Status func(ctx context.Context) (any, error)
	// Scan, if set, serves POST /scan (starts inventory and advisory checks).
	Scan func()
	// Scope returns the networks Varde may contact; devices outside are not
	// listed, and only addresses inside merge hosts. Nil means none.
	Scope func() discovery.Scope
	// Interval is how often an integration kind reads (for its health);
	// nil means unknown.
	Interval func(kind string) time.Duration
}

type api struct {
	store        Store
	authenticate func(r *http.Request) (auth.Principal, bool)
	log          *slog.Logger
	now          func() time.Time
	changed      func(ctx context.Context)
	notifier     Notifier
	status       func(ctx context.Context) (any, error)
	scan         func()
	scopeFn      func() discovery.Scope
	intervalFn   func(kind string) time.Duration
}

func (a *api) scope() discovery.Scope {
	if a.scopeFn == nil {
		return discovery.Scope{}
	}
	return a.scopeFn()
}

func (a *api) interval(kind string) time.Duration {
	if a.intervalFn == nil {
		return 0
	}
	return a.intervalFn(kind)
}

// workloadView is a workload with its identification, as served by the API.
type workloadView struct {
	inventory.Workload
	Identification *identify.Result `json:"identification,omitempty"`
}

// Route is one API endpoint; the list is the source for the OpenAPI sync
// test.
type Route struct {
	Method string
	Path   string // relative to Prefix, OpenAPI style ({id})
}

func (a *api) routes() []struct {
	Route
	h http.HandlerFunc
} {
	return []struct {
		Route
		h http.HandlerFunc
	}{
		{Route{"GET", "status"}, a.getStatus},
		{Route{"POST", "scan"}, a.postScan},
		{Route{"GET", "hosts"}, a.listHosts},
		{Route{"GET", "devices"}, a.listDevices},
		{Route{"GET", "integrations"}, a.listIntegrations},
		{Route{"GET", "workloads"}, a.listWorkloads},
		{Route{"POST", "workloads"}, a.createManual},
		{Route{"GET", "workloads/{id}"}, a.getWorkload},
		{Route{"DELETE", "workloads/{id}"}, a.deleteManual},
		{Route{"GET", "findings"}, a.listFindings},
		{Route{"GET", "findings/{id}"}, a.getFinding},
		{Route{"POST", "findings/{id}/ack"}, a.ackFinding},
		{Route{"POST", "findings/{id}/reopen"}, a.reopenFinding},
		{Route{"POST", "findings/{id}/snooze"}, a.snoozeFinding},
		{Route{"POST", "findings/{id}/suppress"}, a.suppressFinding},
		{Route{"GET", "suppressions"}, a.listSuppressions},
		{Route{"GET", "paths"}, a.listPaths},
		{Route{"GET", "vex"}, a.vex},
		{Route{"DELETE", "suppressions/{id}"}, a.deleteSuppression},
		{Route{"GET", "sources"}, a.listSources},
		{Route{"POST", "notifications/test"}, a.testNotification},
		{Route{"GET", "notifications"}, a.listNotifications},
		{Route{"GET", "audit"}, a.listAudit},
	}
}

// Routes lists every endpoint.
func Routes() []Route {
	var out []Route
	for _, r := range (&api{}).routes() {
		out = append(out, r.Route)
	}
	return out
}

// New returns the API handler, to be mounted at Prefix.
func New(o Options) http.Handler {
	a := &api{store: o.Store, log: o.Log, now: o.Now, changed: o.Changed, notifier: o.Notifier,
		authenticate: o.Authenticate, status: o.Status, scan: o.Scan, scopeFn: o.Scope, intervalFn: o.Interval}
	if a.now == nil {
		a.now = time.Now
	}
	if a.changed == nil {
		a.changed = func(context.Context) {}
	}
	if a.authenticate == nil {
		static := o.Token
		a.authenticate = func(r *http.Request) (auth.Principal, bool) {
			tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if static == "" || !ok || !auth.EqualTokens(tok, static) {
				return auth.Principal{}, false
			}
			return auth.Principal{Actor: "static-token", Write: true}, true
		}
	}

	mux := http.NewServeMux()
	for _, rt := range a.routes() {
		mux.HandleFunc(rt.Method+" "+Prefix+rt.Path, rt.h)
	}
	return a.guard(mux)
}

type principalKey struct{}

// guard authenticates every request and enforces scope and CSRF.
func (a *api) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// Before authorisation: the CSRF check of session requests may
		// read a form body.
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		p, ok := a.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="varde"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if status := auth.Authorize(r, p); status != 0 {
			writeError(w, status, "forbidden: read-only token or missing CSRF token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

func actorOf(r *http.Request) string {
	if p, ok := r.Context().Value(principalKey{}).(auth.Principal); ok {
		return p.Actor
	}
	return "unknown"
}

func (a *api) getStatus(w http.ResponseWriter, r *http.Request) {
	if a.status == nil {
		writeError(w, http.StatusNotFound, "not available")
		return
	}
	st, err := a.status(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *api) postScan(w http.ResponseWriter, r *http.Request) {
	if a.scan == nil {
		writeError(w, http.StatusNotFound, "not available")
		return
	}
	a.scan()
	a.audit(r, "scan.trigger", "", "")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

func (a *api) listHosts(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("view") {
	case "", "records":
	case "merged":
		a.listMergedHosts(w, r)
		return
	default:
		writeError(w, http.StatusBadRequest, "view must be records or merged")
		return
	}
	hosts, err := a.store.Hosts(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	if hosts == nil {
		hosts = []inventory.Host{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

func (a *api) listWorkloads(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.WorkloadFilter{HostID: q.Get("host_id"), Kind: inventory.Kind(q.Get("kind"))}
	switch q.Get("include_removed") {
	case "", "false":
	case "true":
		f.IncludeRemoved = true
	default:
		writeError(w, http.StatusBadRequest, "include_removed must be true or false")
		return
	}
	if f.Kind != "" && !validKind(f.Kind) {
		writeError(w, http.StatusBadRequest, "unknown kind")
		return
	}
	ws, err := a.store.Workloads(r.Context(), f)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	ids, err := a.store.Identifications(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	views := make([]workloadView, 0, len(ws))
	for _, wl := range ws {
		views = append(views, view(wl, ids))
	}
	writeJSON(w, http.StatusOK, map[string]any{"workloads": views})
}

func (a *api) getWorkload(w http.ResponseWriter, r *http.Request) {
	wl, err := a.store.Workload(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "workload not found")
		return
	}
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	ids, err := a.store.Identifications(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view(wl, ids))
}

func view(wl inventory.Workload, ids map[string]identify.Result) workloadView {
	v := workloadView{Workload: wl}
	if id, ok := ids[wl.ID]; ok {
		v.Identification = &id
	}
	return v
}

func (a *api) deleteManual(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	wl, err := a.store.Workload(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "workload not found")
		return
	case err != nil:
		a.internalError(w, r, err)
		return
	case wl.Kind != inventory.KindManual:
		writeError(w, http.StatusConflict, "only manual workloads can be deleted; observed workloads disappear when they stop existing")
		return
	}
	err = a.store.RemoveWorkload(r.Context(), id, inventory.KindManual, a.now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "workload not found")
		return
	}
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.changed(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) internalError(w http.ResponseWriter, r *http.Request, err error) {
	a.log.Error("api request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func validKind(k inventory.Kind) bool {
	switch k {
	case inventory.KindContainer, inventory.KindPackage, inventory.KindService, inventory.KindManual, inventory.KindEndpoint:
		return true
	}
	return false
}
