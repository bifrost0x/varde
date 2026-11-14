// SPDX-License-Identifier: Apache-2.0

// Package web serves the UI, mounts the JSON API and serves the health and
// metrics endpoints.
package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/api"
	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/fleet"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
)

const readyTimeout = 2 * time.Second

// ContentSecurityPolicy is strict: no inline scripts or styles, no external
// origins, no framing.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Deps wires the UI to the rest of the application.
type Deps struct {
	Store    *store.Store
	Catalog  *catalog.Live
	Settings *settings.Service
	Sessions *auth.Sessions
	Throttle *auth.Throttle
	Proxies  *auth.Proxies
	APIAuth  *auth.APIAuth
	// API is mounted at api.Prefix.
	API http.Handler
	// Ready reports readiness for /readyz; nil means always ready.
	Ready func(ctx context.Context) error
	// Analyze re-runs the analysis after user actions.
	Analyze func(ctx context.Context)
	// Scan triggers an inventory sync and an advisory refresh.
	Scan func()
	// Notifier sends test notifications; nil when no channel exists.
	Notifier api.Notifier
	Channels []string
	// LastScan returns the time of the last successful inventory sync.
	LastScan func() time.Time
	// CatchingUp reports that advisory data is still being fetched: no run
	// through the sources has finished yet, or one is under way. limited
	// is set when a source put requests off for later, failed when one
	// answered with an error. Nil when unknown.
	CatchingUp func() (catchingUp, limited, failed bool)
	// LocalDocker is set when the local Docker collector runs.
	LocalDocker bool
	// Mode is the advisory mode (direct, feed or hybrid); empty means direct.
	Mode string
	// Uplink is the switch between direct mode and the uplink feed; nil
	// when the installation has none.
	Uplink Uplink
	// Package is the data package; nil when the installation has none.
	Package Package
	// Advisories returns the stored advisories that count for an app in
	// the analysis (pipeline.Pipeline.Advisories); nil counts them as the
	// analysis does without a data package channel.
	Advisories func(app *catalog.App, recs []store.AdvisoryRecord) []match.Advisory

	AllowDirectSocket bool
	CookieNever       bool
	BehindTLS         bool
	GitHubToken       bool
	// AgentCAPin is the internal CA fingerprint for enrollment tokens; empty
	// when the agent listener is off.
	AgentCAPin      string
	AgentListenAddr string
	// HostAddresses are the configured addresses of the machine Varde
	// runs on (VARDE_HOST_ADDRESS).
	HostAddresses []string
	// AgentBinaries are the agent binaries for push installations; nil
	// when the server ships none.
	AgentBinaries *fleet.Binaries
	// Network runs network scans and agentless integrations; nil disables
	// the network page.
	Network *integrations.Manager

	Log *slog.Logger
	Now func() time.Time
}

type app struct {
	d Deps
	r *renderer
}

// New returns the complete handler.
func New(d Deps) (http.Handler, error) {
	r, err := newRenderer()
	if err != nil {
		return nil, err
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Analyze == nil {
		d.Analyze = func(context.Context) {}
	}
	if d.Scan == nil {
		d.Scan = func() {}
	}
	if d.Mode == "" {
		d.Mode = "direct"
	}
	if d.LastScan == nil {
		d.LastScan = func() time.Time { return time.Time{} }
	}
	a := &app{d: d, r: r}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", readyz(d.Log, d.Ready))
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler()))
	if d.API != nil {
		mux.Handle(api.Prefix, d.API)
	}
	mux.HandleFunc("GET /metrics", a.metrics)

	mux.HandleFunc("GET /login", a.loginForm)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("GET /setup", a.setupForm)
	mux.HandleFunc("POST /setup", a.setup)
	mux.Handle("POST /logout", a.user(a.logout))

	mux.Handle("GET /{$}", a.user(a.overview))
	mux.Handle("POST /scan", a.user(a.scan))
	mux.Handle("POST /setup-guide/{action}", a.user(a.setupGuide))
	mux.Handle("GET /findings", a.user(a.findings))
	mux.Handle("GET /findings/paths", a.user(a.attackPaths))
	mux.Handle("GET /findings/noise", a.user(a.noise))
	mux.Handle("GET /findings/history", a.user(a.history))
	mux.Handle("GET /findings/history.csv", a.user(a.historyCSV))
	mux.Handle("GET /findings/{id}", a.user(a.finding))
	mux.Handle("POST /findings/{id}/{action}", a.user(a.findingAction))
	// Systems: what runs where.
	mux.Handle("GET /systems", a.user(a.systems))
	mux.Handle("GET /systems/{id}", a.user(a.system))
	mux.Handle("GET /systems/apps", a.user(a.inventory))
	mux.Handle("POST /systems/apps/manual", a.user(a.addManual))
	mux.Handle("POST /systems/apps/{id}/delete", a.user(a.removeManual))
	mux.Handle("GET /apps/{id}", a.user(a.appPage))
	mux.Handle("GET /systems/gaps", a.user(a.coverage))
	mux.Handle("GET /systems/gaps/unrecognised.txt", a.user(a.unrecognised))
	mux.Handle("POST /systems/gaps/not-an-app", a.user(a.markNotAnApp))
	mux.Handle("POST /systems/gaps/not-an-app/delete", a.user(a.unmarkNotAnApp))
	// Connections: how Varde reads them.
	mux.Handle("GET /connections", a.user(a.network))
	mux.Handle("POST /connections/scope", a.user(a.saveScope))
	mux.Handle("POST /connections/scan", a.user(a.startScan))
	mux.Handle("GET /connections/connect/{kind}", a.user(a.connectForm))
	mux.Handle("POST /connections/connect/{kind}", a.user(a.connect))
	mux.Handle("POST /connections/integrations/{id}/{action}", a.user(a.integrationAction))
	mux.Handle("GET /connections/agents", a.user(a.agents))
	mux.Handle("GET /connections/agents/install", a.user(a.agentInstallForm))
	mux.Handle("POST /connections/agents/install", a.user(a.agentInstall))
	mux.Handle("POST /connections/agents/tokens", a.user(a.createEnrollment))
	mux.Handle("POST /connections/agents/tokens/{id}/delete", a.user(a.deleteEnrollment))
	mux.Handle("POST /connections/agents/{id}/revoke", a.user(a.revokeHost))
	mux.Handle("GET /settings", a.user(a.settingsPage))
	mux.Handle("GET /settings/sources", a.user(a.sources))
	// The pages before the areas: old links and open tabs keep working.
	for old, area := range movedPages {
		mux.Handle(old, moved(old, area))
		mux.Handle(old+"/", moved(old, area))
	}
	mux.Handle("POST /settings", a.user(a.saveSettings))
	mux.Handle("POST /settings/tokens", a.user(a.createToken))
	mux.Handle("POST /settings/tokens/{id}/delete", a.user(a.deleteToken))
	mux.Handle("POST /settings/users", a.user(a.createUser))
	mux.Handle("POST /settings/users/{id}/delete", a.user(a.deleteUser))
	mux.Handle("POST /settings/password", a.user(a.changePassword))
	mux.Handle("POST /settings/notifications/test", a.user(a.testNotification))
	mux.Handle("POST /settings/package/update", a.user(a.updatePackage))
	mux.Handle("POST /settings/uplink", a.user(a.enableUplink))
	mux.Handle("POST /settings/uplink/disable", a.user(a.disableUplink))
	mux.Handle("POST /settings/uplink/remove", a.user(a.removeUplink))
	registerKit(mux, a)
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		a.renderError(w, req, nil, http.StatusNotFound, "Not found", "There is nothing at this address.")
	})

	return a.securityHeaders(mux), nil
}

// NewServer returns an HTTP server with conservative timeouts.
func NewServer(addr string, logger *slog.Logger, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// handleHealthz is the unauthenticated liveness probe. It reveals nothing
// beyond the fact that the process serves HTTP.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writePlain(w, http.StatusOK, "ok\n")
}

// readyz is the unauthenticated readiness probe. The reason for not being
// ready is logged, never returned, because the endpoint is public.
func readyz(logger *slog.Logger, ready func(context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
			defer cancel()
			if err := ready(ctx); err != nil {
				logger.Debug("not ready", "err", err)
				writePlain(w, http.StatusServiceUnavailable, "not ready\n")
				return
			}
		}
		writePlain(w, http.StatusOK, "ready\n")
	}
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// securityHeaders applies to every response.
func (a *app) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if a.d.BehindTLS || r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

type userHandler func(w http.ResponseWriter, r *http.Request, cur *auth.Current)

// user requires a session; state-changing requests must also pass the
// Origin/Fetch-Metadata check and present the CSRF token.
func (a *app) user(h userHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur, err := a.d.Sessions.Load(r.Context(), r)
		if err != nil {
			a.d.Log.Error("loading session failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if cur == nil {
			if n, err := a.d.Store.CountUsers(r.Context()); err == nil && n == 0 {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			http.Error(w, "session expired", http.StatusUnauthorized)
			return
		}
		if !auth.SafeMethod(r.Method) {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if !auth.CheckOrigin(r) || !auth.CheckCSRF(r, cur) {
				a.renderError(w, r, cur, http.StatusForbidden, "Request blocked", "The form was too old or came from another site. Reload the page and try again.")
				return
			}
		}
		h(w, r, cur)
	})
}

func (a *app) audit(r *http.Request, cur *auth.Current, action, target, detail string) {
	actor := "anonymous"
	if cur != nil {
		actor = cur.User.Username
	}
	if err := a.d.Store.Audit(r.Context(), store.AuditEntry{At: a.d.Now(), Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		a.d.Log.Error("audit log write failed", "action", action, "err", err)
	}
}

func (a *app) renderError(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, title, msg string) {
	v := view{Title: title, Data: struct{ Title, Message string }{title, msg}}
	if cur != nil {
		v.User, v.CSRF = cur.User, cur.CSRFToken
	}
	if cur == nil {
		// Without a session the full navigation would be misleading.
		a.r.render(w, status, "login", view{Title: title, Data: loginData{Error: msg}})
		return
	}
	a.page(w, r, cur, status, "error", v)
}

// page renders an authenticated page with the shared chrome.
func (a *app) page(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, name string, v view) {
	v.User, v.CSRF = cur.User, cur.CSRFToken
	v.Lit = a.newP1(r.Context()) > 0
	if a.d.AllowDirectSocket {
		v.Banners = append(v.Banners, Banner{"alert", "alert", "The Docker socket is mounted directly. A compromise of Varde gives root on this host. Use a read-only socket proxy."})
	}
	if !a.d.Sessions.Secure(r) && !v.OwnSecurityNote {
		// Plain http in the LAN is how Varde starts, and the front page
		// lists HTTPS among the setup steps: the reminder belongs where it
		// can be acted on, not above every page. A proxy that terminates
		// TLS but is not trusted is a mistake in the setup, and is said
		// everywhere.
		proxy := a.d.Sessions.UntrustedTLSProxy(r)
		if proxy != "" || v.Nav == "connections" || v.Nav == "settings" {
			v.Banners = append(v.Banners, Banner{"warn", "lock", insecureText(proxy)})
		}
	}
	if a.d.CatchingUp != nil {
		// What the pages show is not final while the sources are still
		// being read: say so, or early results look like all there is.
		if busy, limited, failed := a.d.CatchingUp(); failed {
			v.Banners = append(v.Banners, Banner{"warn", "alert", "An advisory source answered with an error, so what it would have brought is missing: what is shown is not everything. Advisory data under Settings names the source; Varde asks it again at the next refresh."})
		} else if limited {
			v.Banners = append(v.Banners, Banner{"info", "refresh", "Varde is still fetching advisory data: a source limits how many requests it accepts per hour, so the rest follows by itself over the next hours. Findings and versions keep arriving until then; what is shown is not yet everything."})
		} else if busy {
			v.Banners = append(v.Banners, Banner{"info", "refresh", "Varde is fetching advisory data for what it found. Findings and versions keep arriving until the first round through every source is done; what is shown is not yet everything. This notice goes away by itself."})
		}
	}
	if msg, ok := notices[r.URL.Query().Get("ok")]; ok {
		v.Notice = msg
	}
	a.r.render(w, status, name, v)
}

// notices are fixed messages selected by code, so no request data is
// reflected into the page.
var notices = map[string]string{
	"saved":           "Settings saved.",
	"uplink":          "Uplink switched on.",
	"uplink-off":      "Uplink switched off.",
	"package":         "Data package updated.",
	"package-current": "The data package is already current.",
	"ack":             "Finding acknowledged.",
	"snoozed":         "Finding snoozed.",
	"reopened":        "Finding reopened.",
	"suppressed":      "Advisory suppressed.",
	"unsuppressed":    "Suppression lifted. The findings it covered are open again.",
	"manual-added":    "Manual entry added.",
	"manual-gone":     "Manual entry removed.",
	"not-an-app":      "Marked as not an app. It no longer counts as a gap.",
	"is-an-app":       "Mark removed. The container counts as a gap again.",
	"scope":           "Network ranges saved.",
	"scan-started":    "Scan started. This page updates until it is done.",
	"connected":       "Connected. The inventory appears within a minute.",
	"removed":         "Integration removed with the hosts it reported.",
	"enabled":         "Integration switched on.",
	"disabled":        "Integration switched off.",
	"synced":          "Collection started.",
	"not-running":     "The integration is switched off. Switch it on to read it.",
	"scan":            "Check started. Results appear within a minute.",
	"test-sent":       "Test notification sent.",
	"test-failed":     "Test notification failed. The notification log has details.",
	"token-revoked":   "Token revoked.",
	"user-added":      "User added.",
	"user-deleted":    "User deleted.",
	"password":        "Password changed. Other sessions were signed out.",
}

// newP1 counts P1 findings nobody has acknowledged yet; they light the
// beacon in the top bar.
func (a *app) newP1(ctx context.Context) int {
	fs, err := a.d.Store.Findings(ctx, store.FindingFilter{})
	if err != nil {
		return 0
	}
	n := 0
	for _, f := range fs {
		if f.Priority == "P1" && f.State == store.StateOpen {
			n++
		}
	}
	return n
}

func active(state string) bool { return status.Active(state) }

// movedPages maps the pages of earlier versions to their area.
var movedPages = map[string]string{
	"/hosts":     "/systems",
	"/inventory": "/systems/apps",
	"/coverage":  "/systems/gaps",
	"/network":   "/connections",
	"/sources":   "/settings/sources",
}

// movedSubpaths are paths below a moved page that went elsewhere than the
// page itself.
var movedSubpaths = map[string]string{
	"/hosts/agent/install": "/connections/agents/install",
	"/hosts/enroll":        "/connections/agents/tokens",
}

// moved redirects a path below an old page to the same path below its new
// place, keeping the query. Reads move permanently; form posts are sent on
// with 308 so that the method and body are kept.
func moved(old, area string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, old)
		target := area + rest
		for from, to := range movedSubpaths {
			if r.URL.Path == from || strings.HasPrefix(r.URL.Path, from+"/") {
				target = to + strings.TrimPrefix(r.URL.Path, from)
			}
		}
		if old == "/hosts" && strings.HasSuffix(rest, "/revoke") {
			target = "/connections/agents" + rest
		}
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		code := http.StatusMovedPermanently
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			code = http.StatusPermanentRedirect
		}
		// target starts with a fixed local path; the mux has cleaned the
		// rest, so it cannot point to another host.
		http.Redirect(w, r, target, code) //nolint:gosec // local path, see above
	})
}

// insecureText explains an unencrypted connection. Behind an HTTPS proxy
// Varde does not trust yet, it names the proxy and the setting.
func insecureText(proxy string) string {
	if proxy != "" {
		return "You reach Varde through an HTTPS proxy at " + proxy + ", but Varde does not trust it yet and treats the connection as unencrypted. " +
			"Set VARDE_TRUSTED_PROXIES=" + proxy + " (and VARDE_BEHIND_TLS_PROXY=true when every access goes through it), then restart Varde."
	}
	return "This connection is not encrypted. Put Varde behind HTTPS before using it beyond your own machine."
}
