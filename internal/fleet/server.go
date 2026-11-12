// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// Store is what the agent listener needs.
type Store interface {
	EnrollAgent(ctx context.Context, tokenHash string, h inventory.Host, cert store.AgentCert, now time.Time) error
	EnrollmentTokenValid(ctx context.Context, tokenHash string, now time.Time) (bool, error)
	AgentPins(ctx context.Context, hostID string) (inventory.HostState, string, string, error)
	SetPendingCert(ctx context.Context, hostID string, cert store.AgentCert) error
	PromotePendingCert(ctx context.Context, hostID string) error
	TouchAgent(ctx context.Context, hostID string, r store.AgentReport, now time.Time) error
	ApplyAgentSnapshot(ctx context.Context, hostID string, ws []inventory.Workload, hash string, now time.Time) (inventory.Changes, error)
	SnapshotHash(ctx context.Context, hostID string) (string, error)
	AgentImageIDs(ctx context.Context, hostID string) (map[string]bool, error)
	RecordAgentImagePackages(ctx context.Context, hostID string, p inventory.ImagePackages) (bool, error)
	Audit(ctx context.Context, e store.AuditEntry) error
}

// Server handles agent traffic on its own listener.
type Server struct {
	CA    *CA
	Store Store
	Log   *slog.Logger
	// Changed is called after a report changed the inventory.
	Changed func(ctx context.Context)
	Now     func() time.Time
	// Inventory stores the host inventory of a report (the output of the
	// inventory command) for the agent's host; it reports whether
	// anything changed. Nil ignores host inventories.
	Inventory func(ctx context.Context, hostID string, raw []byte, now time.Time) (bool, error)
	// Binaries are the agent binaries offered as updates; nil offers none.
	Binaries *Binaries
	// ReadImages reports whether agents should read image package
	// databases (the container packages setting); nil means no.
	ReadImages func() bool

	enrollThrottle *auth.Throttle
	mu             sync.Mutex
	buckets        map[string]*bucket
}

// NewServer returns a Server with defaults applied.
func NewServer(ca *CA, st Store, log *slog.Logger, changed func(ctx context.Context)) *Server {
	return &Server{CA: ca, Store: st, Log: log, Changed: changed, Now: time.Now,
		enrollThrottle: auth.NewThrottle(), buckets: map[string]*bucket{}}
}

// TLSConfig requires TLS 1.3 and verifies client certificates against the
// CA when one is presented. Enrollment is the only endpoint without one.
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  s.CA.Pool(),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.CA.ServerCertificate()
		},
	}
}

// Handler routes agent requests.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.EnrollPath, s.enroll)
	mux.HandleFunc("POST "+wire.ReportPath, s.agentOnly(s.report))
	mux.HandleFunc("POST "+wire.RenewPath, s.agentOnly(s.renew))
	mux.HandleFunc("GET "+wire.BinaryPath, s.agentOnly(s.binary))
	return mux
}

// HTTPServer returns the configured listener server.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		TLSConfig:         s.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.Log.Handler(), slog.LevelDebug),
	}
}

var hostIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := clientIP(r)
	if ok, wait := s.enrollThrottle.Begin("enroll:"+ip, ip); !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	var req wire.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	secret, _, err := wire.ParseToken(req.Token)
	if err != nil {
		writeError(w, http.StatusForbidden, "invalid enrollment token")
		return
	}
	if err := wire.ValidAgent(req.Agent); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	interval, err := validInterval(req.IntervalS)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		s.internal(w, err)
		return
	}
	hostID := hex.EncodeToString(idBytes)
	// The token is checked before the CA signs anything: an unknown client
	// gets no certificate at all (the enrollment below still consumes the
	// token atomically).
	if ok, err := s.Store.EnrollmentTokenValid(ctx, auth.HashToken(secret), s.Now()); err != nil {
		s.internal(w, err)
		return
	} else if !ok {
		s.Log.Warn("agent enrollment rejected: unknown, used or expired token", "ip", ip)
		writeError(w, http.StatusForbidden, "invalid enrollment token")
		return
	}
	cert, certPEM, err := s.CA.SignAgent(req.CSR, hostID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := s.Now()
	host := inventory.Host{ID: hostID, Name: req.Agent.Name, Kind: req.Agent.HostKind(), AgentVersion: req.Agent.Version,
		OS: req.Agent.OS, Arch: req.Agent.Arch, ReportInterval: interval}
	err = s.Store.EnrollAgent(ctx, auth.HashToken(secret), host, store.AgentCert{Fingerprint: wire.Fingerprint(cert), Expires: cert.NotAfter}, now)
	if errors.Is(err, store.ErrConflict) {
		s.Log.Warn("agent enrollment rejected: unknown, used or expired token", "ip", ip)
		writeError(w, http.StatusForbidden, "invalid enrollment token")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.enrollThrottle.Success("enroll:"+ip, ip)
	s.audit(ctx, "agent.enroll", hostID, req.Agent.Name+" from "+ip)
	s.Log.Info("agent enrolled", "host", hostID, "name", req.Agent.Name, "ip", ip)
	writeJSON(w, http.StatusOK, wire.EnrollResponse{HostID: hostID, Certificate: string(certPEM)})
}

// agentOnly authenticates the client certificate against the pins stored for
// its host on every request, so revocation takes effect immediately.
func (s *Server) agentOnly(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeError(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		hostID := leaf.Subject.CommonName
		if !hostIDPattern.MatchString(hostID) || !hasClientAuth(leaf) {
			writeError(w, http.StatusForbidden, "certificate not accepted")
			return
		}
		state, current, pending, err := s.Store.AgentPins(r.Context(), hostID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusForbidden, "certificate not accepted")
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		fp := wire.Fingerprint(leaf)
		switch {
		case state == inventory.HostRevoked:
			s.Log.Warn("revoked agent rejected", "host", hostID, "ip", clientIP(r))
			writeError(w, http.StatusForbidden, "agent revoked")
			return
		case fp == current && current != "":
		case fp == pending && pending != "":
			if err := s.Store.PromotePendingCert(r.Context(), hostID); err != nil {
				s.internal(w, err)
				return
			}
			s.Log.Info("agent certificate rotated", "host", hostID)
		default:
			s.Log.Warn("agent certificate does not match the pinned one", "host", hostID, "ip", clientIP(r))
			writeError(w, http.StatusForbidden, "certificate not accepted")
			return
		}
		if !s.allow(hostID) {
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next(w, r, hostID)
	}
}

func hasClientAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func (s *Server) report(w http.ResponseWriter, r *http.Request, hostID string) {
	ctx := r.Context()
	var rep wire.Report
	if !decode(w, r, &rep) {
		return
	}
	if err := wire.ValidAgent(rep.Agent); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	interval, err := validInterval(rep.IntervalS)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(rep.SnapshotHash) != 64 {
		writeError(w, http.StatusBadRequest, "snapshot_hash must be a hex SHA-256")
		return
	}
	now := s.Now()
	if err := s.Store.TouchAgent(ctx, hostID, store.AgentReport{Name: rep.Agent.Name, AgentVersion: rep.Agent.Version,
		OS: rep.Agent.OS, Arch: rep.Agent.Arch, Kind: rep.Agent.HostKind(), Addresses: rep.Agent.Addresses, Interval: interval}, now); err != nil {
		s.internal(w, err)
		return
	}
	if len(rep.Images) > wire.MaxImages {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d image records per report", wire.MaxImages))
		return
	}
	if rep.Containers == nil {
		known, err := s.Store.SnapshotHash(ctx, hostID)
		if err != nil {
			s.internal(w, err)
			return
		}
		if !s.images(w, r, hostID, rep.Images) {
			return
		}
		writeJSON(w, http.StatusOK, s.answer(rep.Agent, known != rep.SnapshotHash))
		return
	}
	ws, err := validContainers(*rep.Containers)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if rep.Inventory != nil && len(*rep.Inventory) > wire.MaxInventoryBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "inventory too large")
		return
	}
	// The host inventory is stored first: the snapshot hash, recorded with
	// the containers, then stands for both.
	hostChanged := false
	if rep.Inventory != nil && s.Inventory != nil {
		hostChanged, err = s.Inventory(ctx, hostID, []byte(*rep.Inventory), now)
		switch {
		case errors.Is(err, store.ErrInvalidState) || errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusForbidden, "agent revoked")
			return
		case errors.Is(err, wire.ErrBadInventory):
			writeError(w, http.StatusBadRequest, err.Error())
			return
		case err != nil:
			s.internal(w, err)
			return
		}
	}
	changes, err := s.Store.ApplyAgentSnapshot(ctx, hostID, ws, rep.SnapshotHash, now)
	if errors.Is(err, store.ErrInvalidState) || errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusForbidden, "agent revoked")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.Log.Info("agent inventory received", "host", hostID, "workloads", len(ws), "host_inventory", rep.Inventory != nil,
		"images", len(rep.Images), "added", changes.Added, "changed", changes.Changed, "removed", changes.Removed)
	// Images after the containers: the containers just stored say which
	// images the agent may report.
	if !s.images(w, r, hostID, rep.Images) {
		return
	}
	if (changes.Any() || hostChanged) && s.Changed != nil {
		// Analysis runs detached from the request: the agent must not wait.
		go s.Changed(context.WithoutCancel(ctx))
	}
	writeJSON(w, http.StatusOK, s.answer(rep.Agent, false))
}

// answer is the report answer: whether the full snapshot is needed, the
// update offer and whether to read image packages.
func (s *Server) answer(a wire.Agent, needSnapshot bool) wire.ReportResponse {
	return wire.ReportResponse{NeedSnapshot: needSnapshot, Update: s.update(a), ReadImages: s.ReadImages != nil && s.ReadImages()}
}

// images stores the image package records of a report. An agent speaks
// only for images its own containers use, and never replaces what another
// source read (ADR 0033); records for other images are ignored. It writes
// the error answer itself and reports false then.
func (s *Server) images(w http.ResponseWriter, r *http.Request, hostID string, recs []inventory.ImagePackages) bool {
	if len(recs) == 0 {
		return true
	}
	ctx := r.Context()
	own, err := s.Store.AgentImageIDs(ctx, hostID)
	if err != nil {
		s.internal(w, err)
		return false
	}
	stored := 0
	for _, p := range recs {
		if err := validImagePackages(p); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return false
		}
		if !own[p.ImageID] || p.Error != "" {
			continue
		}
		p.Read = s.Now()
		ok, err := s.Store.RecordAgentImagePackages(ctx, hostID, p)
		if err != nil {
			s.internal(w, err)
			return false
		}
		if ok {
			stored++
		}
	}
	if stored > 0 && s.Changed != nil {
		go s.Changed(context.WithoutCancel(ctx))
	}
	return true
}

var imageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// validImagePackages checks an image record from an agent: the agent is a
// separate trust zone.
func validImagePackages(p inventory.ImagePackages) error {
	if !imageIDPattern.MatchString(p.ImageID) {
		return errors.New("image record without a valid image ID")
	}
	if len(p.Error) > 512 {
		return errors.New("image record with invalid release fields")
	}
	if err := inventory.CheckImagePackages(p.Distro, p.OS, p.Packages); err != nil {
		return fmt.Errorf("image record with %w", err)
	}
	return nil
}

// update offers the shipped binary for the agent's platform.
func (s *Server) update(a wire.Agent) *wire.Update {
	b, ok := s.Binaries.For(a.Platform)
	if !ok {
		return nil
	}
	return &wire.Update{Version: buildinfo.Version, SHA256: b.SHA256}
}

// binary serves the agent binary for a platform to enrolled agents.
func (s *Server) binary(w http.ResponseWriter, r *http.Request, hostID string) {
	b, ok := s.Binaries.For(r.URL.Query().Get("platform"))
	if !ok {
		writeError(w, http.StatusNotFound, "no agent binary for this platform")
		return
	}
	f, err := os.Open(b.Path)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer func() { _ = f.Close() }()
	// A binary takes longer than the listener's write timeout on a slow
	// link.
	_ = http.NewResponseController(w).SetWriteDeadline(s.Now().Add(10 * time.Minute))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Checksum-Sha256", b.SHA256)
	s.Log.Info("agent binary served", "host", hostID, "platform", b.Platform)
	http.ServeContent(w, r, "", time.Time{}, f)
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request, hostID string) {
	var req wire.RenewRequest
	if !decode(w, r, &req) {
		return
	}
	cert, certPEM, err := s.CA.SignAgent(req.CSR, hostID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.SetPendingCert(r.Context(), hostID, store.AgentCert{Fingerprint: wire.Fingerprint(cert), Expires: cert.NotAfter}); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), "agent.renew", hostID, "")
	writeJSON(w, http.StatusOK, wire.RenewResponse{Certificate: string(certPEM)})
}

func validInterval(sec int) (time.Duration, error) {
	if sec < wire.MinIntervalS || sec > wire.MaxIntervalS {
		return 0, fmt.Errorf("interval_s must be between %d and %d", wire.MinIntervalS, wire.MaxIntervalS)
	}
	return time.Duration(sec) * time.Second, nil
}

// validContainers checks a pushed snapshot. The agent is a separate trust
// zone: the host ID comes from its certificate, never from the payload, and
// only container workloads are accepted in v1.
func validContainers(in []inventory.Workload) ([]inventory.Workload, error) {
	if len(in) > wire.MaxWorkloads {
		return nil, fmt.Errorf("at most %d workloads per snapshot", wire.MaxWorkloads)
	}
	out := make([]inventory.Workload, 0, len(in))
	for i, w := range in {
		if w.Kind != inventory.KindContainer || w.Container == nil || w.Manual != nil || w.Package != nil || w.Service != nil {
			return nil, fmt.Errorf("workload %d: only containers are accepted", i)
		}
		if w.RuntimeID == "" || len(w.RuntimeID) > 128 || w.Name == "" || len(w.Name) > 256 || len(w.Container.ImageRef) > 512 {
			return nil, fmt.Errorf("workload %d: missing or oversized fields", i)
		}
		if len(w.Container.Labels) > 512 || len(w.Container.ImageLabels) > 512 {
			return nil, fmt.Errorf("workload %d: too many labels", i)
		}
		if rt := w.Container.Runtime; rt != nil && (len(rt.CapAdd) > 40 || len(rt.User) > 64 || len(rt.NetworkMode) > 128 || len(rt.PidMode) > 128) {
			return nil, fmt.Errorf("workload %d: oversized runtime settings", i)
		}
		out = append(out, inventory.Workload{
			Kind: inventory.KindContainer, RuntimeID: w.RuntimeID, Name: w.Name, State: w.State, Container: w.Container,
		})
	}
	return out, nil
}

// bucket is a small token bucket per agent: bursts of 10, one request per
// 6 seconds sustained.
type bucket struct {
	tokens float64
	last   time.Time
}

func (s *Server) allow(hostID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	b, ok := s.buckets[hostID]
	if !ok {
		if len(s.buckets) > 10000 {
			s.buckets = map[string]*bucket{}
		}
		b = &bucket{tokens: 10, last: now}
		s.buckets[hostID] = b
	}
	b.tokens = min(10, b.tokens+now.Sub(b.last).Seconds()/6)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) audit(ctx context.Context, action, target, detail string) {
	if err := s.Store.Audit(ctx, store.AuditEntry{At: s.Now(), Actor: "agent", Action: action, Target: target, Detail: detail}); err != nil {
		s.Log.Error("audit failed", "action", action, "err", err)
	}
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.Log.Error("agent request failed", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// clientIP is the TCP peer. The agent listener does not honour forwarded
// headers: it is meant to be reached directly.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, wire.MaxBodyBytes))
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
