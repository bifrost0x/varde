// SPDX-License-Identifier: Apache-2.0

package fleet_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/agent"
	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/fleet"
	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

type env struct {
	st      *store.Store
	ca      *fleet.CA
	srv     *httptest.Server
	fleet   *fleet.Server
	changed chan struct{}
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := fleet.LoadOrCreateCA(filepath.Join(dir, "ca"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: st, ca: ca, changed: make(chan struct{}, 16), now: time.Now()}
	fs := fleet.NewServer(ca, st, slog.New(slog.DiscardHandler), func(context.Context) { e.changed <- struct{}{} })
	e.fleet = fs
	e.srv = httptest.NewUnstartedServer(fs.Handler())
	e.srv.TLS = fs.TLSConfig()
	e.srv.StartTLS()
	// httptest installs its own certificate; without SNI (IP address) Go
	// would prefer it over GetCertificate. Production has none.
	e.srv.TLS.Certificates = nil
	t.Cleanup(e.srv.Close)
	return e
}

// token creates an enrollment token valid for d.
func (e *env) token(t *testing.T, d time.Duration) string {
	t.Helper()
	secret, _ := auth.RandomToken(32)
	id, _ := auth.RandomToken(12)
	if err := e.st.CreateEnrollmentToken(t.Context(), store.EnrollmentToken{
		ID: id, Name: "test", TokenHash: auth.HashToken(secret), CreatedBy: "admin", CreatedAt: e.now, ExpiresAt: e.now.Add(d),
	}); err != nil {
		t.Fatal(err)
	}
	return wire.FormatToken(secret, e.ca.Pin())
}

func (e *env) agent(t *testing.T, token, dataDir string) *agent.Agent {
	t.Helper()
	a, err := agent.New(config.Agent{
		DataDir: dataDir, ServerURL: e.srv.URL, EnrollToken: config.Secret(token), Interval: 15 * time.Minute, AutoUpdate: true,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.UpsertHost(t.Context(), inventory.Host{Name: "nas", OS: "Debian 13", Arch: "arm64"}); err != nil {
		t.Fatal(err)
	}
	return a
}

func container(id, name, image string) inventory.Workload {
	return inventory.Workload{Kind: inventory.KindContainer, RuntimeID: id, Name: name, State: "running",
		Container: &inventory.Container{ImageRef: image}}
}

func push(t *testing.T, a *agent.Agent, ws ...inventory.Workload) error {
	t.Helper()
	_, err := a.ApplySnapshot(t.Context(), "", inventory.KindContainer, ws, time.Now())
	return err
}

func agentHost(t *testing.T, st *store.Store) inventory.Host {
	t.Helper()
	hosts, err := st.Hosts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h.Source == inventory.SourceAgent {
			return h
		}
	}
	t.Fatal("no agent host")
	return inventory.Host{}
}

func TestEnrollReportAndHeartbeat(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	a := e.agent(t, e.token(t, time.Hour), dir)
	if err := push(t, a, container("c1", "immich", "ghcr.io/immich-app/immich-server:v1.120.0")); err != nil {
		t.Fatal(err)
	}
	h := agentHost(t, e.st)
	if h.Name != "nas" || h.State != inventory.HostActive || h.CertExpires == nil || h.ReportInterval != 15*time.Minute {
		t.Fatalf("host: %+v", h)
	}
	ws, _ := e.st.Workloads(t.Context(), store.WorkloadFilter{HostID: h.ID})
	if len(ws) != 1 || ws[0].Name != "immich" || ws[0].HostID != h.ID {
		t.Fatalf("workloads: %+v", ws)
	}
	select {
	case <-e.changed:
	case <-time.After(5 * time.Second):
		t.Fatal("analysis not triggered")
	}
	// Key material is private to the agent.
	fi, err := os.Stat(filepath.Join(dir, "identity.pem"))
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("identity file mode: %v %v", fi.Mode(), err)
	}

	// Unchanged snapshot: heartbeat only, no analysis.
	if err := push(t, a, container("c1", "immich", "ghcr.io/immich-app/immich-server:v1.120.0")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.changed:
		t.Fatal("heartbeat triggered analysis")
	case <-time.After(200 * time.Millisecond):
	}

	// A restarted agent loads its identity and does not need the token.
	b, err := agent.New(config.Agent{DataDir: dir, ServerURL: e.srv.URL, Interval: 15 * time.Minute}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	_ = b.UpsertHost(t.Context(), inventory.Host{Name: "nas"})
	// It does not know the last hash, sends the full snapshot, and the
	// container disappears.
	if err := push(t, b); err != nil {
		t.Fatal(err)
	}
	ws, _ = e.st.Workloads(t.Context(), store.WorkloadFilter{HostID: h.ID})
	if len(ws) != 0 {
		t.Fatalf("removed container still active: %d", len(ws))
	}
}

func TestHeartbeatAfterServerLostSnapshot(t *testing.T) {
	e := newEnv(t)
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	w := container("c1", "app", "nginx:1.27")
	if err := push(t, a, w); err != nil {
		t.Fatal(err)
	}
	h := agentHost(t, e.st)
	// Simulate a restored server database: the stored hash no longer matches.
	if err := e.st.SetSnapshotHash(t.Context(), h.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := push(t, a, w); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.st.SnapshotHash(t.Context(), h.ID); got == "" {
		t.Fatal("server did not ask for the full snapshot again")
	}
}

func TestEnrollmentTokenRules(t *testing.T) {
	e := newEnv(t)
	tok := e.token(t, time.Hour)
	if err := push(t, e.agent(t, tok, t.TempDir())); err != nil {
		t.Fatal(err)
	}
	// Single use.
	if err := push(t, e.agent(t, tok, t.TempDir())); !errors.Is(err, agent.ErrRejected) {
		t.Fatalf("reused token: %v", err)
	}
	// Expired.
	if err := push(t, e.agent(t, e.token(t, -time.Minute), t.TempDir())); !errors.Is(err, agent.ErrRejected) {
		t.Fatalf("expired token: %v", err)
	}
	// Unknown secret with the right pin.
	secret, _ := auth.RandomToken(32)
	if err := push(t, e.agent(t, wire.FormatToken(secret, e.ca.Pin()), t.TempDir())); !errors.Is(err, agent.ErrRejected) {
		t.Fatalf("unknown token: %v", err)
	}
	// A wrong CA pin makes the agent refuse the server before sending
	// anything.
	other := strings.Repeat("ab", 32)
	secret2 := strings.Split(e.token(t, time.Hour), ".")[1]
	err := push(t, e.agent(t, wire.FormatToken(secret2, other), t.TempDir()))
	if err == nil || !strings.Contains(err.Error(), "pinned Varde CA") {
		t.Fatalf("wrong pin: %v", err)
	}
	if _, err := agent.New(config.Agent{DataDir: t.TempDir(), ServerURL: e.srv.URL, EnrollToken: "garbage"}, slog.New(slog.DiscardHandler)); !errors.Is(err, wire.ErrBadToken) {
		t.Fatalf("malformed token: %v", err)
	}
}

func TestRevocationIsImmediate(t *testing.T) {
	e := newEnv(t)
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	if err := push(t, a, container("c1", "app", "nginx:1.27")); err != nil {
		t.Fatal(err)
	}
	h := agentHost(t, e.st)
	if err := e.st.RevokeAgent(t.Context(), h.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := push(t, a, container("c2", "other", "nginx:1.27")); !errors.Is(err, agent.ErrRejected) {
		t.Fatalf("revoked agent accepted: %v", err)
	}
	ws, _ := e.st.Workloads(t.Context(), store.WorkloadFilter{HostID: h.ID})
	if len(ws) != 0 {
		t.Fatalf("revoked host keeps active workloads: %d", len(ws))
	}
	if h := agentHost(t, e.st); h.State != inventory.HostRevoked {
		t.Fatalf("state %s", h.State)
	}
}

// TestCertificatePinning: a certificate from the right CA for the right
// host ID is still rejected when it is not the pinned one, and a certificate
// from another CA fails the handshake.
func TestCertificatePinning(t *testing.T) {
	e := newEnv(t)
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	if err := push(t, a); err != nil {
		t.Fatal(err)
	}
	h := agentHost(t, e.st)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	_, certPEM, err := e.ca.SignAgent(pemCSR(csrDER), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, err := tls.X509KeyPair(certPEM, pemBlock("PRIVATE KEY", keyDER))
	if err != nil {
		t.Fatal(err)
	}
	if code := rawReport(t, e, cert); code != http.StatusForbidden {
		t.Fatalf("unpinned certificate: %d", code)
	}

	// Self-signed client certificate with the host ID: handshake or request fails.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: h.ID},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	foreign := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	if code := rawReport(t, e, foreign); code == http.StatusOK {
		t.Fatal("certificate from another CA accepted")
	}
	// No certificate at all.
	if code := rawReport(t, e, tls.Certificate{}); code != http.StatusUnauthorized {
		t.Fatalf("no certificate: %d", code)
	}
}

func TestRenewalKeepsOldCertificateUntilFirstUse(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	a := e.agent(t, e.token(t, time.Hour), dir)
	if err := push(t, a); err != nil {
		t.Fatal(err)
	}
	h := agentHost(t, e.st)
	_, oldPin, _, _ := e.st.AgentPins(t.Context(), h.ID)
	oldPEM, _ := os.ReadFile(filepath.Join(dir, "identity.pem"))
	oldCert, err := tls.X509KeyPair(oldPEM, oldPEM)
	if err != nil {
		t.Fatal(err)
	}

	// 70 days later the certificate is due for renewal.
	if _, err := a.ApplySnapshot(t.Context(), "", inventory.KindContainer, nil, time.Now().Add(70*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, cur, pending, _ := e.st.AgentPins(t.Context(), h.ID)
	if cur == oldPin || pending != "" {
		t.Fatalf("rotation not completed: current changed=%v pending=%q", cur != oldPin, pending)
	}
	// The old certificate is no longer accepted once the new one was used.
	if code := rawReport(t, e, oldCert); code != http.StatusForbidden {
		t.Fatalf("old certificate after rotation: %d", code)
	}
	if h := agentHost(t, e.st); h.CertExpires == nil || h.CertExpires.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatalf("expiry not updated: %v", h.CertExpires)
	}
}

func TestReportValidation(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	a := e.agent(t, e.token(t, time.Hour), dir)
	if err := push(t, a); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "identity.pem"))
	cert, _ := tls.X509KeyPair(raw, raw)
	hash := strings.Repeat("0", 64)
	manual := []inventory.Workload{{Kind: inventory.KindManual, RuntimeID: "x", Name: "x", Manual: &inventory.Manual{AppID: "immich", Version: "1"}}}
	for name, body := range map[string]any{
		"manual workload": wire.Report{Agent: wire.Agent{Name: "nas"}, IntervalS: 900, SnapshotHash: hash, Containers: &manual},
		"bad interval":    wire.Report{Agent: wire.Agent{Name: "nas"}, IntervalS: 1, SnapshotHash: hash},
		"control chars":   wire.Report{Agent: wire.Agent{Name: "n\x1bas"}, IntervalS: 900, SnapshotHash: hash},
		"unknown field":   map[string]any{"agent": map[string]string{"name": "nas"}, "interval_s": 900, "snapshot_hash": hash, "host_id": "other"},
	} {
		if code := post(t, e, cert, wire.ReportPath, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
}

func TestStaleHostsAndNotices(t *testing.T) {
	e := newEnv(t)
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	if err := push(t, a); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := coverage.RefreshHosts(ctx, e.st, time.Now().Add(40*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if h := agentHost(t, e.st); h.State != inventory.HostActive {
		t.Fatalf("stale too early: %s", h.State)
	}
	if err := coverage.RefreshHosts(ctx, e.st, time.Now().Add(46*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if h := agentHost(t, e.st); h.State != inventory.HostStale {
		t.Fatalf("not stale after three intervals: %s", h.State)
	}
	ns, _ := e.st.ActiveNotices(ctx)
	if len(ns) != 1 || ns[0].Kind != store.NoticeHostStale || !strings.Contains(ns[0].Title, "nas") {
		t.Fatalf("notices: %+v", ns)
	}
	// Reporting again makes the host active and resolves the notice.
	if err := push(t, a); err != nil {
		t.Fatal(err)
	}
	if err := coverage.RefreshHosts(ctx, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ns, _ := e.st.ActiveNotices(ctx); len(ns) != 0 {
		t.Fatalf("notice not resolved: %+v", ns)
	}
}

func TestAgentHealthcheck(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	cfg := config.Agent{DataDir: dir, Interval: 15 * time.Minute}
	if agent.Healthy(cfg, time.Now()) == nil {
		t.Fatal("healthy before the first report")
	}
	if err := push(t, e.agent(t, e.token(t, time.Hour), dir)); err != nil {
		t.Fatal(err)
	}
	if err := agent.Healthy(cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	if agent.Healthy(cfg, time.Now().Add(47*time.Minute)) == nil {
		t.Fatal("healthy after three missed intervals")
	}
}

func rawReport(t *testing.T, e *env, cert tls.Certificate) int {
	t.Helper()
	return post(t, e, cert, wire.ReportPath, wire.Report{Agent: wire.Agent{Name: "x"}, IntervalS: 900, SnapshotHash: strings.Repeat("0", 64)})
}

func post(t *testing.T, e *env, cert tls.Certificate, path string, body any) int {
	t.Helper()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: wire.PinnedServer(e.ca.Pin())} //nolint:gosec // pinned
	if len(cert.Certificate) > 0 {
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 10 * time.Second}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, e.srv.URL+path, bytes.NewReader(raw))
	resp, err := c.Do(req)
	if err != nil {
		return -1 // handshake rejected
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func pemCSR(der []byte) string { return string(pemBlock("CERTIFICATE REQUEST", der)) }

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// TestSnapshotAfterRevocationIsRefused: a report that passed the
// certificate check before a revocation cannot write workloads afterwards.
func TestSnapshotAfterRevocationIsRefused(t *testing.T) {
	e := newEnv(t)
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	if err := push(t, a, container("c1", "app", "nginx:1.27")); err != nil {
		t.Fatal(err)
	}
	h := agentHost(t, e.st)
	if err := e.st.RevokeAgent(t.Context(), h.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err := e.st.ApplyAgentSnapshot(t.Context(), h.ID, []inventory.Workload{container("c2", "late", "nginx:1.27")}, strings.Repeat("1", 64), time.Now())
	if !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("late snapshot: %v", err)
	}
	if ws, _ := e.st.Workloads(t.Context(), store.WorkloadFilter{HostID: h.ID}); len(ws) != 0 {
		t.Fatalf("revoked host got workloads back: %d", len(ws))
	}
}
