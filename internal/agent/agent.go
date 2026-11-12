// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/fsutil"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/inventory/docker"
)

// renewBefore matches the server: certificates are renewed when less than
// 30 days remain.
const renewBefore = 30 * 24 * time.Hour

// ErrRejected marks answers that retrying cannot fix (invalid token,
// revoked agent).
var ErrRejected = errors.New("rejected by the server")

// Agent pushes the local inventory to the server. It implements
// inventory.SnapshotStore so that the same Syncer that drives the server's
// local collector drives the agent.
type Agent struct {
	cfg config.Agent
	log *slog.Logger
	now func() time.Time

	// ReadInventory reads the host inventory sent with every full
	// snapshot; nil sends none. RunInventory is the production reader.
	ReadInventory func(ctx context.Context) ([]byte, error)

	mu       sync.Mutex
	id       *identity
	host     inventory.HostInfo
	lastHash string
	client   *http.Client
	// The host inventory is read at most every half interval, however
	// often Docker events trigger a snapshot.
	inv    *string
	invAt  time.Time
	invErr string
	// exe and selfSHA are set when the agent may replace its binary.
	exe, selfSHA string
	stop         context.CancelFunc
	updated      atomic.Bool
	// images keeps the image package reads until the server accepted
	// them; readImages follows the server's setting (ADR 0033).
	images     *imageStore
	readImages atomic.Bool
	// resync asks for a sync at once, when the server switched image
	// reading on.
	resync func()
}

// New returns an agent; it loads an existing identity from the data
// directory.
func New(cfg config.Agent, log *slog.Logger) (*Agent, error) {
	a := &Agent{cfg: cfg, log: log, now: time.Now, images: newImageStore()}
	id, err := loadIdentity(cfg.DataDir)
	switch {
	case err == nil:
		a.id = id
		a.client = a.httpClient(id.CAPin)
	case errors.Is(err, os.ErrNotExist):
		if cfg.EnrollToken == "" {
			return nil, errors.New("not enrolled yet: set VARDE_ENROLL_TOKEN (or _FILE) to a token from Connections › Agents on the server")
		}
		_, pin, err := wire.ParseToken(string(cfg.EnrollToken))
		if err != nil {
			return nil, err
		}
		a.client = a.httpClient(pin)
	default:
		return nil, err
	}
	return a, nil
}

// Run syncs the collector into the server until ctx ends or the agent
// replaced its binary (see Updated).
func (a *Agent) Run(ctx context.Context, collector inventory.Collector) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.mu.Lock()
	a.stop = cancel
	a.mu.Unlock()
	syncer := inventory.NewSyncer(inventory.SyncerConfig{
		HostID: "agent", HostKind: inventory.HostDocker, Source: inventory.SourceAgent,
		Collector: collector, Store: a, Log: a.log, Resync: a.cfg.Interval,
	})
	a.mu.Lock()
	a.resync = syncer.Trigger
	a.mu.Unlock()
	syncer.Run(ctx)
}

func (a *Agent) httpClient(pin string) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The server is verified by the CA pin in VerifyConnection instead
		// of the system roots and host names (see wire.PinnedServer).
		InsecureSkipVerify: true, //nolint:gosec // replaced by pinned verification below
		VerifyConnection:   wire.PinnedServer(pin),
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.id == nil {
				return &tls.Certificate{}, nil
			}
			c := a.id.Cert
			return &c, nil
		},
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true, MaxIdleConns: 2, IdleConnTimeout: 90 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
			Proxy: http.ProxyFromEnvironment,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (a *Agent) closeIdle() {
	if t, ok := a.client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

// UpsertHost records the host description the collector reported.
func (a *Agent) UpsertHost(_ context.Context, h inventory.Host) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.host = inventory.HostInfo{Name: h.Name, OS: h.OS, Arch: h.Arch}
	if a.cfg.Name != "" {
		a.host.Name = a.cfg.Name
	}
	if a.host.Name == "" {
		a.host.Name = "unnamed host"
	}
	return nil
}

// PurgeRemoved is a no-op: the agent keeps no inventory.
func (a *Agent) PurgeRemoved(context.Context, time.Time) (int64, error) { return 0, nil }

// ApplySnapshot enrolls on first use, renews the certificate when due, and
// pushes the snapshot, or only a heartbeat when nothing changed.
func (a *Agent) ApplySnapshot(ctx context.Context, _ string, _ inventory.Kind, ws []inventory.Workload, now time.Time) (inventory.Changes, error) {
	if err := a.ensureEnrolled(ctx); err != nil {
		return inventory.Changes{}, err
	}
	if err := a.renewIfDue(ctx, now); err != nil {
		// The current certificate is still valid; try again next time.
		a.log.Warn("certificate renewal failed", "err", err)
	}
	inv := a.hostInventory(ctx, now)
	hash, err := snapshotHash(ws, inv)
	if err != nil {
		return inventory.Changes{}, err
	}
	a.mu.Lock()
	full := hash != a.lastHash
	a.mu.Unlock()
	resp, err := a.report(ctx, ws, inv, hash, full)
	if err == nil && resp.NeedSnapshot && !full {
		resp, err = a.report(ctx, ws, inv, hash, true)
	}
	if err != nil {
		return inventory.Changes{}, err
	}
	if was := a.readImages.Swap(resp.ReadImages); resp.ReadImages && !was {
		// Read the images now, not at the next interval.
		a.mu.Lock()
		resync := a.resync
		a.mu.Unlock()
		if resync != nil {
			resync()
		}
	}
	defer a.maybeUpdate(ctx, resp.Update)
	a.mu.Lock()
	a.lastHash = hash
	a.mu.Unlock()
	stamp := []byte(now.UTC().Format(time.RFC3339))
	if err := fsutil.WriteFileAtomic(filepath.Join(a.cfg.DataDir, LastReportFile), stamp, 0o600); err != nil {
		a.log.Warn("recording report time failed", "err", err)
	}
	return inventory.Changes{}, nil
}

func (a *Agent) agentInfo() wire.Agent {
	a.mu.Lock()
	defer a.mu.Unlock()
	docker := a.cfg.DockerHost != config.DockerHostOff
	// Without addresses the host is only announced without them.
	addrs, _ := InterfaceAddresses()
	return wire.Agent{Name: a.host.Name, Version: buildinfo.Version, OS: a.host.OS, Arch: a.host.Arch, Platform: Platform(),
		Docker: &docker, Addresses: addrs}
}

// hostInventory returns the host inventory to send, read again when the
// last read is older than half the interval. A failure is logged once and
// sends no inventory; the server keeps the last one.
func (a *Agent) hostInventory(ctx context.Context, now time.Time) *string {
	if a.ReadInventory == nil {
		return nil
	}
	a.mu.Lock()
	inv, at := a.inv, a.invAt
	a.mu.Unlock()
	if !at.IsZero() && now.Sub(at) < a.cfg.Interval/2 {
		return inv
	}
	raw, err := a.ReadInventory(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.invAt = now
	if err != nil {
		if msg := err.Error(); msg != a.invErr {
			a.invErr = msg
			level := slog.LevelWarn
			if errors.Is(err, errNoShell) {
				// The agent's container image: expected, not a fault.
				level = slog.LevelInfo
			}
			a.log.Log(ctx, level, "host inventory not read", "err", err)
		}
		a.inv = nil
		return nil
	}
	a.invErr = ""
	s := string(raw)
	a.inv = &s
	return a.inv
}

func (a *Agent) ensureEnrolled(ctx context.Context) error {
	a.mu.Lock()
	enrolled := a.id != nil
	a.mu.Unlock()
	if enrolled {
		return nil
	}
	_, pin, err := wire.ParseToken(string(a.cfg.EnrollToken))
	if err != nil {
		return err
	}
	info := a.agentInfo()
	keyPEM, csrPEM, err := newKeyAndCSR(info.Name)
	if err != nil {
		return err
	}
	var resp wire.EnrollResponse
	err = a.post(ctx, wire.EnrollPath, wire.EnrollRequest{
		Token: string(a.cfg.EnrollToken), CSR: string(csrPEM), Agent: info, IntervalS: int(a.cfg.Interval.Seconds()),
	}, &resp)
	if err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}
	cert, err := pair(keyPEM, []byte(resp.Certificate), resp.HostID)
	if err != nil {
		return err
	}
	id := &identity{HostID: resp.HostID, CAPin: pin, Cert: cert}
	if err := saveIdentity(a.cfg.DataDir, id, keyPEM, []byte(resp.Certificate)); err != nil {
		return fmt.Errorf("enrolled as %s but saving the identity failed (create a new token): %w", resp.HostID, err)
	}
	a.mu.Lock()
	a.id = id
	a.mu.Unlock()
	// The enrollment connection carries no client certificate; reports
	// must use a new one.
	a.closeIdle()
	a.log.Info("enrolled with the server", "host_id", resp.HostID, "name", info.Name)
	return nil
}

func (a *Agent) renewIfDue(ctx context.Context, now time.Time) error {
	a.mu.Lock()
	id := a.id
	a.mu.Unlock()
	if id.Cert.Leaf == nil || id.Cert.Leaf.NotAfter.Sub(now) > renewBefore {
		return nil
	}
	keyPEM, csrPEM, err := newKeyAndCSR(a.agentInfo().Name)
	if err != nil {
		return err
	}
	var resp wire.RenewResponse
	if err := a.post(ctx, wire.RenewPath, wire.RenewRequest{CSR: string(csrPEM)}, &resp); err != nil {
		return err
	}
	cert, err := pair(keyPEM, []byte(resp.Certificate), id.HostID)
	if err != nil {
		return err
	}
	next := &identity{HostID: id.HostID, CAPin: id.CAPin, Cert: cert}
	if err := saveIdentity(a.cfg.DataDir, next, keyPEM, []byte(resp.Certificate)); err != nil {
		// The server keeps accepting the old certificate until the new one
		// is used, so not switching is safe.
		return err
	}
	a.mu.Lock()
	a.id = next
	a.mu.Unlock()
	// New connections must present the new certificate.
	a.closeIdle()
	a.log.Info("client certificate renewed", "expires", cert.Leaf.NotAfter)
	return nil
}

func (a *Agent) report(ctx context.Context, ws []inventory.Workload, inv *string, hash string, full bool) (wire.ReportResponse, error) {
	rep := wire.Report{Agent: a.agentInfo(), IntervalS: int(a.cfg.Interval.Seconds()), SnapshotHash: hash, Images: a.images.take()}
	if full {
		if ws == nil {
			ws = []inventory.Workload{}
		}
		rep.Containers, rep.Inventory = &ws, inv
	}
	var resp wire.ReportResponse
	err := a.post(ctx, wire.ReportPath, rep, &resp)
	if err == nil {
		a.images.delivered(rep.Images)
	}
	return resp, err
}

func (a *Agent) post(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.cfg.ServerURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", buildinfo.UserAgent())
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		err := fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, e.Error)
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			err = fmt.Errorf("%w: %w", ErrRejected, err)
		}
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// snapshotHash identifies a snapshot, containers and host inventory,
// independent of collection order.
func snapshotHash(ws []inventory.Workload, inv *string) (string, error) {
	sorted := append([]inventory.Workload(nil), ws...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RuntimeID < sorted[j].RuntimeID })
	raw, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("encode snapshot: %w", err)
	}
	h := sha256.New()
	_, _ = h.Write(raw)
	if inv != nil {
		_, _ = h.Write([]byte("\x00inventory\x00"))
		_, _ = h.Write([]byte(*inv))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Healthy reports whether the agent delivered a report recently: within
// three intervals plus a minute.
func Healthy(cfg config.Agent, now time.Time) error {
	raw, err := os.ReadFile(filepath.Join(cfg.DataDir, LastReportFile)) //nolint:gosec // fixed path in the data directory
	if err != nil {
		return fmt.Errorf("no report delivered yet: %w", err)
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("unreadable report time: %w", err)
	}
	if age := now.Sub(t); age > 3*cfg.Interval+time.Minute {
		return fmt.Errorf("last report %s ago", age.Round(time.Second))
	}
	return nil
}

// PackageReader reads the package databases of the images of the agent's
// containers when the server asks for it, and hands them to the next
// report (ADR 0033).
func (a *Agent) PackageReader() *docker.PackageReader {
	return &docker.PackageReader{Store: a.images, Enabled: a.readImages.Load, Log: a.log}
}
