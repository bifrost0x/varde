// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func plainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

func TestBoxRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "k")
	b, err := OpenBox(path)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := b.Seal("a", []byte("secret"))
	if err != nil || bytes.Contains(sealed, []byte("secret")) {
		t.Fatalf("seal: %v", err)
	}
	b2, _ := OpenBox(path) // same key from disk
	if got, err := b2.Open("a", sealed); err != nil || string(got) != "secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := b2.Open("b", sealed); err == nil {
		t.Error("ciphertext must be bound to its integration ID")
	}
}

func fakeProxmox(t *testing.T, token string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(proxmoxHandler(token))
	srv.StartTLS()
	return srv
}

// fakeProxmoxOwnCert serves with a fresh certificate: httptest servers all
// share one built-in certificate.
func fakeProxmoxOwnCert(t *testing.T, token string) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(proxmoxHandler(token))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	return srv
}

func proxmoxHandler(token string) http.Handler {
	data := map[string]any{
		"/api2/json/version":            map[string]any{"version": "8.2.4"},
		"/api2/json/nodes":              []any{map[string]any{"node": "pve1", "status": "online"}},
		"/api2/json/nodes/pve1/network": []any{map[string]any{"address": "192.168.1.10"}, map[string]any{"address": ""}},
		"/api2/json/cluster/resources": []any{
			map[string]any{"type": "lxc", "vmid": 101, "name": "pihole", "node": "pve1", "status": "running", "tags": "dns;infra"},
			map[string]any{"type": "qemu", "vmid": 100, "name": "docker-vm", "node": "pve1", "status": "running"},
			map[string]any{"type": "qemu", "vmid": 9000, "name": "tmpl", "node": "pve1", "status": "stopped", "template": 1},
		},
		"/api2/json/nodes/pve1/lxc/101/interfaces": []any{
			map[string]any{"name": "lo", "inet": "127.0.0.1/8"},
			map[string]any{"name": "eth0", "inet": "192.168.1.53/24"},
		},
		"/api2/json/nodes/pve1/qemu/100/config": map[string]any{"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0"},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=varde@pve!varde="+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		path := r.URL.Path
		if r.URL.RawQuery != "" && path == "/api2/json/cluster/resources" && r.URL.Query().Get("type") != "vm" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.HasSuffix(path, "/agent/network-get-interfaces") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		d, ok := data[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": d})
	})
}

func TestProxmoxCollect(t *testing.T) {
	srv := fakeProxmox(t, "s3cret")
	defer srv.Close()
	fp, err := ServerFingerprint(t.Context(), srv.URL, plainDial)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(srv.Certificate().Raw)
	if fp != FormatFingerprint(sum[:]) {
		t.Fatalf("fingerprint %s", fp)
	}
	cfg := ProxmoxConfig{URL: srv.URL, TokenID: "varde@pve!varde", Fingerprint: fp}
	pc, err := NewProxmox(cfg, "s3cret", plainDial)
	if err != nil {
		t.Fatal(err)
	}
	st, err := pc.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != "8.2.4" || len(st.Nodes) != 1 || st.Nodes[0].Addresses[0] != "192.168.1.10" || len(st.Guests) != 2 {
		t.Fatalf("status %+v", st)
	}
	vm, ct := st.Guests[0], st.Guests[1]
	if vm.VMID != 100 || vm.Addresses != nil || !strings.Contains(vm.AddressNote, "VM.Monitor") {
		t.Errorf("vm %+v", vm)
	}
	if ct.VMID != 101 || len(ct.Addresses) != 1 || ct.Addresses[0] != "192.168.1.53" || len(ct.Tags) != 2 {
		t.Errorf("container %+v", ct)
	}

	// A different certificate is refused once a fingerprint is pinned.
	other := fakeProxmoxOwnCert(t, "s3cret")
	defer other.Close()
	pc, _ = NewProxmox(ProxmoxConfig{URL: other.URL, TokenID: "varde@pve!varde", Fingerprint: fp}, "s3cret", plainDial)
	if _, err := pc.Collect(t.Context()); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("pinned fingerprint not enforced: %v", err)
	}
	// A wrong token says so.
	pc, _ = NewProxmox(cfg, "wrong", plainDial)
	if _, err := pc.Collect(t.Context()); err == nil || !strings.Contains(err.Error(), "rejected the API token") {
		t.Errorf("wrong token: %v", err)
	}
}

func TestProxmoxInputValidation(t *testing.T) {
	for in, want := range map[string]string{"192.168.1.10": "https://192.168.1.10:8006", "https://pve.lan": "https://pve.lan:8006", "pve.lan:8443": "https://pve.lan:8443"} {
		u, err := ParseProxmoxURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%s: %v %v", in, u, err)
		}
	}
	if _, err := ParseProxmoxURL("http://pve.lan"); err == nil {
		t.Error("plain http accepted")
	}
	for _, id := range []string{"varde", "varde@pve", "var de@pve!x", "a@b!c=d"} {
		if validTokenID(id) {
			t.Errorf("token ID %q accepted", id)
		}
	}
}

// sshDocker runs an SSH server that only accepts the given key and serves
// a fake Docker API when the client runs dial-stdio.
type sshDocker struct {
	addr    string
	hostKey ssh.Signer
	mu      sync.Mutex
	cmds    []string
	// inventory, when set, is printed for the inventory command; fixed
	// holds the output of other forced commands by the name the client
	// sends.
	inventory []byte
	fixed     map[string][]byte
}

func newSSHDocker(t *testing.T, authorized ssh.PublicKey) *sshDocker {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	// A second host key of another type: Varde must still pick Ed25519.
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaSigner, _ := ssh.NewSignerFromKey(ek)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if c.User() == "varde" && bytes.Equal(k.Marshal(), authorized.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(ecdsaSigner)
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &sshDocker{addr: ln.Addr().String(), hostKey: hk}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/version":
			_, _ = io.WriteString(w, `{"Version":"27.3.1","ApiVersion":"1.47","MinAPIVersion":"1.24","Os":"linux","Arch":"amd64"}`)
		case strings.HasSuffix(r.URL.Path, "/info"):
			_, _ = io.WriteString(w, `{"Name":"dockerhost","OperatingSystem":"Debian GNU/Linux 12","Architecture":"x86_64"}`)
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			_, _ = io.WriteString(w, `[]`)
		case strings.HasSuffix(r.URL.Path, "/events"):
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg, api)
		}
	}()
	return s
}

func (s *sshDocker) serve(c net.Conn, cfg *ssh.ServerConfig, api http.Handler) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range creqs {
				if req.Type != "exec" || len(req.Payload) < 4 {
					_ = req.Reply(false, nil)
					continue
				}
				cmd := string(req.Payload[4 : 4+binary.BigEndian.Uint32(req.Payload)])
				s.mu.Lock()
				s.cmds = append(s.cmds, cmd)
				s.mu.Unlock()
				s.mu.Lock()
				inv := s.inventory
				if out, ok := s.fixed[cmd]; ok {
					inv = out
					cmd = "varde-inventory"
				}
				s.mu.Unlock()
				if inv != nil && cmd == "varde-inventory" {
					// Plays the forced command of the inventory key.
					_ = req.Reply(true, nil)
					_, _ = ch.Write(inv)
					_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					_ = ch.Close()
					continue
				}
				_ = req.Reply(cmd == DialStdio, nil)
				if cmd != DialStdio {
					continue
				}
				a, b := net.Pipe()
				go func() { _, _ = io.Copy(a, ch); _ = a.Close() }()
				go func() { _, _ = io.Copy(ch, a); _ = ch.Close() }()
				go func() { _ = (&http.Server{Handler: api, ReadHeaderTimeout: time.Second}).Serve(&oneConn{c: b}) }()
			}
		}()
	}
}

// oneConn is a listener that yields one connection.
type oneConn struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
	mu   sync.Mutex
}

func (l *oneConn) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.done == nil {
		l.done = make(chan struct{})
	}
	done := l.done
	l.mu.Unlock()
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return c, nil
	}
	<-done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done != nil {
		select {
		case <-l.done:
		default:
			close(l.done)
		}
	}
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.c.LocalAddr() }

func newManager(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(t.Context(), filepath.Join(dir, "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	m, err := New(Options{Store: st, DataDir: dir, Log: slog.New(slog.DiscardHandler),
		Scope: func() discovery.Scope { return discovery.Scope{} }})
	if err != nil {
		t.Fatal(err)
	}
	m.dialOverride = plainDial
	return m, st
}

func TestDockerSSHEndToEnd(t *testing.T) {
	m, st := newManager(t)
	srv := newSSHDocker(t, m.Identity().Signer.PublicKey())
	host, port, _ := net.SplitHostPort(srv.addr)
	if line := m.Identity().AuthorizedLine(); !strings.HasPrefix(line, `restrict,command="docker system dial-stdio" ssh-ed25519 `) {
		t.Fatalf("key line %q", line)
	}

	key, err := FetchHostKey(t.Context(), srv.addr, plainDial)
	if err != nil || !bytes.Equal(key.Marshal(), srv.hostKey.PublicKey().Marshal()) || KeyFile(key) != "/etc/ssh/ssh_host_ed25519_key.pub" {
		t.Fatalf("host key: %v (want the Ed25519 key)", err)
	}
	cfg := DockerSSHConfig{Address: host, User: "varde", HostKey: MarshalHostKey(key)}
	cfg.Port = atoi(port)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go m.Run(ctx)
	waitFor(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.ctx != nil })

	in, version, err := m.AddDockerSSH(t.Context(), cfg, "admin", time.Now())
	if err != nil || version != "27.3.1" {
		t.Fatalf("add: %q %v", version, err)
	}
	waitFor(t, func() bool {
		h, err := st.Host(t.Context(), "ssh-"+in.ID)
		return err == nil && h.IntegrationID == in.ID && h.Source == inventory.SourceSSH && h.Name == "dockerhost"
	})
	waitFor(t, func() bool {
		got, err := st.GetIntegration(t.Context(), in.ID)
		return err == nil && got.LastSuccess != nil && strings.Contains(string(got.Status), `"containers":0`)
	})
	srv.mu.Lock()
	for _, c := range srv.cmds {
		if c != DialStdio {
			t.Errorf("ran %q on the host", c)
		}
	}
	srv.mu.Unlock()

	if err := m.Remove(t.Context(), in.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Host(t.Context(), "ssh-"+in.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("host kept after removal: %v", err)
	}
}

func TestDockerSSHRejects(t *testing.T) {
	m, _ := newManager(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	srv := newSSHDocker(t, otherSigner.PublicKey()) // Varde's key not authorised
	host, port, _ := net.SplitHostPort(srv.addr)
	key, _ := FetchHostKey(t.Context(), srv.addr, plainDial)
	cfg := DockerSSHConfig{Address: host, Port: atoi(port), User: "varde", HostKey: MarshalHostKey(key)}
	if _, _, err := m.AddDockerSSH(t.Context(), cfg, "admin", time.Now()); err == nil || !strings.Contains(err.Error(), "authorized_keys") {
		t.Errorf("unauthorised key: %v", err)
	}
	cfg.HostKey = MarshalHostKey(otherSigner.PublicKey()) // wrong pin
	if _, _, err := m.AddDockerSSH(t.Context(), cfg, "admin", time.Now()); !errors.Is(err, ErrHostKeyChanged) {
		t.Errorf("changed host key: %v", err)
	}
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// TestTriggerIntegration: "Read now" reaches only the chosen integration.
func TestTriggerIntegration(t *testing.T) {
	m := &Manager{running: map[string]*runner{}}
	var a, b int
	m.running["a"] = &runner{trigger: func() { a++ }}
	m.running["b"] = &runner{trigger: func() { b++ }}
	if !m.TriggerIntegration("a") || a != 1 || b != 0 {
		t.Fatalf("trigger a: ok, a=%d b=%d", a, b)
	}
	if m.TriggerIntegration("missing") {
		t.Error("an integration that is not running reported as triggered")
	}
}

// The last scan result survives a restart; it used to live only in memory
// while the devices stayed in the database.
func TestLastScanSurvivesRestart(t *testing.T) {
	m, st := newManager(t)
	ended := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	if err := st.RecordScanRun(t.Context(), store.ScanRun{Trigger: "manual", Networks: "10.0.0.0/24", Started: ended.Add(-time.Minute), Ended: ended, Addresses: 254, Found: 7}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go m.Run(ctx)
	waitFor(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.ctx != nil })
	if s := m.Scan(); s.Running || s.Found != 7 || !s.Ended.Equal(ended) {
		t.Errorf("scan state after start: %+v", s)
	}
	if m.Interval(KindProxmox) <= 0 || m.Interval(KindDockerSSH) <= 0 || m.Interval("other") != 0 {
		t.Error("intervals")
	}
}

func TestScheduledScanDue(t *testing.T) {
	m, _ := newManager(t)
	now := time.Now()
	every := time.Duration(0)
	m.o.ScanEvery = func() time.Duration { return every }
	m.scan = ScanState{Ended: now.Add(-7 * time.Hour)}
	if m.scheduledScanDue(now) {
		t.Error("due while scheduled scans are off")
	}
	every = 6 * time.Hour
	if !m.scheduledScanDue(now) {
		t.Error("not due 7 hours after the last scan")
	}
	m.scan.Ended = now.Add(-time.Hour)
	if m.scheduledScanDue(now) {
		t.Error("due one hour after the last scan")
	}
	m.scan = ScanState{Running: true, Started: now.Add(-10 * time.Hour)}
	if m.scheduledScanDue(now) {
		t.Error("due while a scan runs")
	}
	// Never scanned: the first scheduled scan starts at once.
	m.scan = ScanState{}
	if !m.scheduledScanDue(now) {
		t.Error("not due without any scan")
	}
}

func TestGuestMACPattern(t *testing.T) {
	for in, want := range map[string]string{
		"virtio=BC:24:11:5A:6B:7C": "BC:24:11:5A:6B:7C",
		"hwaddr=BC:24:11:00:11:22": "BC:24:11:00:11:22",
		"e1000=02:00:00:00:00:01":  "02:00:00:00:00:01",
		"bridge=vmbr0":             "",
		"ip=10.0.0.5/24":           "",
	} {
		m := guestMAC.FindStringSubmatch(in)
		got := ""
		if m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}
