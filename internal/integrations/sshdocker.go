// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// KindDockerSSH is a Docker host read through the Docker Engine API over
// SSH, the transport the Docker CLI itself uses for ssh:// hosts: the
// remote side runs "docker system dial-stdio" and the API is spoken over
// the session.
const KindDockerSSH = "docker-ssh"

// DialStdio is the only command Varde runs on a Docker host. The key line
// shown to the user forces it, so the key cannot run anything else.
const DialStdio = "docker system dial-stdio"

// DockerSSHConfig is the non-secret part of a Docker-over-SSH integration.
type DockerSSHConfig struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	// HostKey pins the server's host key (authorized_keys format).
	HostKey string `json:"host_key"`
}

// Target returns host:port.
func (c DockerSSHConfig) Target() string {
	return net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
}

// Validate checks the user-supplied fields.
func (c DockerSSHConfig) Validate() error {
	if c.Address == "" || strings.ContainsAny(c.Address, " /@") {
		return errors.New("enter the host address, for example 192.168.1.20")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("the SSH port is between 1 and 65535")
	}
	if c.User == "" || len(c.User) > 32 || strings.ContainsAny(c.User, " :@/\\'\"") {
		return errors.New("enter the user name Varde signs in as")
	}
	return nil
}

// Identity is Varde's own SSH key. One key serves every host; it only works
// where the user added the restricted key line.
type Identity struct {
	Signer ssh.Signer
}

// LoadIdentity reads the key from path, creating an Ed25519 key (mode 0600)
// on first use.
func LoadIdentity(path string) (*Identity, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path from configuration
	if errors.Is(err, os.ErrNotExist) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, fmt.Errorf("generate SSH key: %w", gerr)
		}
		block, merr := ssh.MarshalPrivateKey(priv, "varde")
		if merr != nil {
			return nil, fmt.Errorf("encode SSH key: %w", merr)
		}
		raw = pem.EncodeToMemory(block)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create key directory: %w", err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return nil, fmt.Errorf("write SSH key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("read SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key %s: %w", path, err)
	}
	return &Identity{Signer: signer}, nil
}

// AuthorizedLine is the line the user adds to ~/.ssh/authorized_keys on a
// Docker host. "restrict" disables forwarding, PTY and agent; the forced
// command limits the key to the Docker API stream.
func (id *Identity) AuthorizedLine() string {
	return `restrict,command="` + DialStdio + `" ` + id.publicKey() + ` varde`
}

func (id *Identity) publicKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(id.Signer.PublicKey())))
}

// Fingerprint is the SHA-256 fingerprint of a public key, as ssh-keygen -l
// shows it.
func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// preferredHostKeys asks the server for its Ed25519 key first: it is the
// key type every current OpenSSH has, and the one the setup page tells the
// user to compare.
var preferredHostKeys = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// hostKeyAlgorithms limits a connection to the type of the pinned key, so a
// server cannot fall back to another key the user never confirmed.
func hostKeyAlgorithms(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{k.Type()}
}

// KeyFile names the host key file of a key type under /etc/ssh, for the
// comparison command shown to the user.
func KeyFile(k ssh.PublicKey) string {
	switch {
	case k.Type() == ssh.KeyAlgoED25519:
		return "/etc/ssh/ssh_host_ed25519_key.pub"
	case strings.HasPrefix(k.Type(), "ecdsa-"):
		return "/etc/ssh/ssh_host_ecdsa_key.pub"
	}
	return "/etc/ssh/ssh_host_rsa_key.pub"
}

// ParseHostKey reads a pinned host key.
func ParseHostKey(s string) (ssh.PublicKey, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, errors.New("invalid host key")
	}
	return k, nil
}

// ErrHostKeyChanged is returned when a host presents another key than the
// one the user confirmed.
var ErrHostKeyChanged = errors.New("the host key changed since it was confirmed; if the host was reinstalled, remove and add the integration again")

// FetchHostKey connects to target and returns the host key it presents,
// without authenticating. The user compares its fingerprint before Varde
// trusts it.
func FetchHostKey(ctx context.Context, target string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (ssh.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	var key ssh.PublicKey
	errStop := errors.New("host key read")
	_, _, _, err = ssh.NewClientConn(conn, target, &ssh.ClientConfig{
		User: "varde",
		Auth: []ssh.AuthMethod{},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errStop
		},
		HostKeyAlgorithms: preferredHostKeys,
		Timeout:           10 * time.Second,
	})
	if key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("no SSH server answered on %s: %w", target, err)
}

// DockerSSH keeps one SSH connection to a Docker host and opens a
// dial-stdio session for every Docker API connection.
type DockerSSH struct {
	cfg  DockerSSHConfig
	key  ssh.PublicKey
	id   *Identity
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	mu     sync.Mutex
	client *ssh.Client
}

// NewDockerSSH returns a connector; it connects lazily.
func NewDockerSSH(cfg DockerSSHConfig, id *Identity, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*DockerSSH, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	key, err := ParseHostKey(cfg.HostKey)
	if err != nil {
		return nil, err
	}
	return &DockerSSH{cfg: cfg, key: key, id: id, dial: dial}, nil
}

func (d *DockerSSH) connect(ctx context.Context) (*ssh.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client != nil {
		return d.client, nil
	}
	target := d.cfg.Target()
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.dial(cctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", target, err)
	}
	if dl, ok := cctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, target, &ssh.ClientConfig{
		User: d.cfg.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(d.id.Signer)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if !bytes.Equal(k.Marshal(), d.key.Marshal()) {
				return ErrHostKeyChanged
			}
			return nil
		},
		HostKeyAlgorithms: hostKeyAlgorithms(d.key),
		Timeout:           15 * time.Second,
	})
	if err != nil {
		_ = conn.Close()
		if errors.Is(err, ErrHostKeyChanged) {
			return nil, ErrHostKeyChanged
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, fmt.Errorf("%s rejected Varde's key: add the key line to ~%s/.ssh/authorized_keys", target, d.cfg.User)
		}
		return nil, fmt.Errorf("SSH to %s: %w", target, err)
	}
	_ = conn.SetDeadline(time.Time{})
	d.client = ssh.NewClient(c, chans, reqs)
	go func(cl *ssh.Client) {
		_ = cl.Wait()
		d.mu.Lock()
		if d.client == cl {
			d.client = nil
		}
		d.mu.Unlock()
	}(d.client)
	return d.client, nil
}

// DialDocker opens a stream to the Docker Engine API on the host.
func (d *DockerSSH) DialDocker(ctx context.Context) (net.Conn, error) {
	c, err := d.connect(ctx)
	if err != nil {
		return nil, err
	}
	s, err := c.NewSession()
	if err != nil {
		d.reset(c)
		return nil, fmt.Errorf("open SSH session: %w", err)
	}
	stdin, err := s.StdinPipe()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	stderr := &limitedBuffer{max: 2048}
	s.Stderr = stderr
	if err := s.Start(DialStdio); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("start %q: %w", DialStdio, err)
	}
	return &stdioConn{s: s, r: stdout, w: stdin, stderr: stderr, remote: d.cfg.Target()}, nil
}

func (d *DockerSSH) reset(c *ssh.Client) {
	d.mu.Lock()
	if d.client == c {
		d.client = nil
	}
	d.mu.Unlock()
	_ = c.Close()
}

// Close ends the SSH connection.
func (d *DockerSSH) Close() {
	d.mu.Lock()
	c := d.client
	d.client = nil
	d.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// stdioConn adapts an SSH session running dial-stdio to net.Conn.
type stdioConn struct {
	s      *ssh.Session
	r      io.Reader
	w      io.WriteCloser
	stderr *limitedBuffer
	remote string
	once   sync.Once
}

func (c *stdioConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if errors.Is(err, io.EOF) && n == 0 {
		if msg := strings.TrimSpace(c.stderr.String()); msg != "" {
			return 0, fmt.Errorf("%s on %s: %s", DialStdio, c.remote, dockerHint(msg))
		}
	}
	return n, err
}

func (c *stdioConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *stdioConn) Close() error {
	var err error
	c.once.Do(func() {
		_ = c.w.Close()
		err = c.s.Close()
		if errors.Is(err, io.EOF) {
			err = nil
		}
	})
	return err
}

func (c *stdioConn) LocalAddr() net.Addr              { return stdioAddr("varde") }
func (c *stdioConn) RemoteAddr() net.Addr             { return stdioAddr(c.remote) }
func (c *stdioConn) SetDeadline(time.Time) error      { return nil }
func (c *stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stdioConn) SetWriteDeadline(time.Time) error { return nil }

type stdioAddr string

func (a stdioAddr) Network() string { return "ssh" }
func (a stdioAddr) String() string  { return string(a) }

// dockerHint turns the common failures of dial-stdio into a next step.
func dockerHint(msg string) string {
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "permission denied"):
		return "the user may not access Docker; add it to the docker group (" + msg + ")"
	case strings.Contains(l, "not found"):
		return "the Docker CLI is not installed on the host (" + msg + ")"
	}
	return msg
}

type limitedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
	// truncated is set once more than max bytes were written.
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	room := b.max - b.buf.Len()
	switch {
	case len(p) > room:
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
	default:
		b.buf.Write(p)
	}
	return len(p), nil
}

func (b *limitedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// MarshalHostKey renders a host key for storage (authorized_keys format).
func MarshalHostKey(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}
