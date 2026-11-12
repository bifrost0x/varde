// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/varde/internal/buildinfo"
)

//go:embed agentinstall.sh
var agentInstallScript []byte

// AgentInstall is one installation of the agent over SSH (ADR 0031). The
// credentials are used for this one session and never stored.
type AgentInstall struct {
	// Target is host:port; HostKey the key the user confirmed.
	Target  string
	HostKey ssh.PublicKey
	User    string
	// Password signs in and, for a user other than root, answers sudo.
	Password string
	// PrivateKey (PEM or OpenSSH) and its Passphrase sign in instead.
	PrivateKey []byte
	Passphrase string
	// Docker lets the agent read the Docker API when the host has one,
	// which puts it into the docker group (root-equivalent).
	Docker bool
	// ServerURL is the agent listener as the host reaches it; Token the
	// one-time enrollment token.
	ServerURL string
	Token     string
	// Binary returns the agent binary for a platform ("linux/amd64").
	Binary func(platform string) (path string, ok bool)
}

// AgentInstallResult is what the installation found and did.
type AgentInstallResult struct {
	Platform string
	Init     string
	// Docker reports whether the agent reads the host's Docker API.
	Docker bool
	// Output is what the install script printed, bounded.
	Output string
	// KeptEnrollment is set when the host had an enrolled agent, which
	// keeps its identity: the installation only updated it.
	KeptEnrollment bool
	// Unreachable says why the host could not reach the server's agent
	// port when it was tested right after the installation; empty when it
	// could or was not tested.
	Unreachable string
}

// ErrInstallAuth is returned when the host rejects the credentials.
var ErrInstallAuth = errors.New("the host rejected the user name, password or key")

// probeCommand tells the platform, whether the user is root, whether a
// Docker socket exists and which init system runs.
const probeCommand = `uname -sm; id -u; if [ -S /var/run/docker.sock ]; then echo docker; else echo -; fi; ` +
	`if [ -d /run/systemd/system ]; then echo systemd; elif command -v openrc-run >/dev/null 2>&1; then echo openrc; else echo -; fi`

var tempDir = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)

// InstallAgent signs in once, uploads the agent binary, its configuration
// and the install script into a private temporary directory, and runs the
// script as root (directly, or with sudo). Nothing Varde sends ends up on a
// command line, so the token does not appear in the host's process list.
func InstallAgent(ctx context.Context, req AgentInstall, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (AgentInstallResult, error) {
	var res AgentInstallResult
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	c, err := installClient(ctx, req, dial)
	if err != nil {
		return res, err
	}
	defer func() { _ = c.Close() }()
	// Cancellation closes the connection, which ends every session.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()

	out, err := runSession(c, probeCommand, nil, 4096)
	if err != nil {
		return res, fmt.Errorf("read the platform: %w", err)
	}
	lines := strings.Fields(strings.ReplaceAll(out, "\n", " "))
	if len(lines) != 5 || lines[0] != "Linux" {
		return res, fmt.Errorf("the agent runs on Linux only; the host answered %q", truncateText(out, 120))
	}
	switch lines[1] {
	case "x86_64", "amd64":
		res.Platform = "linux/amd64"
	case "aarch64", "arm64":
		res.Platform = "linux/arm64"
	default:
		return res, fmt.Errorf("no agent binary for the %s architecture", lines[1])
	}
	root := lines[2] == "0"
	res.Docker = req.Docker && lines[3] == "docker"
	res.Init = lines[4]
	if res.Init != "systemd" && res.Init != "openrc" {
		return res, errors.New("the host runs neither systemd nor OpenRC; install the agent by hand (see the documentation)")
	}
	bin, ok := req.Binary(res.Platform)
	if !ok {
		return res, fmt.Errorf("this Varde server has no agent binary for %s", res.Platform)
	}
	binary, err := os.Open(bin) //nolint:gosec // the server's configured binary directory
	if err != nil {
		return res, fmt.Errorf("open agent binary: %w", err)
	}
	defer func() { _ = binary.Close() }()

	dir, err := runSession(c, "umask 077 && mktemp -d", nil, 512)
	if err != nil {
		return res, fmt.Errorf("create a temporary directory: %w", err)
	}
	dir = strings.TrimSpace(dir)
	if !tempDir.MatchString(dir) || strings.Contains(dir, "..") {
		return res, fmt.Errorf("unexpected temporary directory %q", truncateText(dir, 80))
	}
	done := false
	defer func() {
		if !done {
			_, _ = runSession(c, "rm -rf '"+dir+"'", nil, 512)
		}
	}()
	for _, f := range []struct {
		name string
		data io.Reader
	}{
		{"varde", binary},
		{"agent.env", strings.NewReader(agentEnv(req, res.Docker))},
		{"install.sh", bytes.NewReader(agentInstallScript)},
	} {
		if _, err := runSession(c, "cat > '"+dir+"/"+f.name+"'", f.data, 512); err != nil {
			return res, fmt.Errorf("upload %s: %w", f.name, err)
		}
	}
	cmd := "sh '" + dir + "/install.sh' '" + dir + "' " + res.Init
	var stdin io.Reader
	switch {
	case root:
	case req.Password != "":
		// sudo reads the password from stdin and prints no prompt.
		cmd, stdin = "sudo -S -p '' "+cmd, strings.NewReader(req.Password+"\n")
	default:
		cmd = "sudo -n " + cmd
	}
	out, err = runSession(c, cmd, stdin, 64<<10)
	res.Output = cleanOutput(out)
	if err != nil {
		if !root && strings.Contains(out, "sudo") {
			return res, fmt.Errorf("%s is not root and sudo refused; sign in as root or a user who may use sudo", req.User)
		}
		return res, fmt.Errorf("the installation failed: %w", err)
	}
	done = true // the script removed the directory
	res.KeptEnrollment = strings.Contains(out, "varde: kept the existing enrollment")
	res.Unreachable = unreachable(out)
	return res, nil
}

// unreachable returns the reason of a failed connection test in the install
// script's output ("varde: cannot reach https://…: <reason>"), bounded.
func unreachable(out string) string {
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "varde: cannot reach ")
		if !ok {
			continue
		}
		if _, reason, ok := strings.Cut(rest, ": "); ok {
			rest = reason
		}
		if r := []rune(rest); len(r) > 300 {
			rest = string(r[:300])
		}
		return rest
	}
	return ""
}

func installClient(ctx context.Context, req AgentInstall, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*ssh.Client, error) {
	var auths []ssh.AuthMethod
	if len(req.PrivateKey) > 0 {
		var signer ssh.Signer
		var err error
		if req.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(req.PrivateKey, []byte(req.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(req.PrivateKey)
		}
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("the key is protected by a passphrase; enter it")
		}
		if err != nil {
			return nil, errors.New("the private key cannot be read; paste it in OpenSSH or PEM format")
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if req.Password != "" {
		pw := req.Password
		auths = append(auths, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			answers := make([]string, len(qs))
			for i := range qs {
				answers[i] = pw
			}
			return answers, nil
		}))
	}
	if len(auths) == 0 {
		return nil, errors.New("enter a password or a private key")
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := dial(cctx, "tcp", req.Target)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", req.Target, err)
	}
	if dl, ok := cctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, req.Target, &ssh.ClientConfig{
		User: req.User, Auth: auths,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if !bytes.Equal(k.Marshal(), req.HostKey.Marshal()) {
				return ErrHostKeyChanged
			}
			return nil
		},
		HostKeyAlgorithms: hostKeyAlgorithms(req.HostKey),
		Timeout:           20 * time.Second,
	})
	if err != nil {
		_ = conn.Close()
		switch {
		case errors.Is(err, ErrHostKeyChanged):
			return nil, ErrHostKeyChanged
		case strings.Contains(err.Error(), "unable to authenticate"):
			return nil, ErrInstallAuth
		}
		return nil, fmt.Errorf("SSH to %s: %w", req.Target, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

// runSession runs one command and returns its combined output, at most
// limit bytes.
func runSession(c *ssh.Client, cmd string, stdin io.Reader, limit int) (string, error) {
	s, err := c.NewSession()
	if err != nil {
		return "", fmt.Errorf("open SSH session: %w", err)
	}
	defer func() { _ = s.Close() }()
	out := &limitedBuffer{max: limit}
	s.Stdout, s.Stderr, s.Stdin = out, out, stdin
	if err := s.Run(cmd); err != nil {
		if msg := strings.TrimSpace(out.String()); msg != "" {
			return out.String(), fmt.Errorf("%s", truncateText(cleanOutput(msg), 600))
		}
		return out.String(), err
	}
	return out.String(), nil
}

// agentEnv is the agent's configuration file. Every value is checked
// before; none may span lines.
func agentEnv(req AgentInstall, docker bool) string {
	p := buildinfo.EnvPrefix
	var b strings.Builder
	fmt.Fprintf(&b, "%sSERVER_URL=%s\n%sENROLL_TOKEN=%s\n%sDATA_DIR=/var/lib/varde-agent/data\n%sLOG_FORMAT=text\n",
		p, req.ServerURL, p, req.Token, p, p)
	if docker {
		fmt.Fprintf(&b, "%sDOCKER_HOST=unix:///var/run/docker.sock\n%sALLOW_DIRECT_SOCKET=true\n", p, p)
	} else {
		fmt.Fprintf(&b, "%sDOCKER_HOST=off\n", p)
	}
	return b.String()
}

// cleanOutput keeps printable text: the output is shown in the UI.
func cleanOutput(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return -1
	}, s)
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
