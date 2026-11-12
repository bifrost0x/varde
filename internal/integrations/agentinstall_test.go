// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// installHost plays a host for the push installation: it answers the probe
// and the temporary directory, keeps what is uploaded, and records every
// command with its input.
type installHost struct {
	addr    string
	hostKey ssh.Signer
	probe   string
	// installExit and installOut are the exit status and output of the
	// install script.
	installExit uint32
	installOut  string

	mu    sync.Mutex
	cmds  []string
	files map[string][]byte
	input map[string]string
}

const installDir = "/tmp/tmp.Xk3fQ9"

// installToken stands for the enrollment token; it is not one.
const installToken = "test-enrollment-token"

func newInstallHost(t *testing.T, probe string) *installHost {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, _ := ssh.NewSignerFromKey(priv)
	h := &installHost{hostKey: hk, probe: probe, files: map[string][]byte{}, input: map[string]string{},
		installOut: "varde: agent installed\n"}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if (c.User() == "admin" || c.User() == "root") && string(pw) == "s3cret pass" {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.serve(c, cfg)
		}
	}()
	return h
}

func (h *installHost) serve(c net.Conn, cfg *ssh.ServerConfig) {
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
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				cmd := string(req.Payload[4 : 4+binary.BigEndian.Uint32(req.Payload)])
				_ = req.Reply(true, nil)
				in, _ := io.ReadAll(ch)
				h.mu.Lock()
				h.cmds = append(h.cmds, cmd)
				h.input[cmd] = string(in)
				var out string
				var status uint32
				switch {
				case cmd == probeCommand:
					out = h.probe
				case cmd == "umask 077 && mktemp -d":
					out = installDir + "\n"
				case strings.HasPrefix(cmd, "cat > '"+installDir+"/"):
					h.files[strings.TrimSuffix(strings.TrimPrefix(cmd, "cat > '"+installDir+"/"), "'")] = in
				case strings.Contains(cmd, "install.sh"):
					out, status = h.installOut, h.installExit
					if status != 0 {
						out = "useradd: cannot lock /etc/passwd\n"
					}
				}
				h.mu.Unlock()
				_, _ = ch.Write([]byte(out))
				_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
				_ = ch.Close()
			}
		}()
	}
}

func installRequest(t *testing.T, h *installHost, user string) AgentInstall {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "varde-linux-amd64")
	if err := os.WriteFile(bin, []byte("agent binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	return AgentInstall{
		Target: h.addr, HostKey: h.hostKey.PublicKey(), User: user, Password: "s3cret pass", Docker: true,
		ServerURL: "https://varde.lan:8443", Token: installToken,
		Binary: func(p string) (string, bool) { return bin, p == "linux/amd64" },
	}
}

func TestInstallAgentWithSudo(t *testing.T) {
	h := newInstallHost(t, "Linux x86_64\n1000\ndocker\nsystemd\n")
	res, err := InstallAgent(t.Context(), installRequest(t, h, "admin"), plainDial)
	if err != nil {
		t.Fatal(err)
	}
	if res.Platform != "linux/amd64" || res.Init != "systemd" || !res.Docker || !strings.Contains(res.Output, "agent installed") {
		t.Fatalf("result: %+v", res)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if string(h.files["varde"]) != "agent binary" || !bytes.Equal(h.files["install.sh"], agentInstallScript) {
		t.Fatalf("uploads: %v", h.files)
	}
	env := string(h.files["agent.env"])
	for _, want := range []string{"VARDE_SERVER_URL=https://varde.lan:8443\n", "VARDE_ENROLL_TOKEN=" + installToken + "\n",
		"VARDE_DOCKER_HOST=unix:///var/run/docker.sock\n", "VARDE_ALLOW_DIRECT_SOCKET=true\n", "VARDE_DATA_DIR=/var/lib/varde-agent/data\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("agent.env lacks %q:\n%s", want, env)
		}
	}
	last := h.cmds[len(h.cmds)-1]
	if last != "sudo -S -p '' sh '"+installDir+"/install.sh' '"+installDir+"' systemd" {
		t.Fatalf("install command: %q", last)
	}
	// sudo gets the password on stdin; no command line carries a secret.
	if h.input[last] != "s3cret pass\n" {
		t.Fatalf("sudo input: %q", h.input[last])
	}
	for _, c := range h.cmds {
		if strings.Contains(c, "s3cret") || strings.Contains(c, installToken) {
			t.Fatalf("secret on a command line: %q", c)
		}
	}
}

func TestInstallAgentAsRootWithoutDocker(t *testing.T) {
	h := newInstallHost(t, "Linux x86_64\n0\n-\nopenrc\n")
	res, err := InstallAgent(t.Context(), installRequest(t, h, "root"), plainDial)
	if err != nil {
		t.Fatal(err)
	}
	if res.Docker || res.Init != "openrc" || res.KeptEnrollment {
		t.Fatalf("result: %+v", res)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if last := h.cmds[len(h.cmds)-1]; last != "sh '"+installDir+"/install.sh' '"+installDir+"' openrc" {
		t.Fatalf("install command: %q", last)
	}
	env := string(h.files["agent.env"])
	if !strings.Contains(env, "VARDE_DOCKER_HOST=off\n") || strings.Contains(env, "ALLOW_DIRECT_SOCKET") {
		t.Fatalf("agent.env:\n%s", env)
	}
}

func TestInstallAgentRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, probe string
		mutate      func(*AgentInstall)
		want        string
	}{
		{"wrong password", "Linux x86_64\n0\n-\nsystemd\n", func(r *AgentInstall) { r.Password = "wrong" }, "rejected"},
		{"other host key", "Linux x86_64\n0\n-\nsystemd\n", func(r *AgentInstall) {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			s, _ := ssh.NewSignerFromKey(priv)
			r.HostKey = s.PublicKey()
		}, "host key changed"},
		{"not linux", "FreeBSD amd64\n0\n-\n-\n", nil, "Linux only"},
		{"unknown architecture", "Linux riscv64\n0\n-\nsystemd\n", nil, "riscv64"},
		{"no binary", "Linux aarch64\n0\n-\nsystemd\n", nil, "no agent binary for linux/arm64"},
		{"no init system", "Linux x86_64\n0\n-\n-\n", nil, "neither systemd nor OpenRC"},
		{"no credentials", "Linux x86_64\n0\n-\nsystemd\n", func(r *AgentInstall) { r.Password = "" }, "password or a private key"},
		{"bad key", "Linux x86_64\n0\n-\nsystemd\n", func(r *AgentInstall) { r.Password, r.PrivateKey = "", []byte("not a key") }, "cannot be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newInstallHost(t, tc.probe)
			req := installRequest(t, h, "root")
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			_, err := InstallAgent(t.Context(), req, plainDial)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.files) != 0 {
				t.Fatalf("uploaded although refused: %v", h.files)
			}
		})
	}
}

func TestInstallAgentFailureCleansUp(t *testing.T) {
	h := newInstallHost(t, "Linux x86_64\n0\n-\nsystemd\n")
	h.installExit = 1
	res, err := InstallAgent(t.Context(), installRequest(t, h, "root"), plainDial)
	if err == nil || !strings.Contains(err.Error(), "cannot lock") || !strings.Contains(res.Output, "cannot lock") {
		t.Fatalf("err = %v, output %q", err, res.Output)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if last := h.cmds[len(h.cmds)-1]; last != "rm -rf '"+installDir+"'" {
		t.Fatalf("temporary directory not removed: %q", last)
	}
}

func TestAgentInstallScriptSyntax(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	f := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(f, agentInstallScript, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil { //nolint:gosec // test file
		t.Fatalf("sh -n: %v: %s", err, out)
	}
}

// Installing again updates the agent; an enrolled one keeps its identity.
func TestInstallAgentAgain(t *testing.T) {
	h := newInstallHost(t, "Linux x86_64\n0\n-\nsystemd\n")
	h.installOut = "varde: kept the existing enrollment\nvarde: agent installed\n"
	res, err := InstallAgent(t.Context(), installRequest(t, h, "root"), plainDial)
	if err != nil || !res.KeptEnrollment {
		t.Fatalf("err %v, result %+v", err, res)
	}
}

func TestUnreachable(t *testing.T) {
	out := "varde: kept nothing\nvarde: cannot reach https://10.10.2.150:8443: no answer within 5s (a firewall or router drops the connection)\nvarde: agent installed\n"
	if got := unreachable(out); got != "no answer within 5s (a firewall or router drops the connection)" {
		t.Fatalf("got %q", got)
	}
	if got := unreachable("varde: reaches https://10.10.2.150:8443\nvarde: agent installed\n"); got != "" {
		t.Fatalf("reachable: %q", got)
	}
}
