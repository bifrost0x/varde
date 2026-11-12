// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Execute the installer with all filesystem destinations redirected into a
// temporary directory. A service-manager stub replaces the installed binary
// at restart, modelling the service user's ability to change its own bin.
func TestAgentInstallDiagnosticUsesTrustedUpload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("installer uses POSIX filesystem paths")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, init := range []string{"systemd", "openrc"} {
		for _, enrolled := range []bool{false, true} {
			for _, tc := range []struct {
				checkExit    int
				noexec       bool
				stageFailure string
			}{{0, false, ""}, {1, false, ""}, {0, true, ""}, {0, false, "mktemp"}, {0, false, "install"}} {
				t.Run(fmt.Sprintf("%s/enrolled=%v/check=%d/noexec=%v/staging=%s", init, enrolled, tc.checkExit, tc.noexec, tc.stageFailure), func(t *testing.T) {
					root := t.TempDir()
					home, src, stubs := filepath.Join(root, "home"), filepath.Join(root, "upload"), filepath.Join(root, "stubs")
					for _, dir := range []string{home, src, stubs} {
						if err := os.MkdirAll(dir, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					write := func(path, content string, mode os.FileMode) {
						t.Helper()
						if err := os.WriteFile(path, []byte(content), mode); err != nil {
							t.Fatal(err)
						}
					}
					if tc.noexec {
						var err error
						src, err = os.MkdirTemp("/dev/shm", "varde-upload-")
						if err != nil {
							t.Skipf("no shared-memory upload directory: %v", err)
						}
						t.Cleanup(func() { _ = os.RemoveAll(src) })
						probe := filepath.Join(src, "probe")
						write(probe, "#!/bin/sh\nexit 0\n", 0o700)
						if err := exec.CommandContext(t.Context(), probe).Run(); !errors.Is(err, os.ErrPermission) { //nolint:gosec // known harmless fixture
							t.Skipf("shared-memory filesystem is not noexec: %v", err)
						}
					}
					if enrolled {
						if err := os.MkdirAll(filepath.Join(home, "data"), 0o700); err != nil {
							t.Fatal(err)
						}
						write(filepath.Join(home, "data", "agent.json"), "{}", 0o600)
					}
					trusted, hostile := filepath.Join(root, "trusted"), filepath.Join(root, "hostile")
					invoked := filepath.Join(root, "invoked-path")
					// Uploads arrive through cat and are not executable initially.
					write(filepath.Join(src, "varde"), "#!/bin/sh\nprintf '%s %s' \"$1\" \"$VARDE_SERVER_URL\" > \"$TRUSTED_MARKER\"\nprintf '%s' \"$0\" > \"$INVOKED_PATH\"\necho diagnostic-output\nexit \"$CHECK_EXIT\"\n", 0o600)
					write(filepath.Join(src, "agent.env"), "VARDE_SERVER_URL=https://varde.example:8443\nVARDE_DOCKER_HOST=off\n", 0o600)
					write(filepath.Join(root, "payload"), "#!/bin/sh\necho executed > \"$HOSTILE_MARKER\"\n", 0o700)
					write(filepath.Join(stubs, "id"), "#!/bin/sh\nif [ \"${1:-}\" = -gn ]; then echo testgroup; fi\n", 0o700)
					write(filepath.Join(stubs, "install"), `#!/bin/sh
set -eu
directory=no
mode=0755
while [ "$#" -gt 0 ]; do
 case "$1" in
 -d) directory=yes; shift;;
 -m) mode=$2; shift 2;;
 -o|-g) shift 2;;
 *) break;;
 esac
done
if [ "${FAIL_STAGE:-}" = install ] && [ "$mode" = 0700 ]; then exit 1; fi
if [ "$directory" = yes ]; then mkdir -p "$@"; else cp "$1" "$2"; chmod "$mode" "$2"; fi
`, 0o700)
					write(filepath.Join(stubs, "mktemp"), "#!/bin/sh\nif [ \"${FAIL_STAGE:-}\" = mktemp ]; then exit 1; fi\nexec /usr/bin/mktemp \"$@\"\n", 0o700)
					for _, name := range []string{"systemctl", "rc-service"} {
						write(filepath.Join(stubs, name), "#!/bin/sh\nfor arg do\n if [ \"$arg\" = restart ]; then cp \"$PAYLOAD\" \"$AGENT_BIN\"; chmod 0750 \"$AGENT_BIN\"; fi\ndone\n", 0o700)
					}
					for _, name := range []string{"rc-update", "sleep"} {
						write(filepath.Join(stubs, name), "#!/bin/sh\nexit 0\n", 0o700)
					}
					script := strings.NewReplacer("/var/lib/varde-agent", home,
						"/etc/varde-agent.env", filepath.Join(root, "agent.env"),
						"/etc/systemd/system/varde-agent.service", filepath.Join(root, "agent.service"),
						"/etc/init.d/varde-agent", filepath.Join(root, "agent.openrc")).Replace(string(agentInstallScript))
					installer := filepath.Join(root, "install.sh")
					write(installer, script, 0o600)
					cmd := exec.CommandContext(t.Context(), sh, installer, src, init) //nolint:gosec // isolated fixture, no host paths
					cmd.Env = append(os.Environ(), "PATH="+stubs+":/usr/bin:/bin", "PAYLOAD="+filepath.Join(root, "payload"),
						"AGENT_BIN="+filepath.Join(home, "bin", "varde"), "TRUSTED_MARKER="+trusted, "HOSTILE_MARKER="+hostile,
						"INVOKED_PATH="+invoked, "FAIL_STAGE="+tc.stageFailure, fmt.Sprintf("CHECK_EXIT=%d", tc.checkExit))
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("installer failed: %v: %s", err, out)
					}
					if _, err := os.Stat(hostile); !os.IsNotExist(err) {
						t.Errorf("installer executed agent-controlled binary: %v", err)
					}
					got, err := os.ReadFile(trusted)
					switch {
					case enrolled:
						if !os.IsNotExist(err) || !strings.Contains(string(out), "kept the existing enrollment") {
							t.Fatalf("existing enrollment not retained: %v %s", err, out)
						}
					case tc.stageFailure != "":
						if !os.IsNotExist(err) || !strings.Contains(string(out), "connectivity check skipped") || !strings.Contains(string(out), "agent installed") {
							t.Errorf("diagnostic staging failure must not fail installation: %q %v %s", got, err, out)
						}
					case err != nil || string(got) != "check-server https://varde.example:8443" || !strings.Contains(string(out), "diagnostic-output"):
						t.Errorf("trusted diagnostic not run with configured environment: %q %v %s", got, err, out)
					}
					if !enrolled && err == nil {
						path, err := os.ReadFile(invoked)
						if err != nil || filepath.Dir(string(path)) != home || !strings.HasPrefix(filepath.Base(string(path)), ".varde-check.") {
							t.Errorf("diagnostic must run from root-controlled executable staging: %q %v", path, err)
						}
					}
					staged, err := filepath.Glob(filepath.Join(home, ".varde-check.*"))
					if err != nil || len(staged) != 0 {
						t.Errorf("diagnostic staging not cleaned: %v %v", staged, err)
					}
					if _, err := os.Stat(src); !os.IsNotExist(err) {
						t.Errorf("upload directory not cleaned: %v", err)
					}
				})
			}
		}
	}
}

// An identity on the host only counts when the installing server knows it.
// One from another Varde server, or one revoked here, would keep the agent
// silent for good: the installer sets it aside and the agent enrolls anew.
func TestAgentInstallReplacesUnknownEnrollment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("installer uses POSIX filesystem paths")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, tc := range []struct {
		name, known string
		list        bool
		kept        bool
	}{
		{"known to this server", "other-1\nhost-abc\n", true, true},
		{"of another server", "other-1\nother-2\n", true, false},
		{"no agent known", "", true, false},
		{"a prefix is not a match", "host-abcd\nhost-ab\n", true, false},
		{"older server sends no list", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home, src, stubs := filepath.Join(root, "home"), filepath.Join(root, "upload"), filepath.Join(root, "stubs")
			for _, dir := range []string{filepath.Join(home, "data"), src, stubs} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, content string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(home, "data", "agent.json"), `{"host_id": "host-abc", "ca_pin": "aa"}`, 0o600)
			write(filepath.Join(home, "data", "identity.pem"), "old identity", 0o600)
			write(filepath.Join(src, "varde"), "#!/bin/sh\necho checked\n", 0o600)
			write(filepath.Join(src, "agent.env"), "VARDE_SERVER_URL=https://varde.example:8443\nVARDE_DOCKER_HOST=off\n", 0o600)
			if tc.list {
				write(filepath.Join(src, "known-agents"), tc.known, 0o600)
			}
			write(filepath.Join(stubs, "id"), "#!/bin/sh\nif [ \"${1:-}\" = -gn ]; then echo testgroup; fi\n", 0o700)
			write(filepath.Join(stubs, "install"), "#!/bin/sh\nset -eu\ndirectory=no\nmode=0755\nwhile [ \"$#\" -gt 0 ]; do\n case \"$1\" in\n -d) directory=yes; shift;;\n -m) mode=$2; shift 2;;\n -o|-g) shift 2;;\n *) break;;\n esac\ndone\nif [ \"$directory\" = yes ]; then mkdir -p \"$@\"; else cp \"$1\" \"$2\"; chmod \"$mode\" \"$2\"; fi\n", 0o700)
			for _, name := range []string{"systemctl", "rc-update", "rc-service", "sleep"} {
				write(filepath.Join(stubs, name), "#!/bin/sh\nexit 0\n", 0o700)
			}
			script := strings.NewReplacer("/var/lib/varde-agent", home,
				"/etc/varde-agent.env", filepath.Join(root, "agent.env"),
				"/etc/systemd/system/varde-agent.service", filepath.Join(root, "agent.service"),
				"/etc/init.d/varde-agent", filepath.Join(root, "agent.openrc")).Replace(string(agentInstallScript))
			installer := filepath.Join(root, "install.sh")
			write(installer, script, 0o600)
			cmd := exec.CommandContext(t.Context(), sh, installer, src, "systemd") //nolint:gosec // isolated fixture, no host paths
			cmd.Env = append(os.Environ(), "PATH="+stubs+":/usr/bin:/bin")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("installer failed: %v: %s", err, out)
			}
			_, statErr := os.Stat(filepath.Join(home, "data", "agent.json"))
			kept := statErr == nil
			if kept != tc.kept {
				t.Fatalf("identity kept = %v, want %v\n%s", kept, tc.kept, out)
			}
			keptMsg, againMsg := strings.Contains(string(out), "kept the existing enrollment"), strings.Contains(string(out), "enrolling again")
			if keptMsg != tc.kept || againMsg == tc.kept {
				t.Errorf("output does not say what happened (kept=%v):\n%s", tc.kept, out)
			}
			if !tc.kept {
				// The old identity is set aside, not lost, and the new agent
				// is tested like a first installation.
				if b, err := os.ReadFile(filepath.Join(home, "data.stale", "identity.pem")); err != nil || string(b) != "old identity" {
					t.Errorf("old identity not set aside: %q %v", b, err)
				}
				if !strings.Contains(string(out), "checked") {
					t.Errorf("the new enrollment was not tested:\n%s", out)
				}
			}
		})
	}
}

func TestKnownAgentsUpload(t *testing.T) {
	if got := knownAgents([]string{"a-1", "", "b c", "x\ny", "d_2"}); got != "a-1\nd_2\n" {
		t.Errorf("known agents = %q", got)
	}
}
