// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"os/exec"
	"strings"
	"testing"
)

const testLine = `restrict,command="sh -c 'cat /etc/os-release; echo $HOME'" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx0ZXN0a2V5 varde-inventory`

func TestInstallCommand(t *testing.T) {
	cmd := InstallCommand("varde", testLine, false)
	// The line reaches the file unchanged through a quoted here-document.
	if !strings.Contains(cmd, "<<'VARDE_KEY'\n"+testLine+"\nVARDE_KEY\n") {
		t.Fatalf("line not passed verbatim:\n%s", cmd)
	}
	for _, want := range []string{
		"useradd -m -s /bin/sh varde", "adduser -D -s /bin/sh varde",
		`usermod -p '*' varde`, `sed -i '\|AAAAC3NzaC1lZDI1NTE5AAAAIGx0ZXN0a2V5|d'`,
		`install -d -m 700 -o varde`, `chmod 600 "$H/.ssh/authorized_keys"`,
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(cmd, "docker") {
		t.Error("docker group without docker")
	}
	// Existing accounts are never changed: password and groups only in the
	// branch that creates the user; the commands run in a subshell.
	create := strings.Index(cmd, "if ! id varde >/dev/null 2>&1; then")
	end := strings.Index(cmd, "\nfi\n")
	if create < 0 || end < create || !strings.HasPrefix(cmd, "(\n") || !strings.HasSuffix(cmd, ")\n") {
		t.Fatalf("structure:\n%s", cmd)
	}
	for _, guarded := range []string{"usermod -p '*' varde", "useradd -m"} {
		if i := strings.Index(cmd, guarded); i < create || i > end {
			t.Errorf("%q outside the creating branch", guarded)
		}
	}
	if !strings.Contains(cmd, `[ -n "$H" ] && [ "$H" != / ] || {`) {
		t.Error("no check for a missing home directory")
	}
	d := InstallCommand("varde", testLine, true)
	if i := strings.Index(d, "usermod -aG docker varde"); i < 0 || i > strings.Index(d, "elif ! id -nG varde") {
		t.Error("docker group not limited to a new user")
	}
	root := InstallCommand("root", testLine, false)
	if strings.Contains(root, "useradd") || !strings.Contains(root, "tee -a /root/.ssh/authorized_keys") {
		t.Errorf("root variant wrong:\n%s", root)
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		for _, c := range []string{cmd, root} {
			if out, err := exec.Command(sh, "-n", "-c", c).CombinedOutput(); err != nil {
				t.Errorf("not valid shell: %v %s", err, out)
			}
		}
	}
}

// Anything that could leave the here-document or inject into the commands
// gets no commands at all.
func TestInstallCommandRejects(t *testing.T) {
	for _, c := range []struct{ user, line string }{
		{"x;reboot", testLine},
		{"Varde", testLine},
		{"$(id)", testLine},
		{"", testLine},
		{"varde", testLine + "\nrm -rf /"},
		{"varde", testLine + " VARDE_KEY"},
		{"varde", "ssh-ed25519 notablob varde"},
		{"varde", "ssh-ed25519 AAAA|x varde"},
	} {
		if got := InstallCommand(c.user, c.line, true); got != "" {
			t.Errorf("%q %q accepted:\n%s", c.user, c.line, got)
		}
	}
}
