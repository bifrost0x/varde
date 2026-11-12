// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"regexp"
	"strings"
)

var shellUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// InstallCommand returns shell commands that add an authorized_keys line
// for user on a host, creating the user when it does not exist. The line
// goes through a quoted here-document, so its quotes and $ signs reach the
// file unchanged. It works with and without sudo (root on a VM or LXC has
// none) and on Debian, Ubuntu, Fedora and Alpine (useradd or adduser). The
// account gets no password but is not locked: OpenSSH without PAM refuses
// key logins for locked accounts. With docker set, the user joins the
// docker group. Empty for user names that are not plain.
func InstallCommand(user, line string, docker bool) string {
	if !shellUser.MatchString(user) || strings.Contains(line, "\n") || strings.Contains(line, "VARDE_KEY") {
		return ""
	}
	// The key blob identifies earlier lines of the same key, which are
	// replaced: running the commands again (after an update of the forced
	// command, for example) leaves one line.
	blob := ""
	for _, f := range strings.Fields(line) {
		if strings.HasPrefix(f, "AAAA") {
			blob = f
		}
	}
	if blob == "" || strings.ContainsAny(blob, "|'") {
		return ""
	}
	var b strings.Builder
	w := func(s string) {
		b.WriteString(strings.NewReplacer("USER", user, "BLOB", blob).Replace(s) + "\n")
	}
	// A subshell: a failure ends the commands, not the admin's shell.
	b.WriteString("(\n")
	w(`S=$(command -v sudo || true)`)
	if user == "root" {
		w(`$S mkdir -p -m 700 /root/.ssh`)
		w(`[ -f /root/.ssh/authorized_keys ] && $S sed -i '\|BLOB|d' /root/.ssh/authorized_keys`)
		w(`$S tee -a /root/.ssh/authorized_keys >/dev/null <<'VARDE_KEY'`)
		b.WriteString(line + "\nVARDE_KEY\n")
		w(`$S chmod 600 /root/.ssh/authorized_keys`)
		b.WriteString(")\n")
		return b.String()
	}
	// An existing account is left as it is: its password and groups are
	// the admin's. Only a user created here gets no password (unlocked, so
	// key logins work without PAM) and, for Docker, the docker group.
	w(`if ! id USER >/dev/null 2>&1; then`)
	w(`  $S useradd -m -s /bin/sh USER 2>/dev/null || $S adduser -D -s /bin/sh USER`)
	w(`  $S usermod -p '*' USER 2>/dev/null || $S sed -i 's/^USER:!:/USER:*:/' /etc/shadow`)
	if docker {
		w(`  $S usermod -aG docker USER 2>/dev/null || $S addgroup USER docker`)
		w(`elif ! id -nG USER | grep -qw docker; then`)
		w(`  echo "varde: USER exists and is not in the docker group; Varde can only read Docker if it is" >&2`)
	}
	w(`fi`)
	w(`H=$(getent passwd USER | cut -d: -f6)`)
	w(`[ -n "$H" ] && [ "$H" != / ] || { echo "varde: USER has no home directory" >&2; exit 1; }`)
	w(`$S install -d -m 700 -o USER -g "$(id -gn USER)" "$H/.ssh"`)
	w(`[ -f "$H/.ssh/authorized_keys" ] && $S sed -i '\|BLOB|d' "$H/.ssh/authorized_keys"`)
	w(`$S tee -a "$H/.ssh/authorized_keys" >/dev/null <<'VARDE_KEY'`)
	b.WriteString(line + "\nVARDE_KEY\n")
	w(`$S chown USER "$H/.ssh/authorized_keys" && $S chmod 600 "$H/.ssh/authorized_keys"`)
	b.WriteString(")\n")
	return b.String()
}
