// SPDX-License-Identifier: Apache-2.0

package remedy

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bifrost0x/varde/internal/distro"
)

// packageName accepts the names package managers give packages; anything
// else never reaches a command.
var packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:~-]{0,127}$`)

// PackageCommand is the command that installs the updates of the named
// packages on a system of release (os-release, "debian-12"), as root, in
// the package manager's own words; "" when Varde does not know the
// release's package manager or no name is valid. Only the named packages
// are upgraded, so the command does what the flaws need and nothing more.
func PackageCommand(release string, names []string) string {
	eco, _, ok := distro.Ecosystem(release)
	if !ok {
		return ""
	}
	pkgs := validNames(names)
	if len(pkgs) == 0 {
		return ""
	}
	list := strings.Join(pkgs, " ")
	family, _, _ := strings.Cut(eco, ":")
	switch family {
	case "Debian", "Ubuntu":
		return "apt-get update && apt-get install --only-upgrade " + list
	case "Alpine", "Wolfi", "Chainguard":
		return "apk update && apk upgrade " + list
	case "AlmaLinux", "Rocky Linux", "Red Hat":
		return "dnf upgrade --refresh " + list
	case "openSUSE":
		return "zypper refresh && zypper update " + list
	}
	return ""
}

// AsRoot is cmd run through sudo, for a shell on the system itself.
func AsRoot(cmd string) string { return "sudo sh -c " + shellQuote(cmd) }

// InLXC is cmd run inside the LXC container vmid, from a shell on its
// Proxmox node: pct exec runs it as the container's root.
func InLXC(vmid int, cmd string) string {
	return "pct exec " + strconv.Itoa(vmid) + " -- sh -c " + shellQuote(cmd)
}

func validNames(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if packageName.MatchString(n) && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
