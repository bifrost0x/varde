// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pkgdb"
)

// KindSSHInventory reads native packages and systemd services of a host
// over SSH.
const KindSSHInventory = "ssh-inventory"

// InventoryCommand is the only command Varde's inventory key runs. The key
// line forces it, so whatever the client asks for, the host prints the
// package lists and the service list and nothing else. Every part is read
// only; missing tools are skipped. The command contains no double quotes,
// which the authorized_keys command="..." option cannot hold unescaped.
//
// Version 2 reads the package databases themselves (dpkg status, the apk
// database, rpm with its source package), so every package comes with the
// source package that distribution security data names. Output of version 1
// (dpkg -l, apk info) is still read. Version 3 adds the running kernel and
// the restart notes of Debian and Ubuntu, to tell when an update needs a
// reboot; hosts with an older key line keep sending the older output.
const InventoryCommand = `sh -c 'echo varde-inventory 3;` +
	` echo @@hostname; uname -n 2>/dev/null;` +
	` echo @@machine-id; cat /etc/machine-id 2>/dev/null;` +
	` echo @@mac; cat /sys/class/net/*/address 2>/dev/null;` +
	` echo @@os-release; cat /etc/os-release 2>/dev/null;` +
	` echo @@dpkg-status; cat /var/lib/dpkg/status 2>/dev/null;` +
	` echo @@rpm; command -v rpm >/dev/null 2>&1 && rpm -qa --queryformat %{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}=%{SOURCERPM}\; 2>/dev/null; echo;` +
	` echo @@apk-db; cat /lib/apk/db/installed 2>/dev/null;` +
	` echo @@systemd; command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --all --no-legend --no-pager --plain 2>/dev/null;` +
	` echo @@kernel; uname -r 2>/dev/null;` +
	` echo @@reboot; test -f /var/run/reboot-required && echo required; cat /var/run/reboot-required.pkgs 2>/dev/null;` +
	` echo @@listen-tcp; cat /proc/net/tcp /proc/net/tcp6 2>/dev/null;` +
	` echo @@listen-udp; cat /proc/net/udp /proc/net/udp6 2>/dev/null;` +
	` echo @@end'`

// inventoryOutputLimit bounds what Varde reads from a host.
const inventoryOutputLimit = 16 << 20

// InventoryLine is the authorized_keys line for the inventory key.
func (id *Identity) InventoryLine() string {
	return `restrict,command="` + InventoryCommand + `" ` + id.publicKey() + ` varde-inventory`
}

// HostInventory is what one run read from a host.
type HostInventory struct {
	Hostname string
	OS       string
	// Distro is os-release ID and VERSION_ID ("debian-13").
	Distro    string
	MachineID string
	MACs      []string
	Packages  []inventory.Package
	Services  []inventory.Service
	// Kernel is the running kernel release (uname -r); RebootFlag and
	// RebootPackages are Debian's and Ubuntu's restart notes.
	Kernel         string
	RebootFlag     bool
	RebootPackages []string
	// Listen are the sockets the host listens on (ADR 0034).
	Listen []inventory.Listener
}

var (
	kernelPattern = regexp.MustCompile(`^[A-Za-z0-9._+~-]{1,64}$`)
	packageName   = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,127}$`)
	machineID     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	macAddr       = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	distroID      = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)
)

// apkVersion splits "name-1.2.3-r4" into name and version.
var apkVersion = regexp.MustCompile(`^(.+)-(\d[^-]*-r\d+)$`)

// ParseInventory reads the output of InventoryCommand. The host is not
// trusted: lines are bounded, fields checked, and anything unexpected is
// skipped.
func ParseInventory(out []byte) (HostInventory, error) {
	var inv HostInventory
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	if !sc.Scan() {
		return inv, errInventoryHeader
	}
	switch strings.TrimSpace(sc.Text()) {
	case "varde-inventory 1", "varde-inventory 2", "varde-inventory 3":
	default:
		return inv, errInventoryHeader
	}
	section, ended := "", false
	var db pkgdb.Parser
	var osName, osVersion, osID string
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "@@") {
			db.Line("")
			section = line[2:]
			ended = section == "end"
			continue
		}
		switch section {
		case "hostname":
			if h := strings.TrimSpace(line); h != "" && len(h) <= 253 && !strings.ContainsAny(h, " \t") {
				inv.Hostname = h
			}
		case "machine-id":
			if id := strings.TrimSpace(line); machineID.MatchString(id) {
				inv.MachineID = id
			}
		case "mac":
			if mac := strings.ToLower(strings.TrimSpace(line)); macAddr.MatchString(mac) && mac != "00:00:00:00:00:00" {
				inv.MACs = append(inv.MACs, mac)
			}
		case "os-release":
			k, v, ok := strings.Cut(line, "=")
			v = strings.Trim(v, `"'`)
			switch {
			case !ok:
			case k == "NAME":
				osName = v
			case k == "VERSION_ID":
				osVersion = v
			case k == "ID":
				osID = v
			}
		case "dpkg":
			// "ii  name:arch  version  arch  description"; only installed
			// packages ("ii"), not removed ones that left configuration.
			f := strings.Fields(line)
			if len(f) < 3 || f[0] != "ii" {
				continue
			}
			name, _, _ := strings.Cut(f[1], ":")
			addPackage(&inv, "dpkg", name, f[2])
		case "dpkg-status", "apk-db":
			db.Line(line)
		case "rpm":
			for _, rec := range strings.Split(line, ";") {
				f := strings.SplitN(strings.TrimSpace(rec), "=", 3)
				if len(f) < 2 {
					continue
				}
				addPackage(&inv, "rpm", f[0], f[1])
				if len(f) == 3 && len(inv.Packages) > 0 {
					if src := rpmSource(f[2]); src != f[0] {
						inv.Packages[len(inv.Packages)-1].Source = src
					}
				}
			}
		case "apk":
			if m := apkVersion.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				addPackage(&inv, "apk", m[1], m[2])
			}
		case "kernel":
			if k := strings.TrimSpace(line); kernelPattern.MatchString(k) {
				inv.Kernel = k
			}
		case "reboot":
			switch l := strings.TrimSpace(line); {
			case l == "required":
				inv.RebootFlag = true
			case packageName.MatchString(l) && len(inv.RebootPackages) < 50 && !slices.Contains(inv.RebootPackages, l):
				inv.RebootPackages = append(inv.RebootPackages, l)
			}
		case "listen-tcp", "listen-udp":
			if l, ok := parseListener(line, section == "listen-udp"); ok && len(inv.Listen) < maxListeners && !slices.Contains(inv.Listen, l) {
				inv.Listen = append(inv.Listen, l)
			}
		case "systemd":
			// "unit load active sub description"
			f := strings.Fields(line)
			if len(f) < 4 || !strings.HasSuffix(f[0], ".service") || len(f[0]) > 256 {
				continue
			}
			inv.Services = append(inv.Services, inventory.Service{
				Unit: f[0], Enabled: f[1] == "loaded", Active: f[2] == "active",
			})
		}
	}
	if err := sc.Err(); err != nil {
		return inv, fmt.Errorf("reading the inventory output: %w", err)
	}
	if !ended {
		return inv, errors.New("the inventory output ended early")
	}
	inv.Packages = append(inv.Packages, db.Packages("")...)
	inv.OS = strings.TrimSpace(osName + " " + osVersion)
	if distroID.MatchString(osID) {
		inv.Distro = osID
		if distroID.MatchString(osVersion) {
			inv.Distro += "-" + osVersion
		}
	}
	for i := range inv.Packages {
		inv.Packages[i].Distro = inv.Distro
	}
	return inv, nil
}

func addPackage(inv *HostInventory, manager, name, ver string) {
	if name == "" || ver == "" || len(name) > 256 || len(ver) > 128 {
		return
	}
	inv.Packages = append(inv.Packages, inventory.Package{Manager: manager, Name: name, Version: ver})
}

// InventoryWorkloads keeps the packages and services the catalog knows. The
// others are counted, not stored: a host has hundreds of packages, and
// only apps can carry advisories. A service of an app that is already
// read as a package is left out.
func InventoryWorkloads(cat *catalog.Catalog, inv HostInventory) (pkgs, svcs []inventory.Workload, unmatched int) {
	apps := map[string]bool{}
	for _, p := range inv.Packages {
		app, _, ok := cat.ByPackage(p.Manager, p.Name)
		if !ok {
			unmatched++
			continue
		}
		apps[app.ID] = true
		pkg := p
		pkgs = append(pkgs, inventory.Workload{
			Kind: inventory.KindPackage, RuntimeID: p.Manager + ":" + p.Name, Name: p.Name, State: "installed", Package: &pkg,
		})
	}
	for _, s := range inv.Services {
		app, ok := cat.ByService(s.Unit)
		if !ok || apps[app.ID] {
			continue
		}
		svc := s
		state := "inactive"
		if s.Active {
			state = "active"
		}
		svcs = append(svcs, inventory.Workload{
			Kind: inventory.KindService, RuntimeID: s.Unit, Name: s.Unit, State: state, Service: &svc,
		})
	}
	return pkgs, svcs, unmatched
}

// InventoryStatus is what the last successful run saw, for the network
// page.
type InventoryStatus struct {
	OS       string `json:"os"`
	Packages int    `json:"packages"`
	Services int    `json:"services"`
	// Apps are the packages and services the catalog knows.
	Apps int `json:"apps"`
}

// RunInventory runs the inventory command on the host and returns its
// output, at most inventoryOutputLimit bytes.
func (d *DockerSSH) RunInventory(ctx context.Context) ([]byte, error) {
	return d.runFixed(ctx, "varde-inventory", inventoryOutputLimit, 2*time.Minute)
}

// runFixed runs a session whose command the key line forces; name is only
// what the client asks for, for the logs on the host.
func (d *DockerSSH) runFixed(ctx context.Context, name string, limit int, timeout time.Duration) ([]byte, error) {
	c, err := d.connect(ctx)
	if err != nil {
		return nil, err
	}
	s, err := c.NewSession()
	if err != nil {
		d.reset(c)
		return nil, fmt.Errorf("open SSH session: %w", err)
	}
	defer func() { _ = s.Close() }()
	out := &limitedBuffer{max: limit}
	stderr := &limitedBuffer{max: 2048}
	s.Stdout, s.Stderr = out, stderr
	done := make(chan error, 1)
	// The forced command ignores what is sent; the name is for the logs
	// on the host.
	go func() { done <- s.Run(name) }()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case err = <-done:
	case <-cctx.Done():
		_ = s.Close()
		return nil, fmt.Errorf("the command on %s did not finish in time", d.cfg.Target())
	}
	if out.truncated {
		return nil, fmt.Errorf("the output of %s exceeds %d MiB", d.cfg.Target(), limit>>20)
	}
	if err != nil && out.Len() == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("the command failed on %s: %s", d.cfg.Target(), msg)
	}
	return out.Bytes(), nil
}

var errInventoryHeader = errors.New("the host did not run Varde's inventory command; check the key line in authorized_keys")

// srpm is "<name>-<version>-<release>.src.rpm".
var srpm = regexp.MustCompile(`^(.+)-[^-]+-[^-]+\.src\.rpm$`)

// rpmSource is the source package name of an rpm's SOURCERPM.
func rpmSource(s string) string {
	if m := srpm.FindStringSubmatch(strings.TrimSpace(s)); m != nil && len(m[1]) <= 256 {
		return m[1]
	}
	return ""
}

// maxSystemPackages bounds the system packages of one host.
const maxSystemPackages = 5000

// SystemWorkloads are the system packages of a host (ADR 0032): one per
// package of a release with distribution security data, named and
// versioned as that data does (distro.Checked). Packages a catalog app
// covers already, and builds from outside the distribution, are left out.
func SystemWorkloads(cat *catalog.Catalog, inv HostInventory) []inventory.Workload {
	_, manager, ok := distro.Ecosystem(inv.Distro)
	if !ok {
		return nil
	}
	covered := map[string]bool{}
	if cat != nil {
		for _, p := range inv.Packages {
			if _, m, ok := cat.ByPackage(p.Manager, p.Name); ok {
				// The catalog names a binary or source package; the host
				// says which source package it was built from.
				covered[m.SourceName()] = true
				if p.Source != "" {
					covered[p.Source] = true
				}
				covered[p.Name] = true
			}
		}
	}
	checked := distro.Checked(inv.Distro, Installed(inv.Packages), distro.CheckOptions{Kernel: inv.Kernel})
	out := make([]inventory.Workload, 0, len(checked))
	for _, c := range checked {
		if covered[c.Name] || len(out) == maxSystemPackages {
			continue
		}
		pkg := inventory.Package{Manager: manager, Name: c.Name, Version: c.Version, Distro: inv.Distro, Source: c.Name, System: true}
		out = append(out, inventory.Workload{
			Kind: inventory.KindPackage, RuntimeID: "os:" + manager + ":" + c.Name, Name: c.Name, State: "installed", Package: &pkg,
		})
	}
	return out
}

// Installed turns a package list into the form distro.Checked reads;
// manifests of apps are left out.
func Installed(pkgs []inventory.Package) []distro.Installed {
	out := make([]distro.Installed, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Path != "" {
			continue
		}
		out = append(out, distro.Installed{Manager: p.Manager, Name: p.Name, Version: p.Version, Source: p.Source, SourceVersion: p.SourceVersion})
	}
	return out
}

// kernelPrefixes name the packages of installed kernels; the rest of the
// name is the release uname -r reports ("linux-image-6.1.0-28-amd64",
// "proxmox-kernel-6.8.12-4-pve-signed").
var kernelPrefixes = []string{"linux-image-", "proxmox-kernel-", "pve-kernel-"}

// RebootReason says why a host needs a restart for its updates to take
// effect, empty when it does not or Varde cannot tell: a newer kernel is
// installed than the one running, or Debian's or Ubuntu's restart note is
// set. Containers share their host's kernel and have no kernel packages,
// so only the note applies to them.
func RebootReason(inv HostInventory) string {
	eco, _, _ := distro.Ecosystem(inv.Distro)
	if inv.Kernel != "" {
		var running, newest inventory.Package
		found := false
		for _, p := range inv.Packages {
			rel, ok := kernelRelease(p.Name)
			if !ok {
				continue
			}
			found = true
			if rel == inv.Kernel {
				running = p
			}
			if newest.Version == "" {
				newest = p
			} else if c, ok := distro.Compare(eco, p.Version, newest.Version); ok && c > 0 {
				newest = p
			} else if !ok && p.Version > newest.Version {
				newest = p
			}
		}
		switch {
		case !found:
		case running.Name == "":
			return "kernel " + inv.Kernel + " is running, but it is no longer installed: a newer kernel waits for a restart"
		case newest.Name != running.Name:
			if c, ok := distro.Compare(eco, newest.Version, running.Version); !ok || c > 0 {
				rel, _ := kernelRelease(newest.Name)
				return "kernel " + rel + " is installed, " + inv.Kernel + " is running"
			}
		}
	}
	if inv.RebootFlag {
		if len(inv.RebootPackages) > 0 {
			return "updated packages wait for a restart: " + strings.Join(inv.RebootPackages, ", ")
		}
		return "the system asks for a restart after updates"
	}
	return ""
}

// kernelRelease returns the kernel release a kernel image package
// installs; meta packages ("linux-image-amd64") have none.
func kernelRelease(pkg string) (string, bool) {
	for _, prefix := range kernelPrefixes {
		rest, ok := strings.CutPrefix(pkg, prefix)
		if !ok || rest == "" || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		return strings.TrimSuffix(rest, "-signed"), true
	}
	return "", false
}

// maxListeners bounds the sockets kept per host.
const maxListeners = 512

// parseListener reads one line of /proc/net/{tcp,tcp6,udp,udp6} and returns
// it when the socket listens: TCP state 0A (LISTEN), or an unconnected UDP
// socket (07) with a bound port. Addresses are hex in host byte order per
// 32-bit word.
func parseListener(line string, udp bool) (inventory.Listener, bool) {
	f := strings.Fields(line)
	if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
		return inventory.Listener{}, false
	}
	want, proto := "0A", "tcp"
	if udp {
		want, proto = "07", "udp"
	}
	if f[3] != want {
		return inventory.Listener{}, false
	}
	hexAddr, hexPort, ok := strings.Cut(f[1], ":")
	if !ok {
		return inventory.Listener{}, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil || port == 0 {
		return inventory.Listener{}, false
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return inventory.Listener{}, false
	}
	// Each 32-bit word is little-endian.
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return inventory.Listener{}, false
	}
	return inventory.Listener{Proto: proto, Address: addr.Unmap().String(), Port: uint16(port)}, true
}
