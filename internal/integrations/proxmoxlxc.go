// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pkgdb"
)

// KindProxmoxLXC reads the packages of every running LXC container of a
// Proxmox VE node through one restricted key on the node.
const KindProxmoxLXC = "proxmox-lxc"

// LXCCommand is the only command the Proxmox key runs, as root on the node.
// It reads the full inventory of every running guest of the node:
//
//   - LXC containers: host name and MAC addresses from the node's own
//     configuration (pct config), and with `pct exec <id> --`, one call per
//     item, os-release, the dpkg and apk databases, the rpm list and the
//     Docker containers and images inside.
//   - VMs: name and MAC addresses from qm config, and the same items through
//     the QEMU guest agent (`qm guest exec`), for VMs whose agent answers.
//
// pct exec runs inside the container's namespaces with its own rights, so
// symlinks resolve inside it and nothing of the node is read (reading
// /proc/<pid>/root from the host would let a container point a symlink at
// host files). The guest agent runs the fixed commands inside the VM and
// returns their output as a JSON string.
//
// A guest controls what it prints, so every line the node adds carries a
// nonce drawn on the node for this run, which no guest can know: a guest
// cannot forge a marker, another guest, a MAC or the end of the output.
// Every call reads /dev/null as input, so none consumes the guest list the
// loop reads. VMIDs are checked to be numeric; each call has a timeout. No
// double quotes, which the authorized_keys command="..." option cannot
// hold, and no glob characters outside the case patterns.
const LXCCommand = `sh -c 'n=$(od -An -N8 -tx8 /dev/urandom | tr -dc 0-9a-f); echo varde-proxmox-node 3 $n;` +
	` pct list 2>/dev/null | while read id st rest; do` +
	` case $id in *[!0-9]*) continue;; esac;` +
	` case $st in running) ;; *) continue;; esac;` +
	` echo @@$n ct $id;` +
	` pct config $id </dev/null 2>/dev/null | while read k v; do case $k in hostname:|net[0-9]:|net[0-9][0-9]:) echo @@$n cfg $k $v;; esac; done;` +
	` for f in /etc/os-release /var/lib/dpkg/status /lib/apk/db/installed; do echo @@$n file $f;` +
	` timeout 20 pct exec $id -- cat $f </dev/null 2>/dev/null; echo; done;` +
	` echo @@$n rpm; timeout 20 pct exec $id -- rpm -qa --queryformat %{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}=%{SOURCERPM}\; </dev/null 2>/dev/null; echo;` +
	` echo @@$n docker; timeout 20 pct exec $id -- docker ps -a --no-trunc --format {{json .}} </dev/null 2>/dev/null;` +
	` echo @@$n images; timeout 20 pct exec $id -- docker image ls --digests --no-trunc --format {{json .}} </dev/null 2>/dev/null;` +
	` done;` +
	` qm list 2>/dev/null | while read id name st rest; do` +
	` case $id in *[!0-9]*) continue;; esac;` +
	` case $st in running) ;; *) continue;; esac;` +
	` echo @@$n vm $id;` +
	` qm config $id </dev/null 2>/dev/null | while read k v; do case $k in name:|net[0-9]:|net[0-9][0-9]:) echo @@$n cfg $k $v;; esac; done;` +
	` if ! timeout 10 qm guest cmd $id ping </dev/null >/dev/null 2>&1; then echo @@$n noagent; continue; fi;` +
	` for f in /etc/os-release /var/lib/dpkg/status /lib/apk/db/installed; do echo @@$n gfile $f;` +
	` timeout 40 qm guest exec $id --timeout 30 -- cat $f </dev/null 2>/dev/null; echo; done;` +
	` echo @@$n grpm; timeout 40 qm guest exec $id --timeout 30 -- rpm -qa --queryformat %{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}=%{SOURCERPM}\; </dev/null 2>/dev/null; echo;` +
	` echo @@$n gdocker; timeout 40 qm guest exec $id --timeout 30 -- docker ps -a --no-trunc --format {{json .}} </dev/null 2>/dev/null; echo;` +
	` echo @@$n gimages; timeout 40 qm guest exec $id --timeout 30 -- docker image ls --digests --no-trunc --format {{json .}} </dev/null 2>/dev/null; echo;` +
	` done; echo @@$n end'`

// lxcOutputLimit bounds what Varde reads from a node: a few MB of package
// databases per guest.
const lxcOutputLimit = 128 << 20

// LXCLine is the authorized_keys line for root on the Proxmox node.
func (id *Identity) LXCLine() string {
	return `restrict,command="` + LXCCommand + `" ` + id.publicKey() + ` varde-proxmox`
}

// Guest kinds of the node inventory.
const (
	GuestLXC = "lxc"
	GuestVM  = "vm"
)

// ContainerInventory is what the node printed for one guest (an LXC
// container or a VM).
type ContainerInventory struct {
	VMID int
	// Kind is GuestLXC or GuestVM.
	Kind string
	// NoAgent is set for a VM whose guest agent did not answer: only its
	// configuration is known.
	NoAgent bool
	// Containers are the Docker containers running in the guest.
	Containers []GuestContainer
	HostInventory
}

// GuestContainer is a Docker container inside a guest, from docker ps and
// docker image ls.
type GuestContainer struct {
	ID, Name, Image, State string
	Labels                 map[string]string
	// ImageID and RepoDigests come from the image list.
	ImageID     string
	RepoDigests []string
}

var (
	nodeHeader = regexp.MustCompile(`^varde-proxmox-(?:lxc 2|node 3) ([0-9a-f]{8,32})$`)
	hostLine   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	hwaddr     = regexp.MustCompile(`(?:^|,)hwaddr=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?:,|$)`)
	// vmMAC is the MAC of a VM network device ("virtio=BC:24:11:...").
	vmMAC       = regexp.MustCompile(`^[a-z0-9]+=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?:,|$)`)
	containerID = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
)

// ParseLXCInventory reads the output of LXCCommand. The guests are not
// trusted: only lines with the run's nonce are markers, names and MACs come
// only from the node's configuration, guest-agent answers are decoded as
// JSON, lines are bounded, only known fields are read, and a dpkg package
// counts only when its status says installed.
func ParseLXCInventory(out []byte) ([]ContainerInventory, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	if !sc.Scan() {
		return nil, errLXCHeader
	}
	m := nodeHeader.FindStringSubmatch(strings.TrimSpace(sc.Text()))
	if m == nil {
		return nil, errLXCHeader
	}
	marker := "@@" + m[1] + " "
	p := &nodeParser{seen: map[string]bool{}}
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if rest, ok := strings.CutPrefix(line, marker); ok {
			if err := p.marker(rest); err != nil {
				return nil, err
			}
			continue
		}
		p.content(line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading the node output: %w", err)
	}
	if !p.ended {
		return nil, errors.New("the node output ended early")
	}
	return p.out, nil
}

var errLXCHeader = errors.New("the node did not run Varde's node command; run step 3 of the setup again to update the key line in /root/.ssh/authorized_keys")

// nodeParser holds the guest being read.
type nodeParser struct {
	out      []ContainerInventory
	cur      *ContainerInventory
	pkgs     *pkgdb.Parser
	osFields map[string]string
	section  string
	// guest collects the lines of a guest-agent answer (JSON).
	guest  []string
	images map[string]GuestContainer
	seen   map[string]bool
	ended  bool
}

func (p *nodeParser) marker(rest string) error {
	if p.ended {
		return errors.New("the node printed after the end of its output")
	}
	p.endSection()
	kind, arg, _ := strings.Cut(rest, " ")
	switch kind {
	case "ct", "vm":
		id, err := strconv.Atoi(arg)
		if err != nil || id <= 0 || id > 999999999 || p.seen[kind+arg] {
			return fmt.Errorf("the node printed an invalid guest %q", arg)
		}
		p.finish()
		p.seen[kind+arg] = true
		gk := GuestLXC
		if kind == "vm" {
			gk = GuestVM
		}
		p.cur, p.pkgs, p.osFields, p.images = &ContainerInventory{VMID: id, Kind: gk}, &pkgdb.Parser{}, map[string]string{}, map[string]GuestContainer{}
	case "cfg":
		if p.cur != nil {
			lxcConfig(p.cur, arg)
		}
	case "noagent":
		if p.cur != nil {
			p.cur.NoAgent = true
		}
	case "file", "gfile":
		p.section = kind + " " + arg
	case "rpm", "grpm", "docker", "gdocker", "images", "gimages":
		p.section = kind
	case "end":
		p.finish()
		p.ended = true
	}
	return nil
}

// content handles a line the guest printed, directly (pct exec) or inside
// a guest-agent answer.
func (p *nodeParser) content(line string) {
	if p.cur == nil || p.ended {
		return
	}
	if strings.HasPrefix(p.section, "g") {
		if len(p.guest) < 1<<16 {
			p.guest = append(p.guest, line)
		}
		return
	}
	p.line(strings.TrimPrefix(p.section, "g"), line)
}

func (p *nodeParser) line(section, line string) {
	switch section {
	case "file /etc/os-release":
		if k, v, ok := strings.Cut(line, "="); ok && (k == "ID" || k == "NAME" || k == "VERSION_ID") {
			p.osFields[k] = strings.Trim(v, `"'`)
		}
	case "file /var/lib/dpkg/status", "file /lib/apk/db/installed":
		p.pkgs.Line(line)
	case "rpm":
		for _, rec := range strings.Split(line, ";") {
			f := strings.SplitN(strings.TrimSpace(rec), "=", 3)
			if len(f) < 2 || f[0] == "" || f[1] == "" || len(f[0]) > 256 || len(f[1]) > 128 {
				continue
			}
			pk := inventory.Package{Manager: "rpm", Name: f[0], Version: f[1]}
			if len(f) == 3 {
				if src := rpmSource(f[2]); src != f[0] {
					pk.Source = src
				}
			}
			p.cur.Packages = append(p.cur.Packages, pk)
		}
	case "docker":
		if c, ok := parseDockerPS(line); ok && len(p.cur.Containers) < 1000 {
			p.cur.Containers = append(p.cur.Containers, c)
		}
	case "images":
		var im struct{ Repository, Tag, Digest, ID string }
		if json.Unmarshal([]byte(line), &im) == nil && im.Repository != "" && im.Repository != "<none>" {
			p.images[im.Repository+":"+im.Tag] = GuestContainer{ImageID: im.ID, RepoDigests: digestOf(im.Repository, im.Digest)}
		}
	}
}

// endSection decodes a finished guest-agent answer and feeds its output.
func (p *nodeParser) endSection() {
	if p.cur != nil && strings.HasPrefix(p.section, "g") && len(p.guest) > 0 {
		var ans struct {
			ExitCode int    `json:"exitcode"`
			Out      string `json:"out-data"`
		}
		if json.Unmarshal([]byte(strings.Join(p.guest, "\n")), &ans) == nil && ans.ExitCode == 0 {
			section := strings.TrimPrefix(p.section, "g")
			for _, l := range strings.Split(ans.Out, "\n") {
				p.line(section, strings.TrimRight(l, "\r"))
			}
		}
	}
	if p.pkgs != nil {
		// Each file starts a new database section.
		p.pkgs.Line("")
	}
	p.section, p.guest = "", nil
}

func (p *nodeParser) finish() {
	p.endSection()
	if p.cur == nil {
		return
	}
	osr := pkgdb.OSRelease{ID: p.osFields["ID"], VersionID: p.osFields["VERSION_ID"], Name: p.osFields["NAME"]}
	p.cur.OS, p.cur.Distro = osr.String(), osr.Distro()
	p.cur.Packages = append(p.pkgs.Packages(""), p.cur.Packages...)
	for i := range p.cur.Packages {
		p.cur.Packages[i].Distro = p.cur.Distro
	}
	for i, c := range p.cur.Containers {
		if im, ok := p.images[c.Image]; ok {
			p.cur.Containers[i].ImageID, p.cur.Containers[i].RepoDigests = im.ImageID, im.RepoDigests
		} else if im, ok := p.images[c.Image+":latest"]; ok {
			p.cur.Containers[i].ImageID, p.cur.Containers[i].RepoDigests = im.ImageID, im.RepoDigests
		}
	}
	p.out = append(p.out, *p.cur)
	p.cur = nil
}

// parseDockerPS reads one line of `docker ps --format {{json .}}`.
func parseDockerPS(line string) (GuestContainer, bool) {
	var ps struct {
		ID, Image, Names, Labels, State string
	}
	if json.Unmarshal([]byte(line), &ps) != nil || !containerID.MatchString(ps.ID) || ps.Image == "" || len(ps.Image) > 512 {
		return GuestContainer{}, false
	}
	name, _, _ := strings.Cut(ps.Names, ",")
	c := GuestContainer{ID: ps.ID, Name: truncateField(name, 256), Image: ps.Image, State: truncateField(ps.State, 32), Labels: map[string]string{}}
	// docker ps joins labels as "k=v,k=v"; values with commas are cut,
	// which affects free-text labels only.
	for _, kv := range strings.Split(ps.Labels, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" && len(k) <= 256 && len(v) <= 1024 && len(c.Labels) < 256 {
			c.Labels[k] = v
		}
	}
	return c, true
}

func digestOf(repo, digest string) []string {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		return nil
	}
	return []string{repo + "@" + digest}
}

func truncateField(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// lxcConfig reads the host name and MAC addresses from the node's pct or qm
// config lines ("hostname: web", "name: immich",
// "net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:...", "net0: virtio=BC:24:11:...,bridge=vmbr0").
func lxcConfig(ct *ContainerInventory, line string) {
	k, v, _ := strings.Cut(line, " ")
	v = strings.TrimSpace(v)
	switch {
	case k == "hostname:" || k == "name:":
		if hostLine.MatchString(v) {
			ct.Hostname = v
		}
	case strings.HasPrefix(k, "net"):
		m := hwaddr.FindStringSubmatch(v)
		if m == nil {
			m = vmMAC.FindStringSubmatch(v)
		}
		if m != nil {
			if mac := strings.ToLower(m[1]); mac != "00:00:00:00:00:00" {
				ct.MACs = append(ct.MACs, mac)
			}
		}
	}
}

// LXCStatus is what the last successful run saw, for the network page.
type LXCStatus struct {
	// Containers are the LXC containers, VMs the VMs read through their
	// guest agent, NoAgent the running VMs whose agent did not answer.
	Containers int `json:"containers"`
	VMs        int `json:"vms,omitempty"`
	NoAgent    int `json:"no_agent,omitempty"`
	// Docker counts the Docker containers inside the guests.
	Docker   int `json:"docker,omitempty"`
	Packages int `json:"packages"`
	// Apps are the packages the catalog knows.
	Apps int `json:"apps"`
}
