// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/inventory"
)

// inventoryTimeout bounds one run of the inventory command.
const inventoryTimeout = 2 * time.Minute

// errNoShell means the agent runs where there is no shell, as in its own
// container image; there is no host inventory to read there.
var errNoShell = errors.New("no /bin/sh: the host inventory is read only when the agent runs on the host itself")

// RunInventory runs the inventory command of the SSH inventory (ADR 0030) on
// this host and returns its output. The server parses it with the same
// parser, so both ways deliver the same inventory. The command only reads.
func RunInventory(ctx context.Context) ([]byte, error) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		return nil, errNoShell
	}
	ctx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", integrations.InventoryCommand) //nolint:gosec // a constant, read-only command
	out := &cappedBuffer{max: wire.MaxInventoryBytes}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if out.over {
		return nil, fmt.Errorf("the inventory exceeds %d MiB", wire.MaxInventoryBytes>>20)
	}
	if err != nil && out.buf.Len() == 0 {
		return nil, fmt.Errorf("run the inventory command: %w", err)
	}
	return out.buf.Bytes(), nil
}

type cappedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		b.over = true
		return 0, errors.New("output limit reached")
	}
	return b.buf.Write(p)
}

// HostCollector stands in for the Docker collector on a host without
// Docker: it reports no containers and describes the host itself, so the
// agent still delivers the host inventory and heartbeats.
type HostCollector struct{}

// Kind reports containers: the agent's snapshot is a container snapshot,
// here an empty one.
func (HostCollector) Kind() inventory.Kind { return inventory.KindContainer }

// List returns the host description and no workloads.
func (HostCollector) List(context.Context) (inventory.Snapshot, error) {
	name, _ := os.Hostname()
	return inventory.Snapshot{Host: inventory.HostInfo{Name: name, OS: prettyName("/etc/os-release"), Arch: runtime.GOARCH}}, nil
}

// Watch emits nothing; the syncer's resync interval drives the reports.
func (HostCollector) Watch(ctx context.Context) <-chan inventory.Event {
	ch := make(chan inventory.Event)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch
}

// prettyName reads PRETTY_NAME from an os-release file.
func prettyName(path string) string {
	f, err := os.Open(path) //nolint:gosec // fixed system path
	if err != nil {
		return runtime.GOOS
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(io.LimitReader(f, 64<<10))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			v = strings.Trim(v, `"'`)
			if len(v) > 0 && len(v) <= 128 {
				return v
			}
		}
	}
	return runtime.GOOS
}

// maxAddresses bounds the interface addresses an agent announces.
const maxAddresses = 32

// virtualBridges are interface name prefixes of container and VM bridges:
// every Docker host has 172.17.0.1, so these addresses identify nothing.
// Proxmox bridges (vmbr) carry the node's own address and stay.
var virtualBridges = []string{"docker", "br-", "veth", "virbr", "lxcbr", "cni", "flannel", "kube", "podman", "cali"}

func virtualBridge(name string) bool {
	return slices.ContainsFunc(virtualBridges, func(p string) bool { return strings.HasPrefix(name, p) })
}

// InterfaceAddresses lists the unicast addresses of this machine's network
// interfaces, without loopback, link-local and container bridge ones. They
// tie an agent's host to the device the network scan finds at one of them
// (ADR 0023).
func InterfaceAddresses() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("read interfaces: %w", err)
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || virtualBridge(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if out = append(out, ip.String()); len(out) == maxAddresses {
				return out, nil
			}
		}
	}
	return out, nil
}
