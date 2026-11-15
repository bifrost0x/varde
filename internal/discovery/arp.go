// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// ProtoARP marks the pseudo service that carries the MAC address the
// kernel has learned for a host on the local segment. It has no port.
const ProtoARP = "arp"

// arpPath is the kernel's ARP table. It exists on Linux only; elsewhere
// reading it fails and the scan goes on without MAC addresses.
var arpPath = "/proc/net/arp"

// parseARP reads the /proc/net/arp format into IP -> lowercase MAC.
// Incomplete entries (flags 0x0) and all-zero MACs are skipped.
func parseARP(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	first := true
	for sc.Scan() {
		if first { // header line
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		ip, flags, mac := f[0], f[2], strings.ToLower(f[3])
		if _, err := netip.ParseAddr(ip); err != nil {
			continue
		}
		if flags == "0x0" || mac == "00:00:00:00:00:00" || len(mac) != 17 {
			continue
		}
		out[ip] = mac
	}
	return out
}

// readARP returns the ARP table, or nil when it cannot be read.
func readARP() map[string]string {
	f, err := os.Open(arpPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	return parseARP(f)
}
