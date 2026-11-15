// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const arpFixture = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         AA:BB:CC:00:11:22     *        eth0
192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.30     0x1         0x2         de:ad:be:ef:00:01     *        eth0
`

func TestParseARP(t *testing.T) {
	got := parseARP(strings.NewReader(arpFixture))
	if len(got) != 2 || got["192.168.1.1"] != "aa:bb:cc:00:11:22" || got["192.168.1.30"] != "de:ad:be:ef:00:01" {
		t.Fatalf("parseARP = %v", got)
	}
}

func TestReadARPMissingFile(t *testing.T) {
	old := arpPath
	arpPath = filepath.Join(t.TempDir(), "none")
	t.Cleanup(func() { arpPath = old })
	if got := readARP(); got != nil {
		t.Fatalf("readARP = %v, want nil", got)
	}
}

func TestClassifyIgnoresARPService(t *testing.T) {
	arp := Service{Proto: ProtoARP, Fields: []Field{{FieldMAC, "aa:bb:cc:00:11:22", TrustStated}}}
	k1, l1 := Classify(nil)
	k2, l2 := Classify([]Service{arp})
	if k1 != k2 || l1 != l2 {
		t.Fatalf("Classify with ARP = %q %q, without = %q %q", k2, l2, k1, l1)
	}
	ssh := Service{Port: 22, Proto: ProtoSSH, Product: "OpenSSH_9.2 Debian"}
	k1, l1 = Classify([]Service{ssh})
	k2, l2 = Classify([]Service{arp, ssh})
	if k1 != k2 || l1 != l2 {
		t.Fatalf("Classify with ARP = %q %q, without = %q %q", k2, l2, k1, l1)
	}
}

func TestScanAddsMACFromARP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arp")
	table := "IP address HW type Flags HW address Mask Device\n127.0.0.1 0x1 0x2 AA:BB:CC:00:11:22 * lo\n"
	if err := os.WriteFile(path, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	old := arpPath
	arpPath = path
	t.Cleanup(func() { arpPath = old })

	// Nothing listens on port 1: the host is alive (refused) and has no
	// open service, so the ARP entry is its only service.
	s := &Scanner{
		Ports:    []Port{{1, ProtoTCP}},
		InFlight: 1, Rate: 1000, ConnectTimeout: time.Second, ReadTimeout: time.Second,
		dial: (&net.Dialer{}).DialContext,
	}
	res, err := s.Scan(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Devices) != 1 {
		t.Fatalf("devices %+v", res.Devices)
	}
	d := res.Devices[0]
	if d.Label != "Device (no known service)" {
		t.Errorf("label %q", d.Label)
	}
	var mac string
	for _, sv := range d.Services {
		if sv.Proto == ProtoARP && sv.Port == 0 {
			for _, f := range sv.Fields {
				if f.Name == FieldMAC && f.Trust == TrustStated {
					mac = f.Value
				}
			}
		}
	}
	if mac != "aa:bb:cc:00:11:22" {
		t.Errorf("mac %q, services %+v", mac, d.Services)
	}
}
