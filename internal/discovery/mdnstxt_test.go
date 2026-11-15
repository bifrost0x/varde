// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"golang.org/x/net/dns/dnsmessage"
)

func fieldMap(fs []Field) map[string]string {
	m := map[string]string{}
	for _, f := range fs {
		if _, ok := m[f.Name]; !ok {
			m[f.Name] = f.Value
		}
	}
	return m
}

func TestTXTFields(t *testing.T) {
	cases := []struct {
		name  string
		pairs []string
		want  map[string]string
	}{
		{"cast", []string{"md=Chromecast", "fn=Living room"}, map[string]string{"model": "Chromecast"}},
		{"printer", []string{"usb_MFG=Brother", "usb_MDL=HL-L2350DW", "ty=Brother HL-L2350DW"}, map[string]string{"manufacturer": "Brother", "model": "HL-L2350DW"}},
		{"mac", []string{"mac=AA:BB:CC:DD:EE:FF"}, map[string]string{"mac": "aa:bb:cc:dd:ee:ff"}},
		{"deviceid mac", []string{"deviceid=AA:BB:CC:DD:EE:01"}, map[string]string{"mac": "aa:bb:cc:dd:ee:01"}},
		{"id not a mac", []string{"id=not-a-mac"}, map[string]string{}},
		{"firmware serial os", []string{"FW=1.2.3", "sn=XYZ1", "osxvers=21"}, map[string]string{"firmware": "1.2.3", "serial": "XYZ1", "os_version": "21"}},
		{"no equals", []string{"model"}, map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := txtFields(c.pairs)
			got := fieldMap(fs)
			if len(got) != len(c.want) {
				t.Fatalf("got %+v want %v", fs, c.want)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			for _, f := range fs {
				if f.Trust != TrustStated {
					t.Errorf("%s trust %s", f.Name, f.Trust)
				}
			}
		})
	}
}

func instanceMsg(t *testing.T, txt []string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	inst := dnsmessage.MustNewName("nas._device-info._tcp.local.")
	err := b.PTRResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("_device-info._tcp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 10},
		dnsmessage.PTRResource{PTR: inst})
	if err != nil {
		t.Fatal(err)
	}
	err = b.TXTResource(dnsmessage.ResourceHeader{Name: inst, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 10},
		dnsmessage.TXTResource{TXT: txt})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParseMDNSInstances(t *testing.T) {
	got := fieldMap(parseMDNSInstances(instanceMsg(t, []string{"model=DXP4800"})))
	if got["display_name"] != "nas" || got["model"] != "DXP4800" || len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestParseMDNSInstancesHostile(t *testing.T) {
	var txt []string
	for i := range 255 {
		txt = append(txt, "model="+strings.Repeat(string(rune('a'+i%26)), 248))
	}
	fs := parseMDNSInstances(instanceMsg(t, txt))
	if len(fs) > 32 {
		t.Errorf("%d fields", len(fs))
	}
	for _, f := range fs {
		if utf8.RuneCountInString(f.Value) > 128 {
			t.Errorf("value of %d runes", utf8.RuneCountInString(f.Value))
		}
	}
	msg := instanceMsg(t, []string{"model=x"})
	for n := range len(msg) {
		_ = parseMDNSInstances(msg[:n])
	}
	if fs := parseMDNSInstances(msg[:20]); len(fs) != 0 {
		t.Errorf("truncated: %+v", fs)
	}
}

// A device that lists many info types gets at most the enumeration and
// four follow-up queries.
func TestMDNSFollowUpBound(t *testing.T) {
	var n atomic.Int32
	port := udpResponder(t, func(q []byte) []byte {
		n.Add(1)
		var p dnsmessage.Parser
		if _, err := p.Start(q); err != nil {
			return nil
		}
		qs, err := p.AllQuestions()
		if err != nil || len(qs) != 1 {
			return nil
		}
		if qs[0].Name.String() == "_services._dns-sd._udp.local." {
			return mdnsAnswer(t, mdnsInfoTypes[:10]...)
		}
		return instanceMsg(t, []string{"model=DXP4800"})
	})
	s := &Scanner{InFlight: 1, Rate: 1000, dial: (&net.Dialer{}).DialContext, mdnsPort: port}
	svc, ok := s.mdns(t.Context(), netip.MustParseAddr("127.0.0.1"))
	if !ok {
		t.Fatal("no service")
	}
	if got := n.Load(); got != 5 {
		t.Errorf("%d datagrams, want 5", got)
	}
	m := fieldMap(svc.Fields)
	if m["model"] != "DXP4800" || m["display_name"] != "nas" || m["service_type"] == "" {
		t.Errorf("fields %+v", svc.Fields)
	}
}
