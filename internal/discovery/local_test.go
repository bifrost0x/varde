// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// udpResponder answers every datagram with reply(query).
func udpResponder(t *testing.T, reply func([]byte) []byte) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if r := reply(buf[:n]); r != nil {
				_, _ = pc.WriteTo(r, from)
			}
		}
	}()
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
}

func mdnsAnswer(t *testing.T, types ...string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, typ := range types {
		err := b.PTRResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("_services._dns-sd._udp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 10},
			dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(typ + ".local.")})
		if err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// A printer with no probed TCP port is found by its DNS-SD answer and
// named by the most telling service type; a speaker by its UPnP
// description on its own address.
func TestLocalDiscovery(t *testing.T) {
	desc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><root><device><friendlyName>Living Room</friendlyName><manufacturer>Sonos, Inc.</manufacturer><modelName>Sonos One</modelName><modelNumber>S18</modelNumber></device></root>`)
	}))
	t.Cleanup(desc.Close)
	mdnsPort := udpResponder(t, func(q []byte) []byte {
		var p dnsmessage.Parser
		if _, err := p.Start(q); err != nil {
			return nil
		}
		qs, err := p.AllQuestions()
		if err != nil || len(qs) != 1 || qs[0].Name.String() != "_services._dns-sd._udp.local." {
			return nil
		}
		return mdnsAnswer(t, "_ipp._tcp", "_http._tcp", "_printer._tcp")
	})
	ssdpPort := udpResponder(t, func(q []byte) []byte {
		if !strings.HasPrefix(string(q), "M-SEARCH * HTTP/1.1") {
			return nil
		}
		return []byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: " + desc.URL + "/xml/device_description.xml\r\nSERVER: Linux UPnP/1.0 Sonos/80.1\r\nST: upnp:rootdevice\r\n\r\n")
	})
	s := &Scanner{InFlight: 4, Rate: 1000, dial: (&net.Dialer{}).DialContext, mdnsPort: mdnsPort, ssdpPort: ssdpPort}
	got := s.localScan(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	svcs := got[netip.MustParseAddr("127.0.0.1")]
	if len(svcs) != 2 || svcs[0].Proto != ProtoMDNS || svcs[0].Product != "Printer" || svcs[1].Proto != ProtoSSDP || svcs[1].Product != "Sonos, Inc. Sonos One S18" {
		t.Fatalf("services %+v", svcs)
	}
	if kind, label := Classify(svcs); kind != KindOther || label != "Printer" {
		t.Errorf("classified %s %q", kind, label)
	}
}

// An address that does not answer costs one short timeout, not an error;
// a description on another address is not fetched.
func TestLocalDiscoverySilentAndForeign(t *testing.T) {
	port := udpResponder(t, func([]byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.10/desc.xml\r\nSERVER: x\r\n\r\n")
	})
	s := &Scanner{InFlight: 2, Rate: 1000, dial: (&net.Dialer{}).DialContext, mdnsPort: 1, ssdpPort: port}
	start := time.Now()
	got := s.localScan(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if svcs := got[netip.MustParseAddr("127.0.0.1")]; len(svcs) != 1 || svcs[0].Product != "x" {
		t.Errorf("services %+v, want the SSDP server header only", svcs)
	}
	if time.Since(start) > 3*localTimeout {
		t.Errorf("took %s", time.Since(start))
	}
}

const upnpFixture = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<friendlyName>my-nas</friendlyName>
<manufacturer>UGREEN</manufacturer>
<modelName>DXP4800 Plus</modelName>
<modelNumber>DXP4800</modelNumber>
<serialNumber>SN123</serialNumber>
<UDN>uuid:abcd-1</UDN>
<firmwareVersion>1.0.0.1234</firmwareVersion>
</device></root>`

func TestParseUPnPDescription(t *testing.T) {
	label, fields, ok := parseUPnPDescription(strings.NewReader(upnpFixture))
	if !ok || label != "UGREEN DXP4800 Plus DXP4800" {
		t.Fatalf("label = %q ok = %v", label, ok)
	}
	want := []Field{
		{FieldManufacturer, "UGREEN", TrustStated},
		{FieldModel, "DXP4800 Plus", TrustStated},
		{FieldModelNumber, "DXP4800", TrustStated},
		{FieldSerial, "SN123", TrustStated},
		{FieldUUID, "abcd-1", TrustStated},
		{FieldDisplayName, "my-nas", TrustDerived},
		{FieldFirmware, "1.0.0.1234", TrustStated},
	}
	if len(fields) != len(want) {
		t.Fatalf("fields = %+v", fields)
	}
	for _, w := range want {
		found := false
		for _, f := range fields {
			if f == w {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %+v in %+v", w, fields)
		}
	}
}

func TestParseUPnPDescriptionFriendlyNameFallback(t *testing.T) {
	label, _, ok := parseUPnPDescription(strings.NewReader(`<root><device><friendlyName>box</friendlyName></device></root>`))
	if !ok || label != "box" {
		t.Fatalf("label = %q ok = %v", label, ok)
	}
}

func TestParseUPnPDescriptionHostile(t *testing.T) {
	big := `<root><device><manufacturer>` + strings.Repeat("A", 300<<10) + `</manufacturer></device></root>`
	if _, fields, ok := parseUPnPDescription(strings.NewReader(big)); ok && len(fields) > fieldsPerList {
		t.Fatalf("unbounded fields: %d", len(fields))
	}

	ent := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "EXPANDED">]><root><device><modelName>&x;</modelName><manufacturer>Acme</manufacturer></device></root>`
	_, fields, _ := parseUPnPDescription(strings.NewReader(ent))
	for _, f := range fields {
		if strings.Contains(f.Value, "EXPANDED") {
			t.Fatalf("entity expanded: %+v", f)
		}
	}

	bad := "<root><device><modelName>ab\xff\xfecd</modelName><manufacturer>Acme</manufacturer></device></root>"
	_, fields, ok := parseUPnPDescription(strings.NewReader(bad))
	if ok {
		for _, f := range fields {
			if f.Value != printable(f.Value, 128) {
				t.Fatalf("value not printable: %q", f.Value)
			}
		}
	}
}
