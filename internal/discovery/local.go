// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Protocols of the local discovery answers.
const (
	ProtoMDNS = "mdns"
	ProtoSSDP = "ssdp"
)

// Local discovery asks every address directly, by unicast: a DNS-SD query
// to port 5353 (RFC 6762 section 6.7 answers it to the asking port) and an
// SSDP M-SEARCH to port 1900. Both work through Docker's NAT, where
// multicast does not, and they find printers, speakers and other devices
// with no TCP port Varde probes.
const (
	localTimeout = 1500 * time.Millisecond
	// descriptionLimit bounds a UPnP device description.
	descriptionLimit = 256 << 10
)

// mdnsTypes names devices by the DNS-SD service types they announce, in
// this order of preference.
var mdnsTypes = []struct{ typ, label string }{
	{"_home-assistant._tcp", "Home Assistant"},
	{"_googlecast._tcp", "Chromecast or Google speaker"},
	{"_sonos._tcp", "Sonos speaker"},
	{"_airplay._tcp", "AirPlay device"},
	{"_raop._tcp", "AirPlay speaker"},
	{"_hap._tcp", "HomeKit accessory"},
	{"_matter._tcp", "Matter device"},
	{"_matterc._udp", "Matter device"},
	{"_ipp._tcp", "Printer"},
	{"_ipps._tcp", "Printer"},
	{"_printer._tcp", "Printer"},
	{"_pdl-datastream._tcp", "Printer"},
	{"_scanner._tcp", "Scanner"},
	{"_uscan._tcp", "Scanner"},
	{"_spotify-connect._tcp", "Spotify Connect speaker"},
	{"_esphomelib._tcp", "ESPHome device"},
	{"_shelly._tcp", "Shelly device"},
	{"_hue._tcp", "Philips Hue bridge"},
	{"_axis-video._tcp", "IP camera"},
	{"_rtsp._tcp", "Camera or media server"},
	{"_adisk._tcp", "Time Machine disk"},
	{"_afpovertcp._tcp", "Apple file server"},
	{"_smb._tcp", "File server (SMB)"},
	{"_device-info._tcp", ""},
	{"_workstation._tcp", "Computer"},
	{"_ssh._tcp", ""},
}

// localScan asks every address by mDNS and SSDP, at most InFlight at a
// time, then the local segment by multicast, and returns the services
// found per address. Many responders (routers among them) answer only
// multicast queries; those reach the devices only when Varde runs on the
// LAN segment itself (a binary, or a container with host networking).
func (s *Scanner) localScan(ctx context.Context, addrs []netip.Addr) map[netip.Addr][]Service {
	out := map[netip.Addr][]Service{}
	var mu sync.Mutex
	defer func() {
		wanted := make(map[netip.Addr]bool, len(addrs))
		for _, a := range addrs {
			wanted[a] = true
		}
		for a, svc := range s.multicast(ctx) {
			if !wanted[a] {
				continue
			}
			mu.Lock()
			if !hasProto(out[a], svc.Proto) {
				out[a] = append(out[a], svc)
			}
			mu.Unlock()
		}
	}()
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range max(1, s.InFlight) {
		wg.Go(func() {
			for a := range jobs {
				var found []Service
				if svc, ok := s.mdns(ctx, a); ok {
					found = append(found, svc)
				}
				if svc, ok := s.ssdp(ctx, a); ok {
					found = append(found, svc)
				}
				if len(found) > 0 {
					mu.Lock()
					out[a] = found
					mu.Unlock()
				}
			}
		})
	}
	tick := time.NewTicker(time.Second / time.Duration(max(1, s.Rate)))
	defer tick.Stop()
feed:
	for _, a := range addrs {
		select {
		case <-ctx.Done():
			break feed
		case <-tick.C:
		}
		select {
		case <-ctx.Done():
			break feed
		case jobs <- a:
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// mdns sends a DNS-SD service enumeration to addr:5353 and names the
// device by the service types it lists.
func (s *Scanner) mdns(ctx context.Context, a netip.Addr) (Service, bool) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0})
	b.EnableCompression()
	name := dnsmessage.MustNewName("_services._dns-sd._udp.local.")
	if b.StartQuestions() != nil || b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}) != nil {
		return Service{}, false
	}
	q, err := b.Finish()
	if err != nil {
		return Service{}, false
	}
	ans, ok := s.udpExchange(ctx, netip.AddrPortFrom(a, portOr(s.mdnsPort, 5353)), q)
	if !ok {
		return Service{}, false
	}
	types := mdnsServiceTypes(ans)
	if len(types) == 0 {
		return Service{}, false
	}
	return Service{Port: 5353, Proto: ProtoMDNS, Product: mdnsLabel(types)}, true
}

// mdnsServiceTypes reads the service types of an enumeration answer.
func mdnsServiceTypes(msg []byte) []string {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for range 64 {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type != dnsmessage.TypePTR {
			if p.SkipAnswer() != nil {
				break
			}
			continue
		}
		r, err := p.PTRResource()
		if err != nil {
			break
		}
		t := strings.TrimSuffix(strings.ToLower(r.PTR.String()), ".local.")
		if len(t) <= 64 && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// mdnsLabel picks the most telling name for a set of service types.
func mdnsLabel(types []string) string {
	for _, m := range mdnsTypes {
		for _, t := range types {
			if t == m.typ && m.label != "" {
				return m.label
			}
		}
	}
	return "mDNS device"
}

// ssdp sends a unicast M-SEARCH to addr:1900 and reads the device
// description the answer points to, when it is on the same address.
func (s *Scanner) ssdp(ctx context.Context, a netip.Addr) (Service, bool) {
	req := "M-SEARCH * HTTP/1.1\r\nHOST: " + a.String() + ":1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n"
	ans, ok := s.udpExchange(ctx, netip.AddrPortFrom(a, portOr(s.ssdpPort, 1900)), []byte(req))
	if !ok {
		return Service{}, false
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(ans)), nil)
	if err != nil {
		return Service{}, false
	}
	_ = resp.Body.Close()
	svc := Service{Port: 1900, Proto: ProtoSSDP, Product: printable(resp.Header.Get("Server"), 96)}
	if loc, err := url.Parse(resp.Header.Get("Location")); err == nil && (loc.Scheme == "http" || loc.Scheme == "https") && loc.Hostname() == a.String() {
		if d, ok := s.upnpDescription(ctx, loc.String()); ok {
			svc.Product = d
		}
	}
	if svc.Product == "" {
		svc.Product = "UPnP device"
	}
	return svc, true
}

// upnpDescription reads manufacturer and model from a UPnP device
// description.
func (s *Scanner) upnpDescription(ctx context.Context, loc string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*localTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	if err != nil {
		return "", false
	}
	client := &http.Client{Transport: s.fingerprintTransport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var doc struct {
		Device struct {
			FriendlyName string `xml:"friendlyName"`
			Manufacturer string `xml:"manufacturer"`
			ModelName    string `xml:"modelName"`
			ModelNumber  string `xml:"modelNumber"`
		} `xml:"device"`
	}
	dec := xml.NewDecoder(io.LimitReader(resp.Body, descriptionLimit))
	dec.Strict = false
	if err := dec.Decode(&doc); err != nil {
		return "", false
	}
	d := doc.Device
	parts := []string{printable(d.Manufacturer, 48), printable(d.ModelName, 64), printable(d.ModelNumber, 32)}
	label := strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
	if label == "" {
		label = printable(d.FriendlyName, 64)
	}
	return label, label != ""
}

// udpExchange sends one datagram and returns the first answer from the
// same address.
func (s *Scanner) udpExchange(ctx context.Context, to netip.AddrPort, msg []byte) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, localTimeout)
	defer cancel()
	conn, err := s.dial(ctx, "udp", to.String())
	if err != nil {
		return nil, false
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, false
	}
	buf := make([]byte, 9000)
	n, err := conn.Read(buf)
	if err != nil {
		// A timeout or a refusal (ICMP port unreachable): no answer.
		return nil, false
	}
	return buf[:n], true
}

// printable keeps a device-supplied string printable and bounded.
func printable(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= n {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func portOr(p, def uint16) uint16 {
	if p != 0 {
		return p
	}
	return def
}

func hasProto(svcs []Service, proto string) bool {
	for _, s := range svcs {
		if s.Proto == proto {
			return true
		}
	}
	return false
}

// multicast sends one DNS-SD enumeration to 224.0.0.251:5353 and one
// M-SEARCH to 239.255.255.250:1900 from an ephemeral port (answers come
// back to it, RFC 6762 section 6.7) and collects the answers of senders
// inside the scope for a short while.
func (s *Scanner) multicast(ctx context.Context) map[netip.Addr]Service {
	out := map[netip.Addr]Service{}
	if s.inScope == nil {
		return out
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return out
	}
	defer func() { _ = pc.Close() }()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("_services._dns-sd._udp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		return out
	}
	ssdpQuery := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n")
	_, _ = pc.WriteTo(q, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: int(portOr(s.mdnsPort, 5353))})
	_, _ = pc.WriteTo(ssdpQuery, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: int(portOr(s.ssdpPort, 1900))})
	deadline := time.Now().Add(2 * localTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = pc.SetReadDeadline(deadline)
	buf := make([]byte, 9000)
	for len(out) < 1024 {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		a := from.Addr().Unmap()
		if !s.inScope(a) {
			continue
		}
		msg := append([]byte(nil), buf[:n]...)
		switch from.Port() {
		case portOr(s.mdnsPort, 5353):
			if types := mdnsServiceTypes(msg); len(types) > 0 {
				if prev, ok := out[a]; !ok || prev.Proto != ProtoMDNS {
					out[a] = Service{Port: 5353, Proto: ProtoMDNS, Product: mdnsLabel(types)}
				}
			}
		case portOr(s.ssdpPort, 1900):
			if _, ok := out[a]; !ok {
				if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(msg)), nil); err == nil {
					_ = resp.Body.Close()
					product := printable(resp.Header.Get("Server"), 96)
					if product == "" {
						product = "UPnP device"
					}
					out[a] = Service{Port: 1900, Proto: ProtoSSDP, Product: product}
				}
			}
		}
	}
	return out
}
