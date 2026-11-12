// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Protocols a probed port is read with.
const (
	ProtoSSH       = "ssh"
	ProtoHTTP      = "http"
	ProtoHTTPS     = "https"
	ProtoDocker    = "docker"     // Docker Engine API without TLS
	ProtoDockerTLS = "docker-tls" // Docker Engine API with TLS
	ProtoTCP       = "tcp"        // open, not read
)

// Port is a TCP port Varde probes and how it reads the answer.
type Port struct {
	Number int
	Proto  string
}

// DefaultPorts are the ports homelab services usually listen on. The list
// is short on purpose: a scan should find hosts and the services Varde can
// integrate with, not map every open port.
var DefaultPorts = []Port{
	{22, ProtoSSH},
	{80, ProtoHTTP},
	{443, ProtoHTTPS},
	{8006, ProtoHTTPS}, // Proxmox VE
	{8007, ProtoHTTPS}, // Proxmox Backup Server
	{2375, ProtoDocker},
	{2376, ProtoDockerTLS},
	{9443, ProtoHTTPS}, // Portainer
	{8123, ProtoHTTP},  // Home Assistant
	{8080, ProtoHTTP},
	{8443, ProtoHTTPS},
	{3000, ProtoHTTP},
	{5000, ProtoHTTP},
	{5001, ProtoHTTPS},
	{81, ProtoHTTP},   // Nginx Proxy Manager admin
	{8096, ProtoHTTP}, // Jellyfin
	{4533, ProtoHTTP}, // Navidrome
	{445, ProtoTCP},
	{53, ProtoTCP},
}

// Device kinds, from the most to the least specific.
const (
	KindProxmox       = "proxmox"
	KindProxmoxBackup = "proxmox-backup"
	KindDocker        = "docker"
	KindPortainer     = "portainer"
	KindHomeAssistant = "home-assistant"
	KindNetwork       = "network"
	KindNAS           = "nas"
	KindSSH           = "ssh"
	KindWeb           = "web"
	KindOther         = "other"
)

// Service is one open port and what it announced.
type Service struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Product string `json:"product,omitempty"` // e.g. "Proxmox VE", "OpenSSH_9.2p1 Debian-2"
	Version string `json:"version,omitempty"` // only when the service states it
	// Insecure marks a service that grants access without authentication,
	// such as a Docker API on port 2375.
	Insecure bool `json:"insecure,omitempty"`
}

// Device is a host that answered on at least one port.
type Device struct {
	Address  string    `json:"address"`
	Hostname string    `json:"hostname,omitempty"`
	Kind     string    `json:"kind"`
	Label    string    `json:"label"`
	Services []Service `json:"services"`
}

// Scanner probes addresses. The zero value is not usable; use NewScanner.
type Scanner struct {
	Ports []Port
	// InFlight bounds concurrent connection attempts, Rate the new attempts
	// per second. Both keep a scan from flooding small home networks.
	InFlight int
	Rate     int
	// ConnectTimeout bounds each TCP connect, ReadTimeout each read of a
	// service answer.
	ConnectTimeout, ReadTimeout time.Duration
	// Resolve looks up host names for found devices; nil disables it.
	Resolve func(ctx context.Context, addr string) ([]string, error)
	// Local enables the unicast mDNS and SSDP queries (local.go).
	Local bool
	// SNMP, when set, reads the system description of devices that
	// answered (snmp.go).
	SNMP *SNMP

	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// mdnsPort, ssdpPort and snmpPort replace 5353, 1900 and 161 in tests.
	mdnsPort, ssdpPort, snmpPort uint16
	// inScope accepts the senders of multicast answers; nil accepts none.
	inScope func(netip.Addr) bool
}

// NewScanner returns a scanner that only connects inside scope.
func NewScanner(scope Scope) *Scanner {
	d := &net.Dialer{Timeout: 800 * time.Millisecond}
	return &Scanner{
		// 300 attempts per second lost answers at a UniFi router and
		// through Docker Desktop over WLAN, so whole hosts went missing from
		// one scan to the next; at 100 a /24 takes about four minutes and
		// finds the same hosts every time.
		Ports: DefaultPorts, InFlight: 32, Rate: 100, Local: true,
		ConnectTimeout: 800 * time.Millisecond, ReadTimeout: 3 * time.Second,
		Resolve: (&net.Resolver{}).LookupAddr,
		dial:    scope.DialContext(d),
		inScope: scope.Contains,
	}
}

type probe struct {
	addr netip.Addr
	port Port
}

// retryTimeout is the least connect timeout of the retries.
const retryTimeout = 2 * time.Second

// retryPorts are the ports a silent address is tried on again: whatever
// runs there, one of them usually answers or refuses.
var retryPorts = []int{22, 80, 443, 8006, 445, 8080, 9443, 53}

func retryPort(n int) bool { return slices.Contains(retryPorts, n) }

// scanState collects the answers of all passes of one scan.
type scanState struct {
	mu       sync.Mutex
	refused  map[netip.Addr]bool
	services map[netip.Addr][]Service
	// silent are the probes that got no answer at all (a timeout or a
	// lost packet, not a refusal).
	silent   map[probe]bool
	done     int
	total    int
	progress func(done, total int)
}

// answered reports whether an address answered on any port, or refused.
// The caller holds no lock: passes do not run concurrently.
func (st *scanState) answered(a netip.Addr) bool {
	return st.refused[a] || len(st.services[a]) > 0
}

// pass probes, at most InFlight at a time and rate new attempts per
// second, each with the given connect timeout.
func (s *Scanner) pass(ctx context.Context, st *scanState, probes []probe, timeout time.Duration, rate int) {
	if len(probes) == 0 {
		return
	}
	st.mu.Lock()
	st.total += len(probes)
	st.mu.Unlock()
	jobs := make(chan probe)
	var wg sync.WaitGroup
	for range max(1, s.InFlight) {
		wg.Go(func() {
			for p := range jobs {
				svc, up := s.probe(ctx, p, timeout)
				st.mu.Lock()
				switch {
				case svc != nil:
					st.services[p.addr] = append(st.services[p.addr], *svc)
					delete(st.silent, p)
				case up:
					st.refused[p.addr] = true
					delete(st.silent, p)
				default:
					st.silent[p] = true
				}
				st.done++
				if st.progress != nil {
					st.progress(st.done, st.total) // serialised under mu
				}
				st.mu.Unlock()
			}
		})
	}
	tick := time.NewTicker(time.Second / time.Duration(max(1, rate)))
	defer tick.Stop()
feed:
	for _, p := range probes {
		select {
		case <-ctx.Done():
			break feed
		case <-tick.C:
		}
		select {
		case <-ctx.Done():
			break feed
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()
}

// Result is the outcome of a scan.
type Result struct {
	Devices []Device
	// Intercepted lists ports that answered on almost every address. A
	// router that redirects all DNS traffic, or a transparent proxy, makes
	// a port look open everywhere; such ports are left out of the devices
	// because they say nothing about the host.
	Intercepted []int
}

// Interception thresholds: a port open on more than this share of the
// scanned addresses, and on at least interceptMin of them, is intercepted.
const (
	interceptShare = 0.6
	interceptMin   = 16
	// maxNameServers bounds the DNS servers asked for reverse names.
	maxNameServers = 2
)

// Scan probes every address on every port and returns the devices that
// answered, ordered by address. progress, if set, is called after each
// address-port pair, never concurrently. A host that refuses a connection
// is alive too: it is listed even when no probed port is open.
func (s *Scanner) Scan(ctx context.Context, addrs []netip.Addr, progress func(done, total int)) (Result, error) {
	st := &scanState{refused: map[netip.Addr]bool{}, services: map[netip.Addr][]Service{}, silent: map[probe]bool{}, progress: progress}
	var first []probe
	for _, a := range addrs {
		for _, port := range s.Ports {
			first = append(first, probe{a, port})
		}
	}
	s.pass(ctx, st, first, s.ConnectTimeout, s.Rate)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	// Connection attempts get lost: over WLAN, through Docker Desktop's
	// NAT, at a router that throttles what looks like a port scan. One lost
	// attempt must not hide a host, so what did not answer is tried again,
	// slower and with a longer timeout: on hosts that answered, the ports
	// that stayed silent; on silent addresses, the ports that tell most.
	// An address that answers only now is then probed on every port.
	slow, slowTimeout := max(1, s.Rate/3), max(retryTimeout, s.ConnectTimeout*5/2)
	var second []probe
	for _, p := range first {
		if !st.silent[p] {
			continue
		}
		if st.answered(p.addr) || retryPort(p.port.Number) {
			second = append(second, p)
		}
	}
	before := map[netip.Addr]bool{}
	for _, a := range addrs {
		before[a] = st.answered(a)
	}
	s.pass(ctx, st, second, slowTimeout, slow)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	var third []probe
	for _, p := range first {
		if !before[p.addr] && st.answered(p.addr) && st.silent[p] && !retryPort(p.port.Number) {
			third = append(third, p)
		}
	}
	s.pass(ctx, st, third, slowTimeout, slow)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	refused, services := st.refused, st.services
	if s.Local {
		// Devices without a probed TCP port (printers, speakers, smart
		// home devices) answer these; they count as found.
		for a, svcs := range s.localScan(ctx, addrs) {
			services[a] = append(services[a], svcs...)
		}
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
	}
	snmpNames := map[netip.Addr]string{}
	if s.SNMP.Enabled() {
		for a, svc := range s.snmpScan(ctx, addrs, func(a netip.Addr) bool { return refused[a] || len(services[a]) > 0 }) {
			services[a] = append(services[a], svc.svc)
			if svc.name != "" {
				snmpNames[a] = svc.name
			}
		}
	}

	var res Result
	openOn := map[int]int{}
	for _, svcs := range services {
		for _, sv := range svcs {
			openOn[sv.Port]++
		}
	}
	intercepted := map[int]bool{}
	for port, n := range openOn {
		if n >= interceptMin && float64(n) > interceptShare*float64(len(addrs)) {
			intercepted[port] = true
			res.Intercepted = append(res.Intercepted, port)
		}
	}
	sort.Ints(res.Intercepted)

	// Home routers usually answer reverse lookups for their DHCP clients;
	// the resolver of a container often cannot. Ask the first DNS servers
	// found in the scan. When port 53 is intercepted every address
	// answers, and the lowest ones (usually the router) are asked.
	var dnsServers []netip.Addr
	for a, svcs := range services {
		for _, sv := range svcs {
			if sv.Port == 53 {
				dnsServers = append(dnsServers, a)
			}
		}
	}
	sort.Slice(dnsServers, func(i, j int) bool { return dnsServers[i].Less(dnsServers[j]) })
	if len(dnsServers) > maxNameServers {
		dnsServers = dnsServers[:maxNameServers]
	}

	for a, svcs := range services {
		kept := svcs[:0]
		for _, sv := range svcs {
			if !intercepted[sv.Port] {
				kept = append(kept, sv)
			}
		}
		if len(kept) == 0 && !refused[a] {
			continue
		}
		sort.Slice(kept, func(i, j int) bool { return kept[i].Port < kept[j].Port })
		d := Device{Address: a.String(), Services: kept}
		d.Kind, d.Label = Classify(kept)
		res.Devices = append(res.Devices, d)
	}
	for a := range refused {
		if _, ok := services[a]; !ok {
			d := Device{Address: a.String(), Services: []Service{}}
			d.Kind, d.Label = Classify(nil)
			res.Devices = append(res.Devices, d)
		}
	}
	sort.Slice(res.Devices, func(i, j int) bool {
		a, _ := netip.ParseAddr(res.Devices[i].Address)
		b, _ := netip.ParseAddr(res.Devices[j].Address)
		return a.Less(b)
	})

	// Names are looked up a few at a time.
	sem := make(chan struct{}, 8)
	var nwg sync.WaitGroup
	for i := range res.Devices {
		sem <- struct{}{}
		nwg.Go(func() {
			defer func() { <-sem }()
			res.Devices[i].Hostname = s.lookupName(ctx, res.Devices[i].Address, dnsServers)
			if a, err := netip.ParseAddr(res.Devices[i].Address); err == nil && res.Devices[i].Hostname == "" {
				res.Devices[i].Hostname = snmpNames[a]
			}
		})
	}
	nwg.Wait()
	return res, nil
}

// lookupName returns the first PTR name from the given DNS servers, then
// from the system resolver.
func (s *Scanner) lookupName(ctx context.Context, addr string, servers []netip.Addr) string {
	try := func(r *net.Resolver) string {
		rctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		names, err := r.LookupAddr(rctx, addr)
		if err != nil || len(names) == 0 {
			return ""
		}
		return strings.TrimSuffix(names[0], ".")
	}
	if s.Resolve == nil {
		return ""
	}
	for _, srv := range servers {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return s.dial(ctx, network, net.JoinHostPort(srv.String(), "53"))
		}}
		if n := try(r); n != "" {
			return n
		}
	}
	rctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if names, err := s.Resolve(rctx, addr); err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

// probe connects once. up reports whether the host answered at all (an
// accepted or a refused connection); svc is set for an open port.
func (s *Scanner) probe(ctx context.Context, p probe, timeout time.Duration) (svc *Service, up bool) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target := net.JoinHostPort(p.addr.String(), strconv.Itoa(p.port.Number))
	conn, err := s.dial(cctx, "tcp", target)
	if err != nil {
		return nil, errors.Is(err, syscall.ECONNREFUSED)
	}
	_ = conn.Close()
	svc = &Service{Port: p.port.Number, Proto: p.port.Proto}
	rctx, rcancel := context.WithTimeout(ctx, s.ReadTimeout)
	defer rcancel()
	switch p.port.Proto {
	case ProtoSSH:
		s.readSSH(rctx, target, svc)
	case ProtoHTTP, ProtoHTTPS:
		s.readHTTP(rctx, target, p.port.Proto == ProtoHTTPS, svc)
	case ProtoDocker:
		s.readDocker(rctx, target, svc)
	case ProtoDockerTLS:
		s.readDockerTLS(rctx, target, svc)
	}
	return svc, true
}

var sshBanner = regexp.MustCompile(`^SSH-[0-9.]+-([!-~]{1,100})(?: ([ -~]{0,120}))?$`)

// readSSH reads the greeting an SSH server sends on its own. Nothing is
// sent.
func (s *Scanner) readSSH(ctx context.Context, target string, svc *Service) {
	conn, err := s.dial(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	line, err := bufio.NewReaderSize(io.LimitReader(conn, 512), 512).ReadString('\n')
	if err != nil && line == "" {
		return
	}
	if m := sshBanner.FindStringSubmatch(strings.TrimRight(line, "\r\n")); m != nil {
		svc.Product = strings.TrimSpace(m[1] + " " + m[2])
	}
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>([^<]{1,200})</title>`)

// fingerprintTransport reads public pages of local services. Certificates
// are not verified: homelab services mostly use self-signed ones, and the
// scan only reads what the page shows anyone; it never sends credentials.
// Integrations verify certificates by pinning (see package integrations).
func (s *Scanner) fingerprintTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           s.dial,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // read-only fingerprinting, see above
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: s.ReadTimeout,
		TLSHandshakeTimeout:   s.ReadTimeout,
	}
}

func (s *Scanner) readHTTP(ctx context.Context, target string, tlsOn bool, svc *Service) {
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	client := &http.Client{
		Transport:     s.fingerprintTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+target+"/", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "varde-discovery")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	title := ""
	if m := titleRe.FindSubmatch(body); m != nil {
		title = strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
	}
	issuer := ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		c := resp.TLS.PeerCertificates[0]
		issuer = strings.Join(append(c.Issuer.Organization, c.Issuer.CommonName), " ")
	}
	svc.Product = productFromHTTP(title, resp.Header.Get("Server"), issuer)
	if svc.Product == "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc, err := resp.Location(); err == nil && loc.Path != "" && loc.Path != "/" && len(loc.Path) <= 40 {
			svc.Product = "redirects to " + loc.Path
		}
	}
}

// genericTitle matches error and redirect pages, which say nothing about
// the service.
var genericTitle = regexp.MustCompile(`(?i)^(\d{3}\b|.*\b(moved permanently|moved temporarily|not found|bad request|forbidden|unauthorized|redirect(ing)?|error|welcome to nginx|it works)\b|apache2 .* default page)`)

// productFromHTTP names well-known services by their own page title, server
// header or certificate issuer; otherwise it keeps the title.
func productFromHTTP(title, server, issuer string) string {
	all := strings.ToLower(title + " " + server + " " + issuer)
	switch {
	case strings.Contains(all, "proxmox backup"):
		return "Proxmox Backup Server"
	case strings.Contains(all, "proxmox"):
		return "Proxmox VE"
	case strings.Contains(all, "portainer"):
		return "Portainer"
	case strings.Contains(all, "home assistant"):
		return "Home Assistant"
	case strings.Contains(all, "unifi"):
		return "UniFi OS"
	case strings.Contains(all, "synology"), strings.Contains(all, "diskstation"):
		return "Synology DSM"
	case strings.Contains(all, "truenas"):
		return "TrueNAS"
	case strings.Contains(all, "unraid"):
		return "Unraid"
	case strings.Contains(all, "qnap"):
		return "QNAP"
	case strings.Contains(all, "pi-hole"):
		return "Pi-hole"
	case strings.Contains(all, "adguard"):
		return "AdGuard Home"
	case strings.Contains(all, "opnsense"):
		return "OPNsense"
	case strings.Contains(all, "pfsense"):
		return "pfSense"
	case strings.Contains(all, "fritz!box"), strings.Contains(all, "fritzbox"):
		return "FRITZ!Box"
	}
	if title != "" && !genericTitle.MatchString(title) {
		return title
	}
	if server != "" && !strings.EqualFold(server, "nginx") && !strings.EqualFold(server, "apache") {
		return server
	}
	return ""
}

// knownProducts are named in device labels in this order of preference.
var knownProducts = []struct{ product, kind, label string }{
	{"Proxmox VE", KindProxmox, "Proxmox VE"},
	{"Proxmox Backup Server", KindProxmoxBackup, "Proxmox Backup Server"},
	{"Docker Engine", KindDocker, "Docker host (API open without authentication)"},
	{"Docker Engine (TLS)", KindDocker, "Docker host (API with TLS)"},
	{"Portainer", KindPortainer, "Portainer"},
	{"Home Assistant", KindHomeAssistant, "Home Assistant"},
	{"UniFi OS", KindNetwork, "UniFi OS (gateway or console)"},
	{"OPNsense", KindNetwork, "OPNsense"},
	{"pfSense", KindNetwork, "pfSense"},
	{"FRITZ!Box", KindNetwork, "FRITZ!Box"},
	{"Synology DSM", KindNAS, "Synology NAS"},
	{"TrueNAS", KindNAS, "TrueNAS"},
	{"Unraid", KindNAS, "Unraid"},
	{"QNAP", KindNAS, "QNAP NAS"},
	{"Pi-hole", KindWeb, "Pi-hole"},
	{"AdGuard Home", KindWeb, "AdGuard Home"},
}

func (s *Scanner) readDocker(ctx context.Context, target string, svc *Service) {
	client := &http.Client{Transport: s.fingerprintTransport()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/version", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	var v struct{ Version, APIVersion string }
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&v) != nil || v.Version == "" {
		return
	}
	svc.Product, svc.Version, svc.Insecure = "Docker Engine", v.Version, true
}

// readDockerTLS recognises a Docker daemon that requires client
// certificates: the handshake asks for one.
func (s *Scanner) readDockerTLS(ctx context.Context, target string, svc *Service) {
	conn, err := s.dial(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	asked := false
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // only observes whether a client certificate is requested
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			asked = true
			return &tls.Certificate{}, nil
		},
	})
	_ = tc.HandshakeContext(ctx)
	if asked {
		svc.Product = "Docker Engine (TLS)"
	}
}

// Classify derives a device kind and a short label from its services.
func Classify(svcs []Service) (kind, label string) {
	for _, k := range knownProducts {
		for _, s := range svcs {
			if s.Product == k.product {
				return k.kind, k.label
			}
		}
	}
	// What a device announces about itself by mDNS or UPnP names it
	// better than an SSH banner or a web page title.
	for _, proto := range []string{ProtoMDNS, ProtoSSDP, ProtoSNMP} {
		for _, s := range svcs {
			if s.Proto == proto && s.Product != "" && s.Product != "mDNS device" && s.Product != "UPnP device" {
				return KindOther, s.Product
			}
		}
	}
	for _, s := range svcs {
		if s.Proto == ProtoSSH {
			return KindSSH, sshLabel(s.Product)
		}
	}
	smb := false
	for _, s := range svcs {
		smb = smb || s.Port == 445
	}
	for _, s := range svcs {
		if (s.Proto == ProtoHTTP || s.Proto == ProtoHTTPS) && s.Product != "" && !strings.HasPrefix(s.Product, "redirects to") {
			return KindWeb, s.Product
		}
	}
	switch {
	case smb:
		return KindOther, "File server or Windows PC (SMB)"
	case len(svcs) == 0:
		return KindOther, "Device (no known service)"
	}
	for _, s := range svcs {
		if s.Proto == ProtoHTTP || s.Proto == ProtoHTTPS {
			return KindWeb, "Web service"
		}
	}
	return KindOther, fmt.Sprintf("Device (port %d open)", svcs[0].Port)
}

func sshLabel(banner string) string {
	b := strings.ToLower(banner)
	for _, os := range []struct{ hint, name string }{
		{"ubuntu", "Ubuntu"}, {"debian", "Debian"}, {"raspbian", "Raspberry Pi OS"}, {"freebsd", "FreeBSD"},
		{"alpine", "Alpine"}, {"fedora", "Fedora"}, {"dropbear", "Embedded Linux (Dropbear)"},
	} {
		if strings.Contains(b, os.hint) {
			return "Linux host (" + os.name + ")"
		}
	}
	return "SSH host"
}
