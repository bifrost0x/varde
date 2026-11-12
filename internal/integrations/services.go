// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // HTTP digest auth of the Fritz!Box is defined with MD5 (RFC 2617)
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/exposure"
)

// Kinds of the integrations with homelab services. Each reads with the
// narrowest credential the service offers (ADR 0024).
const (
	KindTraefik  = "traefik"
	KindNPM      = "npm"
	KindFritzBox = "fritzbox"
	KindOPNsense = "opnsense"
	KindUniFi    = "unifi"
)

// ServiceKinds lists the service integrations with their setup text.
var ServiceKinds = map[string]ServiceKind{
	KindTraefik: {Name: "Traefik", DefaultPort: 8080, Routes: true, UserOptional: true,
		Setup: "Traefik's API only reads. If the dashboard is behind basic auth, enter that user and password; with api.insecure no credential is needed."},
	KindNPM: {Name: "Nginx Proxy Manager", DefaultPort: 81, Routes: true,
		Setup: "Create a user with the role user and the permission Proxy Hosts: View, visibility All. Varde signs in as that user."},
	KindFritzBox: {Name: "Fritz!Box", DefaultPort: 49443, Clients: true, DefaultTLS: true,
		Setup: "Create a Fritz!Box user without any rights ticked; reading the host list needs none. Allow access for applications (TR-064) under Home Network > Network > Network Settings. Varde also asks for the FRITZ!OS version (DeviceInfo); where the box refuses it to a user without rights, only the host list is read."},
	KindOPNsense: {Name: "OPNsense", DefaultPort: 443, Clients: true, DefaultTLS: true,
		Setup: "Create a user with only the privileges Diagnostics: ARP Table and Services: ISC DHCPv4: Leases, then an API key for it. Enter the key as user and the secret as password."},
	KindUniFi: {Name: "UniFi", DefaultPort: 443, Clients: true, DefaultTLS: true, UserOptional: true,
		Setup: "Needs UniFi Network 9.0 or later. Create an API key in the Network app's integration settings (in many versions Settings > Control Plane > Integrations, or open /network/default/integrations on the console; the place differs between versions). UniFi lets only an admin with full rights create a key, and there are no read-only keys: the key carries the rights of that admin, so keep it secret and remove it in UniFi when you no longer use it. Leave the user empty and enter the key as secret. Varde only sends read requests, for the client list and the firmware state of the devices."},
	KindSynology: {Name: "Synology DSM", DefaultPort: 5001, DefaultTLS: true, Appliance: true,
		Setup: "Create a DSM user without admin rights and without two-factor sign-in, and deny it every application except DSM itself. Varde signs in with it, reads the DSM version (SYNO.DSM.Info) and signs out again."},
	KindQNAP: {Name: "QNAP", DefaultPort: 443, DefaultTLS: true, Appliance: true, UserOptional: true, NoSecret: true,
		Setup: "No credential: QNAP's sign-in page reports the firmware version (/cgi-bin/authLogin.cgi). Leave user and secret empty."},
	KindTrueNAS: {Name: "TrueNAS", DefaultPort: 443, DefaultTLS: true, Appliance: true, UserOptional: true,
		Setup: "Create an API key for a user with a read-only role (Credentials > Users, role Read-only Administrator; then API Keys). Leave the user empty and enter the key as secret. Varde reads /api/v2.0/system/version."},
	KindUnraid: {Name: "Unraid", DefaultPort: 443, DefaultTLS: true, Appliance: true, UserOptional: true,
		Setup: "Needs the Unraid API (Unraid 7.2 or later, or the Unraid Connect plugin). Create an API key with read access to system information (Settings > Management Access > API Keys). Leave the user empty and enter the key as secret."},
	KindHomeAssistant: {Name: "Home Assistant", DefaultPort: 8123, Appliance: true, UserOptional: true,
		Setup: "For Home Assistant OS or Supervised, whose Core Varde cannot see as a container. Create a user without admin rights, sign in as it and create a long-lived access token under the profile's Security tab. Leave the user empty and enter the token as secret. Varde reads /api/config."},
}

// ServiceKind describes a service integration.
type ServiceKind struct {
	Name        string
	DefaultPort int
	DefaultTLS  bool
	// Routes: the service reports reverse proxy routes; Clients: LAN
	// clients with MAC and name.
	Routes, Clients bool
	// UserOptional: the service may run without a credential.
	UserOptional bool
	// Appliance: the integration reports the system's own operating
	// system or firmware version (ApplianceSystem); NoSecret: it needs no
	// credential at all.
	Appliance, NoSecret bool
	Setup               string
}

// ServiceConfig is the non-secret part of a service integration.
type ServiceConfig struct {
	URL  string `json:"url"`
	User string `json:"user,omitempty"`
	// Fingerprint pins the server certificate for https.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ParseServiceURL accepts host, host:port or an http(s) URL and returns the
// base URL (scheme and host only).
func ParseServiceURL(raw string, kind ServiceKind) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		scheme := "http"
		if kind.DefaultTLS {
			scheme = "https"
		}
		raw = scheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("enter the address of the service, for example 192.168.1.1 or https://router.lan")
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(kind.DefaultPort))
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// TLSFingerprint returns the SHA-256 fingerprint of the certificate the
// server presents, for the user to confirm before it is pinned.
func TLSFingerprint(ctx context.Context, u *url.URL, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", u.Host)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s: %w", u.Host, err)
	}
	defer func() { _ = conn.Close() }()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // only reads the certificate to show its fingerprint
	if err := tc.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("TLS handshake with %s failed: %w", u.Host, err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("the server sent no certificate")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return FormatFingerprint(sum[:]), nil
}

// serviceClient talks to one service: scope-checked dialer, pinned
// certificate for https, no redirects, bounded responses.
type serviceClient struct {
	base   *url.URL
	user   string
	secret string
	http   *http.Client
}

const serviceBodyLimit = 8 << 20

func newServiceClient(cfg ServiceConfig, kind ServiceKind, secret string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*serviceClient, error) {
	u, err := ParseServiceURL(cfg.URL, kind)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{Proxy: nil, DialContext: dial, IdleConnTimeout: time.Minute}
	if u.Scheme == "https" {
		if cfg.Fingerprint == "" {
			return nil, errors.New("confirm the certificate fingerprint first")
		}
		if tr.TLSClientConfig, err = pinnedTLS(u.Hostname(), cfg.Fingerprint); err != nil {
			return nil, err
		}
	}
	return &serviceClient{base: u, user: cfg.User, secret: secret, http: &http.Client{
		Timeout: 20 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// do sends a request and returns the body of a 2xx answer.
func (c *serviceClient) do(ctx context.Context, method, path string, body []byte, hdr map[string]string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "varde")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, serviceBodyLimit+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > serviceBodyLimit {
		return nil, nil, errors.New("the answer is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return b, resp.Header, &ServiceError{Path: path, Status: resp.StatusCode}
	}
	return b, resp.Header, nil
}

// ServiceError is a non-success answer, with the next step in its text.
type ServiceError struct {
	Path   string
	Status int
}

func (e *ServiceError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "the service rejected the credential (401); check user and password or key"
	case http.StatusForbidden:
		return "the credential lacks a permission for " + e.Path + " (403); see the setup text for the one it needs"
	case http.StatusNotFound:
		return e.Path + " does not exist on this service (404); check the address and the version"
	}
	return fmt.Sprintf("%s answered %d", e.Path, e.Status)
}

// Route is a host name a reverse proxy serves and where it forwards to.
type Route struct {
	Host     string   `json:"host"`
	Backends []string `json:"backends"`
}

// LANClient is a device a router or DHCP server knows.
type LANClient struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
	Name string `json:"name,omitempty"`
}

// NetworkDevice is a device a network controller manages (switch, access
// point, gateway), with its firmware.
type NetworkDevice struct {
	Name     string `json:"name,omitempty"`
	Model    string `json:"model,omitempty"`
	MAC      string `json:"mac,omitempty"`
	IP       string `json:"ip,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	// Updatable is set when the controller offers a newer firmware.
	Updatable bool `json:"updatable,omitempty"`
}

// ServiceStatus is what the last successful read saw.
type ServiceStatus struct {
	Routes  []Route         `json:"routes,omitempty"`
	Clients []LANClient     `json:"clients,omitempty"`
	Devices []NetworkDevice `json:"devices,omitempty"`
	// System is what an appliance reports about itself.
	System *ApplianceSystem `json:"system,omitempty"`
}

// readService reads the routes or clients of one service.
func readService(ctx context.Context, kind string, c *serviceClient) (ServiceStatus, error) {
	switch kind {
	case KindTraefik:
		r, err := traefikRoutes(ctx, c)
		return ServiceStatus{Routes: r}, err
	case KindNPM:
		r, err := npmRoutes(ctx, c)
		return ServiceStatus{Routes: r}, err
	case KindFritzBox:
		cl, err := fritzClients(ctx, c)
		if err != nil {
			return ServiceStatus{}, err
		}
		// The firmware needs no more rights on many boxes; where it is
		// refused, the client list still counts.
		sys, _ := fritzSystem(ctx, c)
		return ServiceStatus{Clients: cl, System: sys}, nil
	case KindOPNsense:
		cl, err := opnsenseClients(ctx, c)
		return ServiceStatus{Clients: cl}, err
	case KindUniFi:
		cl, sites, err := unifiClients(ctx, c)
		if err != nil {
			return ServiceStatus{}, err
		}
		// The devices and their firmware come with the same rights; a
		// controller that does not answer them still gives its clients.
		devs, _ := unifiDevices(ctx, c, sites)
		return ServiceStatus{Clients: cl, Devices: devs}, nil
	}
	if ServiceKinds[kind].Appliance {
		sys, err := readAppliance(ctx, kind, c)
		return ServiceStatus{System: sys}, err
	}
	return ServiceStatus{}, fmt.Errorf("unknown service kind %q", kind)
}

func (c *serviceClient) basic() map[string]string {
	if c.user == "" {
		return nil
	}
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(c.user, c.secret)
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

// traefikRoutes reads the HTTP routers and services (GET only; the API has
// no writes) and resolves each router's host names to its backends.
func traefikRoutes(ctx context.Context, c *serviceClient) ([]Route, error) {
	var routers []struct {
		Rule    string `json:"rule"`
		Service string `json:"service"`
		Status  string `json:"status"`
	}
	var services []struct {
		Name         string `json:"name"`
		LoadBalancer struct {
			Servers []struct {
				URL string `json:"url"`
			} `json:"servers"`
		} `json:"loadBalancer"`
	}
	if err := c.pages(ctx, "/api/http/routers", &routers); err != nil {
		return nil, err
	}
	if err := c.pages(ctx, "/api/http/services", &services); err != nil {
		return nil, err
	}
	backends := map[string][]string{}
	for _, s := range services {
		for _, srv := range s.LoadBalancer.Servers {
			if u, err := url.Parse(srv.URL); err == nil && u.Host != "" {
				backends[s.Name] = append(backends[s.Name], u.Host)
			}
		}
	}
	var out []Route
	for _, r := range routers {
		svc := r.Service
		if !strings.Contains(svc, "@") {
			// Router services without a provider suffix refer to the
			// router's own provider; the service list names them with it.
			for name := range backends {
				if strings.HasPrefix(name, svc+"@") {
					svc = name
					break
				}
			}
		}
		for _, h := range exposure.RuleHosts(r.Rule) {
			out = append(out, Route{Host: h, Backends: backends[svc]})
		}
	}
	return sortRoutes(out), nil
}

// pagesBudget bounds the bytes of all pages of one list together; a
// homelab Traefik has a few hundred routers.
const pagesBudget = 16 << 20

// pages follows Traefik's X-Next-Page, at most 50 pages of 100 and
// pagesBudget bytes in all.
func (c *serviceClient) pages(ctx context.Context, path string, out any) error {
	var all []json.RawMessage
	page, total := "1", 0
	for i := 0; i < 50 && page != ""; i++ {
		b, hdr, err := c.do(ctx, http.MethodGet, path+"?per_page=100&page="+url.QueryEscape(page), nil, c.basic())
		if err != nil {
			return err
		}
		if total += len(b); total > pagesBudget {
			return fmt.Errorf("%s: answer larger than %d MB", path, pagesBudget>>20)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(b, &items); err != nil {
			return fmt.Errorf("%s: unexpected answer: %w", path, err)
		}
		all = append(all, items...)
		page = hdr.Get("X-Next-Page")
		if n, err := strconv.Atoi(page); err != nil || n <= i+1 {
			page = ""
		}
	}
	raw, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// npmRoutes signs in with a view-only user and reads the proxy hosts.
func npmRoutes(ctx context.Context, c *serviceClient) ([]Route, error) {
	body, err := json.Marshal(map[string]string{"identity": c.user, "secret": c.secret})
	if err != nil {
		return nil, err
	}
	b, _, err := c.do(ctx, http.MethodPost, "/api/tokens", body, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, err
	}
	var tok struct {
		Token       string `json:"token"`
		RequiresTwo bool   `json:"requires_2fa"`
	}
	if err := json.Unmarshal(b, &tok); err != nil {
		return nil, fmt.Errorf("unexpected sign-in answer: %w", err)
	}
	if tok.RequiresTwo || tok.Token == "" {
		return nil, errors.New("the user has two-factor authentication; use a dedicated view-only user without it")
	}
	b, _, err = c.do(ctx, http.MethodGet, "/api/nginx/proxy-hosts", nil, map[string]string{"Authorization": "Bearer " + tok.Token})
	if err != nil {
		return nil, err
	}
	var hosts []struct {
		Domains     []string `json:"domain_names"`
		ForwardHost string   `json:"forward_host"`
		ForwardPort int      `json:"forward_port"`
		Enabled     any      `json:"enabled"`
	}
	if err := json.Unmarshal(b, &hosts); err != nil {
		return nil, fmt.Errorf("unexpected proxy host list: %w", err)
	}
	var out []Route
	for _, h := range hosts {
		if on, ok := h.Enabled.(bool); ok && !on {
			continue
		}
		if f, ok := h.Enabled.(float64); ok && f == 0 {
			continue
		}
		backend := net.JoinHostPort(h.ForwardHost, strconv.Itoa(h.ForwardPort))
		for _, d := range h.Domains {
			out = append(out, Route{Host: strings.ToLower(d), Backends: []string{backend}})
		}
	}
	return sortRoutes(out), nil
}

func sortRoutes(rs []Route) []Route {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Host < rs[j].Host })
	return rs
}

// opnsenseClients reads the ARP table and, when the privilege is granted,
// the ISC DHCPv4 leases (for host names).
func opnsenseClients(ctx context.Context, c *serviceClient) ([]LANClient, error) {
	b, _, err := c.do(ctx, http.MethodGet, "/api/diagnostics/interface/get_arp", nil, c.basic())
	if err != nil {
		return nil, err
	}
	var arp []struct {
		IP       string `json:"ip"`
		MAC      string `json:"mac"`
		Hostname string `json:"hostname"`
		Expired  bool   `json:"expired"`
	}
	if err := json.Unmarshal(b, &arp); err != nil {
		return nil, fmt.Errorf("unexpected ARP table: %w", err)
	}
	names := map[string]string{}
	if b, _, err := c.do(ctx, http.MethodGet, "/api/dhcpv4/leases/search_lease", nil, c.basic()); err == nil {
		var leases struct {
			Rows []struct {
				Address  string `json:"address"`
				MAC      string `json:"mac"`
				Hostname string `json:"hostname"`
			} `json:"rows"`
		}
		if json.Unmarshal(b, &leases) == nil {
			for _, l := range leases.Rows {
				names[strings.ToLower(l.MAC)] = l.Hostname
			}
		}
	}
	var out []LANClient
	for _, a := range arp {
		if a.Expired {
			continue
		}
		mac := strings.ToLower(a.MAC)
		name := a.Hostname
		if n := names[mac]; n != "" {
			name = n
		}
		if cl, ok := lanClient(a.IP, mac, name); ok {
			out = append(out, cl)
		}
	}
	return out, nil
}

// fritzClients reads the host table over TR-064 (Hosts:1), entry by entry;
// a user without any rights may call these actions.
func fritzClients(ctx context.Context, c *serviceClient) ([]LANClient, error) {
	n, err := c.fritzAction(ctx, "GetHostNumberOfEntries", "")
	if err != nil {
		return nil, err
	}
	count, err := strconv.Atoi(n["NewHostNumberOfEntries"])
	if err != nil || count < 0 {
		return nil, errors.New("unexpected host count from the Fritz!Box")
	}
	if count > 1000 {
		count = 1000
	}
	var out []LANClient
	for i := range count {
		e, err := c.fritzAction(ctx, "GetGenericHostEntry", "<NewIndex>"+strconv.Itoa(i)+"</NewIndex>")
		if err != nil {
			return nil, err
		}
		if e["NewActive"] != "1" {
			continue
		}
		if cl, ok := lanClient(e["NewIPAddress"], strings.ToLower(e["NewMACAddress"]), e["NewHostName"]); ok {
			out = append(out, cl)
		}
	}
	return out, nil
}

const fritzService = "urn:dslforum-org:service:Hosts:1"

// fritzDeviceInfo is the TR-064 service that reports model and firmware.
const fritzDeviceInfo = "urn:dslforum-org:service:DeviceInfo:1"

// fritzAction calls one SOAP action of the Hosts service with HTTP digest
// authentication.
func (c *serviceClient) fritzAction(ctx context.Context, action, args string) (map[string]string, error) {
	return c.tr064(ctx, fritzService, "/upnp/control/hosts", action, args)
}

// tr064 calls one SOAP action of a TR-064 service.
func (c *serviceClient) tr064(ctx context.Context, service, path, action, args string) (map[string]string, error) {
	body := []byte(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:` + action + ` xmlns:u="` + service + `">` + args + `</u:` + action + `></s:Body></s:Envelope>`)
	hdr := map[string]string{"Content-Type": `text/xml; charset="utf-8"`, "SoapAction": service + "#" + action}
	b, h, err := c.do(ctx, http.MethodPost, path, body, hdr)
	var se *ServiceError
	if errors.As(err, &se) && se.Status == http.StatusUnauthorized {
		auth, derr := digestAuth(h.Get("WWW-Authenticate"), c.user, c.secret, http.MethodPost, path)
		if derr != nil {
			return nil, derr
		}
		hdr["Authorization"] = auth
		b, _, err = c.do(ctx, http.MethodPost, path, body, hdr)
	}
	if err != nil {
		return nil, err
	}
	return soapValues(b)
}

// soapValues returns the child elements of the action response.
func soapValues(b []byte) (map[string]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	out := map[string]string{}
	var cur string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("unexpected TR-064 answer: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			cur = t.Name.Local
		case xml.CharData:
			if strings.HasPrefix(cur, "New") {
				out[cur] = strings.TrimSpace(string(t))
			}
		case xml.EndElement:
			cur = ""
		}
	}
}

// digestAuth builds an RFC 2617 Authorization header (qop=auth, MD5).
func digestAuth(challenge, user, pass, method, uri string) (string, error) {
	if !strings.HasPrefix(challenge, "Digest ") {
		return "", errors.New("the Fritz!Box asked for an unsupported authentication")
	}
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Digest "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			params[strings.ToLower(k)] = strings.Trim(v, `"`)
		}
	}
	realm, nonce := params["realm"], params["nonce"]
	if nonce == "" {
		return "", errors.New("the Fritz!Box sent no digest nonce")
	}
	h := func(s string) string {
		sum := md5.Sum([]byte(s)) //nolint:gosec // RFC 2617 digest
		return hex.EncodeToString(sum[:])
	}
	cb := make([]byte, 8)
	if _, err := rand.Read(cb); err != nil {
		return "", err
	}
	cnonce, nc := hex.EncodeToString(cb), "00000001"
	ha1, ha2 := h(user+":"+realm+":"+pass), h(method+":"+uri)
	resp := h(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	return fmt.Sprintf(`Digest username=%q, realm=%q, nonce=%q, uri=%q, qop=auth, nc=%s, cnonce=%q, response=%q`,
		user, realm, nonce, uri, nc, cnonce, resp), nil
}

func lanClient(ip, mac, name string) (LANClient, bool) {
	addr, err := netipParse(ip)
	if err != nil || !macAddr.MatchString(mac) || mac == "00:00:00:00:00:00" {
		return LANClient{}, false
	}
	if !hostLine.MatchString(name) {
		name = ""
	}
	return LANClient{IP: addr, MAC: mac, Name: name}, true
}

func netipParse(s string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "", errors.New("invalid address")
	}
	return ip.String(), nil
}

// serviceReadTimeout bounds one read of a service, during setup and on
// schedule (a Fritz!Box answers its host table entry by entry).
const serviceReadTimeout = 2 * time.Minute

// unifiSiteID is the form of a site ID of the UniFi Network integration API;
// it goes into a request path.
var unifiSiteID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// unifiClients reads the connected clients of every site through the
// official UniFi Network integration API (Network 9.0+), with an API key.
// Pages of 200, at most 50 per site and pagesBudget bytes in all.
func unifiClients(ctx context.Context, c *serviceClient) ([]LANClient, []string, error) {
	hdr := map[string]string{"X-API-Key": c.secret, "Accept": "application/json"}
	b, _, err := c.do(ctx, http.MethodGet, "/proxy/network/integration/v1/sites?limit=50", nil, hdr)
	if err != nil {
		return nil, nil, err
	}
	var sites struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &sites); err != nil {
		return nil, nil, fmt.Errorf("unexpected site list: %w", err)
	}
	if len(sites.Data) == 0 {
		return nil, nil, errors.New("the API key sees no site")
	}
	var out []LANClient
	var ids []string
	total := len(b)
	for _, site := range sites.Data {
		if !unifiSiteID.MatchString(site.ID) {
			continue
		}
		ids = append(ids, site.ID)
		for offset, page := 0, 0; page < 50; page++ {
			b, _, err := c.do(ctx, http.MethodGet, "/proxy/network/integration/v1/sites/"+site.ID+"/clients?limit=200&offset="+strconv.Itoa(offset), nil, hdr)
			if err != nil {
				return nil, nil, err
			}
			if total += len(b); total > pagesBudget {
				return nil, nil, fmt.Errorf("client list larger than %d MB", pagesBudget>>20)
			}
			var clients struct {
				TotalCount int `json:"totalCount"`
				Data       []struct {
					Name       string `json:"name"`
					IPAddress  string `json:"ipAddress"`
					MACAddress string `json:"macAddress"`
				} `json:"data"`
			}
			if err := json.Unmarshal(b, &clients); err != nil {
				return nil, nil, fmt.Errorf("unexpected client list: %w", err)
			}
			for _, cl := range clients.Data {
				if lc, ok := lanClient(cl.IPAddress, strings.ToLower(cl.MACAddress), cl.Name); ok {
					out = append(out, lc)
				}
			}
			offset += len(clients.Data)
			if len(clients.Data) == 0 || offset >= clients.TotalCount {
				break
			}
		}
	}
	return out, ids, nil
}

// maxNetworkDevices bounds the devices kept per controller.
const maxNetworkDevices = 2000

// unifiDevices reads the adopted devices of the sites with their firmware
// version and whether the controller offers an update.
func unifiDevices(ctx context.Context, c *serviceClient, sites []string) ([]NetworkDevice, error) {
	hdr := map[string]string{"X-API-Key": c.secret, "Accept": "application/json"}
	var out []NetworkDevice
	total := 0
	for _, site := range sites {
		for offset, page := 0, 0; page < 20; page++ {
			b, _, err := c.do(ctx, http.MethodGet, "/proxy/network/integration/v1/sites/"+site+"/devices?limit=200&offset="+strconv.Itoa(offset), nil, hdr)
			if err != nil {
				return out, err
			}
			if total += len(b); total > pagesBudget {
				return out, fmt.Errorf("device list larger than %d MB", pagesBudget>>20)
			}
			var devs struct {
				TotalCount int `json:"totalCount"`
				Data       []struct {
					Name              string `json:"name"`
					Model             string `json:"model"`
					MACAddress        string `json:"macAddress"`
					IPAddress         string `json:"ipAddress"`
					FirmwareVersion   string `json:"firmwareVersion"`
					FirmwareUpdatable bool   `json:"firmwareUpdatable"`
				} `json:"data"`
			}
			if err := json.Unmarshal(b, &devs); err != nil {
				return out, fmt.Errorf("unexpected device list: %w", err)
			}
			for _, d := range devs.Data {
				if len(out) >= maxNetworkDevices {
					return out, nil
				}
				out = append(out, NetworkDevice{Name: clip(d.Name, 128), Model: clip(d.Model, 64), MAC: clip(strings.ToLower(d.MACAddress), 17),
					IP: clip(d.IPAddress, 45), Firmware: clip(d.FirmwareVersion, 64), Updatable: d.FirmwareUpdatable})
			}
			offset += len(devs.Data)
			if len(devs.Data) == 0 || offset >= devs.TotalCount {
				break
			}
		}
	}
	return out, nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
