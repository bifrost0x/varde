// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KindProxmox is a Proxmox VE cluster or node read through its REST API.
const KindProxmox = "proxmox"

// ProxmoxConfig is the non-secret part of a Proxmox integration.
type ProxmoxConfig struct {
	// URL is the API base, e.g. https://192.168.1.10:8006.
	URL string `json:"url"`
	// TokenID is the API token ID, e.g. varde@pve!varde.
	TokenID string `json:"token_id"`
	// Fingerprint pins the server certificate (SHA-256 of the leaf, hex
	// with colons as Proxmox shows it). Empty means the certificate must be
	// valid for the host name under the system roots.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ProxmoxStatus is what the last successful run saw.
type ProxmoxStatus struct {
	Version string         `json:"version"`
	Nodes   []ProxmoxNode  `json:"nodes"`
	Guests  []ProxmoxGuest `json:"guests"`
}

// ProxmoxNode is one cluster node.
type ProxmoxNode struct {
	Name      string   `json:"name"`
	Online    bool     `json:"online"`
	Addresses []string `json:"addresses,omitempty"`
}

// ProxmoxGuest is a VM or container.
type ProxmoxGuest struct {
	VMID      int      `json:"vmid"`
	Name      string   `json:"name"`
	Type      string   `json:"type"` // qemu or lxc
	Node      string   `json:"node"`
	Status    string   `json:"status"`
	Tags      []string `json:"tags,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	// AddressNote explains missing addresses, for example a VM without the
	// guest agent.
	AddressNote string `json:"address_note,omitempty"`
	// MACs are the MAC addresses of the guest's network devices, from its
	// configuration.
	MACs []string `json:"macs,omitempty"`
}

const (
	proxmoxTimeout  = 15 * time.Second
	proxmoxMaxBody  = 8 << 20
	proxmoxParallel = 4
	proxmoxMaxGuest = 1000
)

// Proxmox is a read-only client for the Proxmox VE API.
type Proxmox struct {
	base   *url.URL
	auth   string
	client *http.Client
}

// NewProxmox returns a client. dial restricts connections to the allowed
// networks.
func NewProxmox(cfg ProxmoxConfig, secret string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*Proxmox, error) {
	u, err := ParseProxmoxURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if !validTokenID(cfg.TokenID) {
		return nil, errors.New("the token ID looks like user@realm!name, for example varde@pve!varde")
	}
	tlsCfg, err := pinnedTLS(u.Hostname(), cfg.Fingerprint)
	if err != nil {
		return nil, err
	}
	return &Proxmox{
		base: u,
		auth: "PVEAPIToken=" + cfg.TokenID + "=" + secret,
		client: &http.Client{
			Timeout: proxmoxTimeout,
			Transport: &http.Transport{
				Proxy: nil, DialContext: dial, TLSClientConfig: tlsCfg,
				MaxIdleConnsPerHost: proxmoxParallel, IdleConnTimeout: time.Minute,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// ParseProxmoxURL accepts "host", "host:port" or a full https URL and
// returns the API base with the default port 8006.
func ParseProxmoxURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("enter the address of a Proxmox node, for example 192.168.1.10 or https://pve.lan:8006")
	}
	if u.Scheme != "https" {
		return nil, errors.New("the Proxmox API is only used over https")
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "8006")
	}
	return &url.URL{Scheme: "https", Host: u.Host}, nil
}

func validTokenID(id string) bool {
	user, name, ok := strings.Cut(id, "!")
	if !ok || name == "" || len(id) > 128 || !strings.Contains(user, "@") {
		return false
	}
	for _, r := range id {
		if r <= ' ' || r == '=' || r > '~' {
			return false
		}
	}
	return true
}

// pinnedTLS verifies the server by fingerprint when one is pinned, else by
// the system roots and the host name.
func pinnedTLS(host, fingerprint string) (*tls.Config, error) {
	if fingerprint == "" {
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, nil
	}
	want, err := parseFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is replaced by the pin below: Proxmox nodes use a
		// self-signed certificate by default, which the user confirmed by
		// its fingerprint.
		InsecureSkipVerify: true, //nolint:gosec // pinned in VerifyConnection
		// VerifyConnection also runs for resumed sessions.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], want) {
				return errors.New("the server certificate changed: its fingerprint no longer matches the confirmed one")
			}
			return nil
		},
	}, nil
}

func parseFingerprint(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("the fingerprint is a SHA-256 value such as AB:CD:…")
	}
	return b, nil
}

// FormatFingerprint renders a SHA-256 digest as Proxmox displays it.
func FormatFingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}

// ServerFingerprint connects to addr and returns the SHA-256 fingerprint of
// the certificate it presents, so the user can compare it with the one the
// Proxmox UI shows before trusting it.
func ServerFingerprint(ctx context.Context, rawURL string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (string, error) {
	u, err := ParseProxmoxURL(rawURL)
	if err != nil {
		return "", err
	}
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

// APIError is a non-success answer of the Proxmox API.
type APIError struct {
	Path   string
	Status int
}

func (e *APIError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "Proxmox rejected the API token (check token ID and secret)"
	case http.StatusForbidden:
		return "the API token lacks a permission for " + e.Path + " (assign the PVEAuditor role on path /)"
	}
	return fmt.Sprintf("Proxmox API %s answered %d", e.Path, e.Status)
}

func (p *Proxmox) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base.String()+"/api2/json"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", p.auth)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("Proxmox API %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return &APIError{Path: path, Status: resp.StatusCode}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, proxmoxMaxBody)).Decode(&env); err != nil {
		return fmt.Errorf("Proxmox API %s: decode: %w", path, err)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("Proxmox API %s: decode data: %w", path, err)
	}
	return nil
}

// Collect reads nodes and guests. Missing addresses of single guests are
// reported per guest, not as a failure.
func (p *Proxmox) Collect(ctx context.Context) (ProxmoxStatus, error) {
	var st ProxmoxStatus
	var ver struct {
		Version string `json:"version"`
	}
	if err := p.get(ctx, "/version", &ver); err != nil {
		return st, err
	}
	st.Version = ver.Version

	var nodes []struct {
		Node   string `json:"node"`
		Status string `json:"status"`
	}
	if err := p.get(ctx, "/nodes", &nodes); err != nil {
		return st, err
	}
	for _, n := range nodes {
		if !safeSegment(n.Node) {
			continue
		}
		node := ProxmoxNode{Name: n.Node, Online: n.Status == "online"}
		if node.Online {
			node.Addresses = p.nodeAddresses(ctx, n.Node)
		}
		st.Nodes = append(st.Nodes, node)
	}

	var res []struct {
		Type     string `json:"type"`
		VMID     int    `json:"vmid"`
		Name     string `json:"name"`
		Node     string `json:"node"`
		Status   string `json:"status"`
		Template int    `json:"template"`
		Tags     string `json:"tags"`
	}
	if err := p.get(ctx, "/cluster/resources?type=vm", &res); err != nil {
		return st, err
	}
	for _, r := range res {
		if r.Template == 1 || (r.Type != "qemu" && r.Type != "lxc") || !safeSegment(r.Node) || r.VMID <= 0 {
			continue
		}
		if len(st.Guests) >= proxmoxMaxGuest {
			break
		}
		g := ProxmoxGuest{VMID: r.VMID, Name: r.Name, Type: r.Type, Node: r.Node, Status: r.Status}
		g.Tags = append(g.Tags, strings.FieldsFunc(r.Tags, func(c rune) bool { return c == ';' || c == ',' || c == ' ' })...)
		if g.Name == "" {
			g.Name = fmt.Sprintf("%s %d", r.Type, r.VMID)
		}
		st.Guests = append(st.Guests, g)
	}

	// Addresses need one request per guest; a few at a time.
	sem := make(chan struct{}, proxmoxParallel)
	var wg sync.WaitGroup
	for i := range st.Guests {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			g := &st.Guests[i]
			g.Addresses, g.AddressNote = p.guestAddresses(ctx, *g)
			g.MACs = p.guestMACs(ctx, *g)
		})
	}
	wg.Wait()
	sort.Slice(st.Guests, func(i, j int) bool { return st.Guests[i].VMID < st.Guests[j].VMID })
	return st, ctx.Err()
}

// safeSegment keeps API path segments to node-name characters.
func safeSegment(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r != '-' && r != '.' && r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

func (p *Proxmox) nodeAddresses(ctx context.Context, node string) []string {
	var ifaces []struct {
		Address  string `json:"address"`
		Address6 string `json:"address6"`
	}
	if err := p.get(ctx, "/nodes/"+node+"/network", &ifaces); err != nil {
		return nil
	}
	var out []string
	for _, i := range ifaces {
		out = appendAddr(out, i.Address)
		out = appendAddr(out, i.Address6)
	}
	return sortAddrs(out)
}

func (p *Proxmox) guestAddresses(ctx context.Context, g ProxmoxGuest) ([]string, string) {
	base := "/nodes/" + g.Node + "/" + g.Type + "/" + strconv.Itoa(g.VMID)
	var out []string
	if g.Type == "lxc" {
		if g.Status == "running" {
			var ifaces []struct {
				Name  string `json:"name"`
				Inet  string `json:"inet"`
				Inet6 string `json:"inet6"`
			}
			if err := p.get(ctx, base+"/interfaces", &ifaces); err == nil {
				for _, i := range ifaces {
					if internalInterface(i.Name) {
						continue
					}
					out = appendAddr(out, i.Inet)
					out = appendAddr(out, i.Inet6)
				}
			}
		}
		if len(out) == 0 {
			out = p.configAddresses(ctx, base, "ip=")
		}
		if len(out) == 0 {
			return nil, "no address (DHCP container that is not running)"
		}
		return sortAddrs(out), ""
	}
	if g.Status != "running" {
		out = p.configAddresses(ctx, base, "ip=")
		if len(out) == 0 {
			return nil, "VM is not running"
		}
		return sortAddrs(out), ""
	}
	var agent struct {
		Result []struct {
			Name string `json:"name"`
			IPs  []struct {
				Address string `json:"ip-address"`
			} `json:"ip-addresses"`
		} `json:"result"`
	}
	err := p.get(ctx, base+"/agent/network-get-interfaces", &agent)
	if err == nil {
		for _, i := range agent.Result {
			if internalInterface(i.Name) {
				continue
			}
			for _, ip := range i.IPs {
				out = appendAddr(out, ip.Address)
			}
		}
	}
	if len(out) == 0 {
		out = p.configAddresses(ctx, base, "ip=")
	}
	if len(out) > 0 {
		return sortAddrs(out), ""
	}
	var api *APIError
	if errors.As(err, &api) && api.Status == http.StatusForbidden {
		return nil, "address needs the VM.GuestAgent.Audit (Proxmox 9) or VM.Monitor (Proxmox 8) permission"
	}
	return nil, "address unknown: install and start the QEMU guest agent in the VM"
}

// internalInterface reports interfaces whose addresses are not reachable
// from the network: loopback and the bridges of container runtimes inside
// the guest (Docker, Podman, LXD, Kubernetes CNIs).
func internalInterface(name string) bool {
	if name == "lo" || name == "docker0" {
		return true
	}
	for _, p := range []string{"br-", "veth", "cni", "flannel", "virbr", "lxcbr", "lxdbr", "podman", "cali", "tunl", "kube", "vxlan"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var guestMAC = regexp.MustCompile(`(?i)^(?:[a-z0-9]+|hwaddr)=([0-9a-f]{2}(?::[0-9a-f]{2}){5})$`)

// guestMACs reads the MAC addresses of the guest's network devices from
// its configuration (net0 of VMs: "virtio=BC:24:11:..", of containers:
// "hwaddr=BC:24:11:..").
func (p *Proxmox) guestMACs(ctx context.Context, g ProxmoxGuest) []string {
	var cfg map[string]any
	if err := p.get(ctx, "/nodes/"+g.Node+"/"+g.Type+"/"+strconv.Itoa(g.VMID)+"/config", &cfg); err != nil {
		return nil
	}
	var out []string
	for k, v := range cfg {
		s, ok := v.(string)
		if !ok || !strings.HasPrefix(k, "net") {
			continue
		}
		for _, part := range strings.Split(s, ",") {
			if m := guestMAC.FindStringSubmatch(part); m != nil {
				out = append(out, strings.ToLower(m[1]))
			}
		}
	}
	sort.Strings(out)
	return out
}

// configAddresses reads static addresses from the guest configuration
// (net0 of containers, ipconfig0 of cloud-init VMs).
func (p *Proxmox) configAddresses(ctx context.Context, base, key string) []string {
	var cfg map[string]any
	if err := p.get(ctx, base+"/config", &cfg); err != nil {
		return nil
	}
	var out []string
	for k, v := range cfg {
		s, ok := v.(string)
		if !ok || (!strings.HasPrefix(k, "net") && !strings.HasPrefix(k, "ipconfig")) {
			continue
		}
		for _, part := range strings.Split(s, ",") {
			for _, prefix := range []string{key, "ip6="} {
				if v, ok := strings.CutPrefix(part, prefix); ok {
					out = appendAddr(out, v)
				}
			}
		}
	}
	return out
}

// appendAddr adds an address given as "a.b.c.d" or "a.b.c.d/nn", skipping
// loopback, link-local and placeholders such as "dhcp".
func appendAddr(out []string, s string) []string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return out
	}
	for _, x := range out {
		if x == a.String() {
			return out
		}
	}
	return append(out, a.String())
}

func sortAddrs(a []string) []string {
	sort.Slice(a, func(i, j int) bool {
		x, _ := netip.ParseAddr(a[i])
		y, _ := netip.ParseAddr(a[j])
		if x.Is4() != y.Is4() {
			return x.Is4()
		}
		return x.Less(y)
	})
	return a
}
