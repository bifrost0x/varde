// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"crypto/md5" //nolint:gosec // checks the RFC 2617 digest the client sends
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func serviceFor(t *testing.T, kind string, h http.Handler, user, secret string) *serviceClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := newServiceClient(ServiceConfig{URL: srv.URL, User: user}, ServiceKinds[kind], secret, plainDial)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTraefikRoutes(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Traefik got %s", r.Method)
		}
		page := r.URL.Query().Get("page")
		switch {
		case r.URL.Path == "/api/http/routers" && page == "1":
			w.Header().Set("X-Next-Page", "2")
			_, _ = io.WriteString(w, `[{"rule":"Host(`+"`photos.example.com`"+`)","service":"immich","status":"enabled"}]`)
		case r.URL.Path == "/api/http/routers" && page == "2":
			w.Header().Set("X-Next-Page", "1")
			_, _ = io.WriteString(w, `[{"rule":"Host(`+"`vault.example.com`"+`) || Host(`+"`vw.lan`"+`)","service":"vw@docker"}]`)
		case r.URL.Path == "/api/http/services":
			_, _ = io.WriteString(w, `[{"name":"immich@docker","loadBalancer":{"servers":[{"url":"http://10.10.1.41:2283"}]}},{"name":"vw@docker","loadBalancer":{"servers":[{"url":"http://172.18.0.5:80"}]}}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	routes, err := traefikRoutes(t.Context(), serviceFor(t, KindTraefik, h, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range routes {
		got[r.Host] = strings.Join(r.Backends, ",")
	}
	if len(routes) != 3 || got["photos.example.com"] != "10.10.1.41:2283" || got["vw.lan"] != "172.18.0.5:80" {
		t.Errorf("routes %+v", routes)
	}
}

func TestNPMRoutes(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tokens":
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["identity"] != "viewer@example.com" || in["secret"] != "pw" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"token":"tok","expires":"2026-12-01"}`)
		case "/api/nginx/proxy-hosts":
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `[{"domain_names":["Cloud.example.com"],"forward_host":"10.10.1.50","forward_port":8080,"enabled":true},{"domain_names":["old.example.com"],"forward_host":"10.10.1.9","forward_port":80,"enabled":false}]`)
		}
	})
	routes, err := npmRoutes(t.Context(), serviceFor(t, KindNPM, h, "viewer@example.com", "pw"))
	if err != nil || len(routes) != 1 || routes[0].Host != "cloud.example.com" || routes[0].Backends[0] != "10.10.1.50:8080" {
		t.Fatalf("routes %+v %v", routes, err)
	}
	if _, err := npmRoutes(t.Context(), serviceFor(t, KindNPM, h, "viewer@example.com", "wrong")); err == nil || !strings.Contains(err.Error(), "rejected the credential") {
		t.Errorf("wrong password: %v", err)
	}
}

func TestFritzClientsWithDigest(t *testing.T) {
	const user, pass, realm, nonce = "varde", "secret", "F!Box SOAP-Auth", "abc123"
	entries := []string{
		`<NewIPAddress>192.168.178.20</NewIPAddress><NewMACAddress>BC:24:11:00:00:01</NewMACAddress><NewHostName>media</NewHostName><NewActive>1</NewActive>`,
		`<NewIPAddress>192.168.178.30</NewIPAddress><NewMACAddress>AA:BB:CC:00:00:02</NewMACAddress><NewHostName>off</NewHostName><NewActive>0</NewActive>`,
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Digest ") {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm=%q, nonce=%q, algorithm=MD5, qop="auth"`, realm, nonce))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p := map[string]string{}
		for _, part := range strings.Split(strings.TrimPrefix(auth, "Digest "), ", ") {
			k, v, _ := strings.Cut(part, "=")
			p[k] = strings.Trim(v, `"`)
		}
		md := func(s string) string { s2 := md5.Sum([]byte(s)); return hex.EncodeToString(s2[:]) } //nolint:gosec // RFC 2617
		want := md(md(user+":"+realm+":"+pass) + ":" + nonce + ":" + p["nc"] + ":" + p["cnonce"] + ":auth:" + md("POST:/upnp/control/hosts"))
		if p["response"] != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var out string
		switch {
		case strings.Contains(string(body), "GetHostNumberOfEntries"):
			out = `<NewHostNumberOfEntries>2</NewHostNumberOfEntries>`
		case strings.Contains(string(body), "<NewIndex>0</NewIndex>"):
			out = entries[0]
		default:
			out = entries[1]
		}
		_, _ = io.WriteString(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:R xmlns:u="`+fritzService+`">`+out+`</u:R></s:Body></s:Envelope>`)
	})
	clients, err := fritzClients(t.Context(), serviceFor(t, KindFritzBox, h, user, pass))
	if err != nil || len(clients) != 1 || clients[0].MAC != "bc:24:11:00:00:01" || clients[0].Name != "media" {
		t.Fatalf("clients %+v %v", clients, err)
	}
}

func TestOPNsenseClients(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "key" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/diagnostics/interface/get_arp":
			_, _ = io.WriteString(w, `[{"ip":"10.10.1.41","mac":"BC:24:11:00:02:02","hostname":"","expired":false},{"ip":"10.10.1.99","mac":"aa:bb:cc:dd:ee:ff","hostname":"printer","expired":true}]`)
		default:
			// The lease privilege was not granted.
			w.WriteHeader(http.StatusForbidden)
		}
	})
	clients, err := opnsenseClients(t.Context(), serviceFor(t, KindOPNsense, h, "key", "secret"))
	if err != nil || len(clients) != 1 || clients[0].IP != "10.10.1.41" {
		t.Fatalf("clients %+v %v", clients, err)
	}
}

// https needs a confirmed fingerprint; a changed certificate is refused.
func TestServicePinnedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `[]`) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if _, err := newServiceClient(ServiceConfig{URL: srv.URL}, ServiceKinds[KindTraefik], "", plainDial); err == nil {
		t.Error("https without a fingerprint accepted")
	}
	fp, err := TLSFingerprint(t.Context(), u, plainDial)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(srv.Certificate().Raw)
	if fp != FormatFingerprint(sum[:]) {
		t.Fatal("fingerprint differs from the certificate")
	}
	c, err := newServiceClient(ServiceConfig{URL: srv.URL, Fingerprint: fp}, ServiceKinds[KindTraefik], "", plainDial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := traefikRoutes(t.Context(), c); err != nil {
		t.Errorf("pinned: %v", err)
	}
	other := strings.Repeat("AB:", 31) + "AB"
	c, _ = newServiceClient(ServiceConfig{URL: srv.URL, Fingerprint: other}, ServiceKinds[KindTraefik], "", plainDial)
	if _, err := traefikRoutes(t.Context(), c); err == nil {
		t.Error("changed certificate accepted")
	}
}

// LAN clients become device records keyed by MAC, so they tie into the
// machines of other sources.
func TestStoreServiceClients(t *testing.T) {
	m, st := newManager(t)
	in := store.Integration{ID: "fb", Kind: KindFritzBox, Name: "Fritz!Box 192.168.178.1", Address: "192.168.178.1", Enabled: true, CreatedAt: time.Now()}
	if err := st.CreateIntegration(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	status := ServiceStatus{Clients: []LANClient{{IP: "192.168.178.20", MAC: "bc:24:11:00:00:01", Name: "media"}, {IP: "192.168.178.21", MAC: "bc:24:11:00:00:01"}}}
	if err := m.storeService(t.Context(), in, status, time.Now()); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.Hosts(t.Context())
	n := 0
	for _, h := range hosts {
		if h.IntegrationID == "fb" {
			n++
			if h.Source != inventory.SourceLease || h.MACs[0] != "bc:24:11:00:00:01" || h.Name != "media" {
				t.Errorf("host %+v", h)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d records for one MAC", n)
	}
}

// A proxy that keeps sending pages is cut off by one byte budget for all
// pages together, not 50 pages of 8 MB each.
func TestTraefikPagesBudget(t *testing.T) {
	big := "[" + strings.Repeat(`{"name":"`+strings.Repeat("x", 1000)+`"},`, 4000) + `{"name":"y"}]`
	c := serviceFor(t, KindTraefik, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Next-Page", fmt.Sprint(atoi(r.URL.Query().Get("page"))+1))
		_, _ = w.Write([]byte(big))
	}), "", "")
	var out []map[string]any
	if err := c.pages(t.Context(), "/api/http/routers", &out); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("budget not enforced: %v (%d items)", err, len(out))
	}
}

// UniFi: the integration API with an API key, every site, paged clients;
// site IDs that could change the request path are skipped.
func TestUniFiClients(t *testing.T) {
	var paths []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "the-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		paths = append(paths, r.URL.RequestURI())
		switch r.URL.Path {
		case "/proxy/network/integration/v1/sites":
			_, _ = io.WriteString(w, `{"data":[{"id":"88f7af54-98f8-306a-a1c7-c9349722b1f6"},{"id":"../../x"}]}`)
		case "/proxy/network/integration/v1/sites/88f7af54-98f8-306a-a1c7-c9349722b1f6/devices":
			_, _ = io.WriteString(w, `{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
				{"name":"Gateway","model":"UCG Ultra","macAddress":"74:AC:B9:00:00:01","ipAddress":"10.10.1.1","firmwareVersion":"4.0.6","firmwareUpdatable":true},
				{"name":"AP Office","model":"U7 Pro","macAddress":"74:ac:b9:00:00:02","ipAddress":"10.10.1.2","firmwareVersion":"7.0.82","firmwareUpdatable":false}]}`)
		case "/proxy/network/integration/v1/sites/88f7af54-98f8-306a-a1c7-c9349722b1f6/clients":
			if r.URL.Query().Get("offset") == "0" {
				_, _ = io.WriteString(w, `{"offset":0,"limit":200,"count":2,"totalCount":3,"data":[
					{"type":"WIRED","name":"docker-host","ipAddress":"10.10.1.11","macAddress":"BC:24:11:AA:BB:01"},
					{"type":"WIRELESS","name":"phone","ipAddress":"10.10.1.50","macAddress":"bc:24:11:aa:bb:02"}]}`)
				return
			}
			_, _ = io.WriteString(w, `{"offset":2,"limit":200,"count":1,"totalCount":3,"data":[
				{"type":"VPN","name":"<script>","ipAddress":"not-an-ip","macAddress":"bc:24:11:aa:bb:03"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	clients, _, err := unifiClients(t.Context(), serviceFor(t, KindUniFi, h, "", "the-key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 || clients[0].MAC != "bc:24:11:aa:bb:01" || clients[0].Name != "docker-host" || clients[1].IP != "10.10.1.50" {
		t.Fatalf("clients %+v", clients)
	}
	for _, p := range paths {
		if strings.Contains(p, "..") {
			t.Fatalf("site ID put into a path: %s", p)
		}
	}
	if _, _, err := unifiClients(t.Context(), serviceFor(t, KindUniFi, h, "", "wrong")); err == nil {
		t.Fatal("a wrong key was accepted")
	}
	// The devices come with their firmware.
	st, err := readService(t.Context(), KindUniFi, serviceFor(t, KindUniFi, h, "", "the-key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Devices) != 2 || st.Devices[0].MAC != "74:ac:b9:00:00:01" || !st.Devices[0].Updatable || st.Devices[1].Updatable || st.Devices[0].Firmware != "4.0.6" {
		t.Fatalf("devices %+v", st.Devices)
	}
}

// A router that reports its firmware keeps its clients: both are stored in
// one sync, and the firmware becomes a package on the router's record.
func TestStoreServiceClientsAndFirmware(t *testing.T) {
	m, st := newManager(t)
	ctx, now := t.Context(), time.Now()
	in := store.Integration{ID: "fb", Kind: KindFritzBox, Name: "Fritz!Box 192.168.178.1", Address: "192.168.178.1", Enabled: true, CreatedAt: now}
	if err := st.CreateIntegration(ctx, in); err != nil {
		t.Fatal(err)
	}
	status := ServiceStatus{Clients: []LANClient{{IP: "192.168.178.20", MAC: "bc:24:11:00:00:01", Name: "media"}},
		System: &ApplianceSystem{Product: "FRITZ!OS", Model: "FRITZ!Box 7590", Package: "fritzos", Version: "7.57", Raw: "FRITZ!OS 7.57"}}
	if err := m.storeService(ctx, in, status, now); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.Hosts(ctx)
	kinds := map[inventory.HostSource]int{}
	for _, h := range hosts {
		if h.IntegrationID == "fb" {
			kinds[h.Source]++
		}
	}
	if kinds[inventory.SourceLease] != 1 || kinds[inventory.SourceAppliance] != 1 {
		t.Fatalf("hosts by source %v, want the client and the router", kinds)
	}
	ws, err := st.Workloads(ctx, store.WorkloadFilter{HostID: "app-fb"})
	if err != nil || len(ws) != 1 || ws[0].Package == nil || ws[0].Package.Manager != "firmware" || ws[0].Package.Version != "7.57" {
		t.Fatalf("firmware workload %+v %v", ws, err)
	}
}

// Each UniFi device with firmware is a system of its own, tied to other
// records by its MAC; devices without a known line or version are not.
func TestNetworkDeviceSystems(t *testing.T) {
	in := store.Integration{ID: "u", Name: "UniFi 10.10.1.1"}
	got := networkDeviceSystems(in, []NetworkDevice{
		{Name: "Office AP", Model: "U6-Pro", MAC: "aa:bb:cc:00:00:01", IP: "10.10.1.10", Firmware: "6.6.77"},
		{Name: "Core", Model: "USW-24-PoE", MAC: "aa:bb:cc:00:00:02", Firmware: "7.1.66.15432"},
		{Name: "Gateway", Model: "UDM Pro", MAC: "aa:bb:cc:00:00:03", Firmware: "4.0.6"},
		{Name: "Camera", Model: "G4 Bullet", MAC: "aa:bb:cc:00:00:04", Firmware: "4.69.55"},
		{Name: "Broken", Model: "U6-Lite", MAC: "aa:bb:cc:00:00:05", Firmware: "6.6.77; rm"},
	}, time.Now())
	pk := map[string]string{}
	for _, d := range got {
		pk[d.host.Name] = d.sys.Package + " " + d.sys.Version
		if d.host.MACs[0] == "" || d.host.Source != inventory.SourceAppliance {
			t.Errorf("host %+v", d.host)
		}
	}
	want := map[string]string{"Office AP": "unifi-ap 6.6.77", "Core": "unifi-switch 7.1.66.15432", "Gateway": "unifi-gateway 4.0.6"}
	if len(pk) != len(want) {
		t.Fatalf("systems %v, want %v", pk, want)
	}
	for k, v := range want {
		if pk[k] != v {
			t.Errorf("%s: %q, want %q", k, pk[k], v)
		}
	}
}
