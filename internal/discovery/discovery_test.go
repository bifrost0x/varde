// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestParseScope(t *testing.T) {
	sc, err := ParseScope("192.168.1.0/24, 10.0.10.5 fd00::/64")
	if err != nil {
		t.Fatal(err)
	}
	if sc.String() != "10.0.10.5/32, 192.168.1.0/24, fd00::/64" {
		t.Errorf("scope %q", sc.String())
	}
	for _, bad := range []string{"8.8.8.0/24", "0.0.0.0/0", "10.0.0.0/7", "192.168.1.0/33", "example.com", "2001:db8::/32"} {
		if _, err := ParseScope(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if !sc.Contains(netip.MustParseAddr("192.168.1.77")) || sc.Contains(netip.MustParseAddr("192.168.2.1")) {
		t.Error("Contains")
	}
	addrs, err := sc.Addresses()
	if err != nil || len(addrs) != 255 { // 254 hosts of the /24 plus the single address
		t.Fatalf("addresses %d %v", len(addrs), err)
	}
	if big, _ := ParseScope("10.1.0.0/19"); true {
		if _, err := big.Addresses(); err == nil {
			t.Error("a /19 must be refused for scanning")
		}
	}
	if ok, _ := ParseScope("10.1.0.0/20"); true {
		if a, err := ok.Addresses(); err != nil || len(a) != 4094 {
			t.Errorf("/20: %d %v", len(a), err)
		}
	}
}

func TestScopeDialRefusesOutside(t *testing.T) {
	sc, _ := ParseScope("192.168.1.0/24")
	_, err := sc.DialContext(&net.Dialer{Timeout: time.Second})(t.Context(), "tcp", "8.8.8.8:53")
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("dial outside scope: %v", err)
	}
}

func TestScanFingerprints(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<html><head><title>Proxmox Virtual Environment</title></head></html>")
	}))
	defer web.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	}))
	defer redirect.Close()
	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sshLn.Close() }()
	go func() {
		for {
			c, err := sshLn.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"))
			_ = c.Close()
		}
	}()
	port := func(addr string) int {
		_, p, _ := net.SplitHostPort(addr)
		n, _ := strconv.Atoi(p)
		return n
	}
	s := &Scanner{
		Ports: []Port{
			{port(sshLn.Addr().String()), ProtoSSH},
			{port(web.Listener.Addr().String()), ProtoHTTP},
			{port(redirect.Listener.Addr().String()), ProtoHTTP},
			{1, ProtoTCP}, // closed
		},
		InFlight: 4, Rate: 1000, ConnectTimeout: time.Second, ReadTimeout: 2 * time.Second,
		dial: (&net.Dialer{}).DialContext,
	}
	var calls int
	res, err := s.Scan(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, func(int, int) { calls++ })
	devs := res.Devices
	if err != nil {
		t.Fatal(err)
	}
	if calls != 4 || len(devs) != 1 {
		t.Fatalf("progress calls %d, devices %v", calls, devs)
	}
	d := devs[0]
	if d.Kind != KindProxmox || d.Label != "Proxmox VE" || len(d.Services) != 3 {
		t.Fatalf("device %+v", d)
	}
	got := map[string]bool{}
	for _, sv := range d.Services {
		got[sv.Product] = true
	}
	if !got["OpenSSH_9.2p1 Debian-2+deb12u3"] || !got["redirects to /admin/"] {
		t.Errorf("services %+v", d.Services)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		svcs        []Service
		kind, label string
	}{
		{[]Service{{Port: 80, Proto: ProtoHTTP, Product: productFromHTTP("301 Moved Permanently", "", "")}, {Port: 443, Proto: ProtoHTTPS, Product: productFromHTTP("UniFi OS", "", "")}}, KindNetwork, "UniFi OS (gateway or console)"},
		{[]Service{{Port: 22, Proto: ProtoSSH, Product: "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8"}, {Port: 80, Proto: ProtoHTTP}}, KindSSH, "Linux host (Ubuntu)"},
		{[]Service{{Port: 2375, Proto: ProtoDocker, Product: "Docker Engine", Insecure: true}, {Port: 22, Proto: ProtoSSH}}, KindDocker, "Docker host (API open without authentication)"},
		{[]Service{{Port: 445, Proto: ProtoTCP}, {Port: 80, Proto: ProtoHTTP}}, KindOther, "File server or Windows PC (SMB)"},
		{[]Service{{Port: 8080, Proto: ProtoHTTP, Product: productFromHTTP("HTTP Status 400 – Bad Request", "", "")}}, KindWeb, "Web service"},
		{nil, KindOther, "Device (no known service)"},
	}
	for i, c := range cases {
		k, l := Classify(c.svcs)
		if k != c.kind || l != c.label {
			t.Errorf("%d: %s %q, want %s %q", i, k, l, c.kind, c.label)
		}
	}
}

func TestInterceptedPortIgnored(t *testing.T) {
	// One listener stands in for a port that answers on every address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	target := ln.Addr().String()
	s := &Scanner{
		Ports: []Port{{port, ProtoTCP}}, InFlight: 8, Rate: 10000, ConnectTimeout: time.Second, ReadTimeout: time.Second,
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
	var addrs []netip.Addr
	a := netip.MustParseAddr("192.168.50.1")
	for range 20 {
		addrs = append(addrs, a)
		a = a.Next()
	}
	res, err := s.Scan(t.Context(), addrs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Devices) != 0 || len(res.Intercepted) != 1 || res.Intercepted[0] != port {
		t.Fatalf("devices %d, intercepted %v", len(res.Devices), res.Intercepted)
	}
}

// A lost connection attempt does not hide a host: what got no answer is
// tried again, and an address that answers only then is probed fully.
func TestScanRetriesLostAttempts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln2.Close() }()
	for _, l := range []net.Listener{ln, ln2} {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	port := func(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }
	saved := retryPorts
	retryPorts = []int{port(ln)}
	defer func() { retryPorts = saved }()
	var mu sync.Mutex
	attempts := map[string]int{}
	lossy := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		attempts[addr]++
		n := attempts[addr]
		mu.Unlock()
		if n == 1 {
			// The first attempt to every port is lost on the way.
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	s := &Scanner{
		Ports:    []Port{{port(ln), ProtoTCP}, {port(ln2), ProtoTCP}},
		InFlight: 4, Rate: 1000, ConnectTimeout: 50 * time.Millisecond, ReadTimeout: time.Second,
		dial: lossy,
	}
	res, err := s.Scan(t.Context(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Devices) != 1 || len(res.Devices[0].Services) != 2 {
		t.Fatalf("devices: %+v", res.Devices)
	}
}
