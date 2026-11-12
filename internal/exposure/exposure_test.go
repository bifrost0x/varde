// SPDX-License-Identifier: Apache-2.0

package exposure

import (
	"reflect"
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

func ctr(labels map[string]string, ports ...inventory.Port) inventory.Workload {
	return inventory.Workload{Kind: inventory.KindContainer, Container: &inventory.Container{Labels: labels, Ports: ports}}
}

func TestRuleHosts(t *testing.T) {
	cases := map[string][]string{
		"Host(`photos.example.com`)":                                 {"photos.example.com"},
		"Host(`a.example.com`) || Host(`B.example.org`)":             {"a.example.com", "b.example.org"},
		"Host(`a.example.com`, `b.example.com`) && PathPrefix(`/x`)": {"a.example.com", "b.example.com"},
		"Host(`*.example.com`)":                                      {"example.com"},
		"Host(`**.example.com`)":                                     {"example.com"},
		"HostRegexp(`^.+\\.example\\.com$`)":                         nil,
		"HostSNI(`db.example.com`)":                                  nil,
		"PathPrefix(`/api`)":                                         nil,
		"(Host(`x.lan`) && Method(`GET`)) || Host(`y.example.com`)":  {"x.lan", "y.example.com"},
	}
	for rule, want := range cases {
		if got := RuleHosts(rule); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v want %v", rule, got, want)
		}
	}
}

func TestDetect(t *testing.T) {
	d := New(Config{PublicDomains: []string{"Example.com."}, InternalDomains: []string{"home.arpa", "lan"}})
	all := inventory.Port{IP: "0.0.0.0", PrivatePort: 2283, PublicPort: 2283, Protocol: "tcp"}
	loop := inventory.Port{IP: "127.0.0.1", PrivatePort: 80, PublicPort: 8080, Protocol: "tcp"}
	cases := []struct {
		name string
		w    inventory.Workload
		want inventory.Exposure
		ev   string
	}{
		{"no ports", ctr(nil), inventory.ExposureInternal, "no published ports"},
		{"loopback", ctr(nil, loop), inventory.ExposureInternal, "loopback"},
		{"all interfaces", ctr(nil, loop, all), inventory.ExposureLAN, "port 2283"},
		{"ipv6 wildcard", ctr(nil, inventory.Port{IP: "::", PublicPort: 443}), inventory.ExposureLAN, "port 443"},
		{"traefik public", ctr(map[string]string{"traefik.http.routers.immich.rule": "Host(`photos.example.com`)"}), inventory.ExposurePublic, "photos.example.com"},
		{"traefik subdomain only", ctr(map[string]string{"traefik.http.routers.x.rule": "Host(`notexample.com`)"}), inventory.ExposureInternal, "no published ports"},
		{"traefik internal", ctr(map[string]string{"traefik.http.routers.x.rule": "Host(`nas.home.arpa`)"}, all), inventory.ExposureLAN, "internal domain"},
		{"traefik disabled", ctr(map[string]string{"traefik.enable": "false", "traefik.http.routers.x.rule": "Host(`a.example.com`)"}), inventory.ExposureInternal, ""},
		{"traefik public beats lan route", ctr(map[string]string{
			"traefik.http.routers.a.rule": "Host(`a.lan`)", "traefik.http.routers.b.rule": "Host(`b.example.com`)",
		}), inventory.ExposurePublic, ""},
		{"catch-all ignored", ctr(map[string]string{"traefik.http.routers.x.rule": "Host(`*`)"}), inventory.ExposureInternal, ""},
		{"manual label wins", ctr(map[string]string{LabelExposure: "Internal", "traefik.http.routers.x.rule": "Host(`a.example.com`)"}, all), inventory.ExposureInternal, "label varde.exposure=internal"},
		{"bad manual label ignored", ctr(map[string]string{LabelExposure: "world"}, all), inventory.ExposureLAN, ""},
		{"manual entry", inventory.Workload{Kind: inventory.KindManual, Manual: &inventory.Manual{Exposure: inventory.ExposurePublic}}, inventory.ExposurePublic, "manual entry"},
		{"manual entry unknown", inventory.Workload{Kind: inventory.KindManual, Manual: &inventory.Manual{Exposure: inventory.ExposureUnknown}}, inventory.ExposureUnknown, ""},
	}
	for _, c := range cases {
		r := d.Detect(c.w)
		if r.Exposure != c.want {
			t.Errorf("%s: %s (evidence %v), want %s", c.name, r.Exposure, r.Evidence, c.want)
			continue
		}
		if c.ev != "" && !strings.Contains(strings.Join(r.Evidence, "|"), c.ev) {
			t.Errorf("%s: evidence %v lacks %q", c.name, r.Evidence, c.ev)
		}
	}
}

func TestExposureNetworkModesAndBinds(t *testing.T) {
	d := New(Config{})
	ct := func(c inventory.Container) inventory.Workload {
		return inventory.Workload{Kind: inventory.KindContainer, Container: &c}
	}
	for name, c := range map[string]struct {
		w    inventory.Workload
		want inventory.Exposure
	}{
		"host network":      {ct(inventory.Container{Runtime: &inventory.Runtime{NetworkMode: "host"}}), inventory.ExposureLAN},
		"shared network":    {ct(inventory.Container{Runtime: &inventory.Runtime{NetworkMode: "container:abc"}}), inventory.ExposureUnknown},
		"LAN address":       {ct(inventory.Container{Ports: []inventory.Port{{IP: "192.168.1.10", PrivatePort: 80, PublicPort: 8080}}}), inventory.ExposureLAN},
		"tailscale address": {ct(inventory.Container{Ports: []inventory.Port{{IP: "100.64.1.2", PrivatePort: 80, PublicPort: 8080}}}), inventory.ExposureLAN},
		"loopback":          {ct(inventory.Container{Ports: []inventory.Port{{IP: "127.0.0.1", PrivatePort: 80, PublicPort: 8080}}}), inventory.ExposureInternal},
		"loopback v6":       {ct(inventory.Container{Ports: []inventory.Port{{IP: "::1", PrivatePort: 80, PublicPort: 8080}}}), inventory.ExposureInternal},
	} {
		if got := d.Detect(c.w).Exposure; got != c.want {
			t.Errorf("%s: got %s, want %s", name, got, c.want)
		}
	}
}
