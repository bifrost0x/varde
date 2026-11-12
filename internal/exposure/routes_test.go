// SPDX-License-Identifier: Apache-2.0

package exposure

import (
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

// Routes a reverse proxy reports through its API make the container they
// forward to public or LAN, by host address and published port anywhere,
// by container address or name only on the proxy's own host.
func TestRoutes(t *testing.T) {
	d := New(Config{PublicDomains: []string{"example.com"}, InternalDomains: []string{"home.arpa"}})
	w := func(host, name string, ip string, ports ...inventory.Port) inventory.Workload {
		return inventory.Workload{HostID: host, Kind: inventory.KindContainer, Name: name, Container: &inventory.Container{
			ComposeService: "immich-server", Ports: ports, Networks: []inventory.Network{{Name: "proxy", IPAddress: ip}},
		}}
	}
	immich := w("nas", "immich_server", "172.18.0.5", inventory.Port{PrivatePort: 2283, PublicPort: 2283, Protocol: "tcp"})
	addrs := map[string][]string{"nas": {"10.0.0.5"}, "other": {"10.0.0.6"}}
	cases := []struct {
		name  string
		route Route
		w     inventory.Workload
		want  inventory.Exposure
	}{
		{"host address and published port", Route{Host: "photos.example.com", Backend: "10.0.0.5:2283", Via: "npm"}, immich, inventory.ExposurePublic},
		{"container address on the proxy host", Route{Host: "photos.example.com", Backend: "172.18.0.5:2283", Via: "traefik", Hosts: []string{"nas"}}, immich, inventory.ExposurePublic},
		{"container address on another host", Route{Host: "photos.example.com", Backend: "172.18.0.5:2283", Via: "traefik", Hosts: []string{"other"}}, immich, inventory.ExposureLAN},
		{"service name on the proxy host", Route{Host: "photos.home.arpa", Backend: "immich-server:2283", Via: "npm", Hosts: []string{"nas"}}, immich, inventory.ExposureLAN},
		{"service name, proxy host unknown", Route{Host: "photos.example.com", Backend: "immich-server:2283", Via: "npm"}, immich, inventory.ExposureLAN},
		{"other port", Route{Host: "photos.example.com", Backend: "10.0.0.5:8080", Via: "npm"}, immich, inventory.ExposureLAN},
		{"unknown domain", Route{Host: "photos.lan", Backend: "10.0.0.5:2283", Via: "npm"}, immich, inventory.ExposureLAN},
	}
	for _, c := range cases {
		got := d.WithRoutes([]Route{c.route}, addrs).Detect(c.w)
		if got.Exposure != c.want {
			t.Errorf("%s: %s %v, want %s", c.name, got.Exposure, got.Evidence, c.want)
		}
	}
	// The evidence names the proxy and the route.
	got := d.WithRoutes([]Route{{Host: "photos.example.com", Backend: "10.0.0.5:2283", Via: "npm"}}, addrs).Detect(immich)
	if !strings.Contains(strings.Join(got.Evidence, " "), "npm route photos.example.com forwards to 10.0.0.5:2283") {
		t.Errorf("evidence: %v", got.Evidence)
	}
	// The detector without routes is unchanged.
	if d.Detect(immich).Exposure != inventory.ExposureLAN {
		t.Error("published port alone must stay LAN")
	}
}
