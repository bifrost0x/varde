// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"encoding/json"
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func TestProxyRoutes(t *testing.T) {
	status, _ := json.Marshal(map[string]any{"routes": []map[string]any{{"host": "photos.example.com", "backends": []string{"10.0.0.5:2283", "immich-server:2283"}}}})
	ins := []store.Integration{
		{ID: "a", Name: "npm", Address: "http://10.0.0.5:81", Enabled: true, Status: status},
		{ID: "b", Name: "off", Address: "10.0.0.9", Enabled: false, Status: status},
		{ID: "c", Name: "broken", Address: "10.0.0.7", Enabled: true, Status: json.RawMessage(`{`)},
	}
	hosts := []inventory.Host{{ID: "nas", Addresses: []string{"10.0.0.5"}}, {ID: "x", Addresses: []string{"10.0.0.6"}}}
	routes, addrs := ProxyRoutes(ins, hosts)
	if len(routes) != 2 || routes[0].Via != "npm" || len(routes[0].Hosts) != 1 || routes[0].Hosts[0] != "nas" || routes[1].Backend != "immich-server:2283" {
		t.Fatalf("routes: %+v", routes)
	}
	if len(addrs["nas"]) != 1 {
		t.Errorf("addresses: %v", addrs)
	}
	for in, want := range map[string]string{"https://10.0.0.5:8080/x": "10.0.0.5", "10.0.0.5:81": "10.0.0.5", "10.0.0.5": "10.0.0.5"} {
		if got := addressHost(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}
