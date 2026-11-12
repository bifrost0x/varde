// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func TestIntegrationHealth(t *testing.T) {
	now := time.Now()
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	iv := 10 * time.Minute
	cases := []struct {
		name string
		in   store.Integration
		want string
	}{
		{"off", store.Integration{Enabled: false, LastError: "x"}, HealthOff},
		{"fresh", store.Integration{Enabled: true, CreatedAt: now}, HealthWaiting},
		{"ok", store.Integration{Enabled: true, CreatedAt: now.Add(-time.Hour), LastSuccess: ago(5 * time.Minute)}, HealthOK},
		{"one failed read", store.Integration{Enabled: true, LastSuccess: ago(15 * time.Minute), LastError: "timeout"}, HealthError},
		{"never read, error", store.Integration{Enabled: true, CreatedAt: now, LastError: "permission denied"}, HealthFailing},
		{"three intervals", store.Integration{Enabled: true, LastSuccess: ago(31 * time.Minute), LastError: "timeout"}, HealthFailing},
		// A stuck collector without an error is noticed as well.
		{"silent", store.Integration{Enabled: true, LastSuccess: ago(31 * time.Minute)}, HealthFailing},
	}
	for _, c := range cases {
		if got := IntegrationHealth(c.in, now, iv); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// A failing integration raises a notice, which also reaches the digest, and
// its hosts count as not reporting. Before, only agents could go stale.
func TestFailingIntegration(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	ins := []store.Integration{
		{ID: "pve", Kind: "proxmox", Name: "Proxmox pve", Enabled: true, LastSuccess: &old, LastError: "dial tcp: i/o timeout"},
		{ID: "off", Kind: "proxmox", Name: "Proxmox off", Enabled: false, LastSuccess: &old},
	}
	interval := func(string) time.Duration { return 10 * time.Minute }
	ns := IntegrationNotices(ins, now, interval)
	if len(ns) != 1 || ns[0].Key != store.NoticeIntegrationFailing+":pve" || !strings.Contains(ns[0].Detail, "i/o timeout") {
		t.Fatalf("notices: %+v", ns)
	}
	ms := Machines(MachineInput{
		Hosts:        []inventory.Host{{ID: "ssh-pve", Name: "d", Kind: inventory.HostDocker, Source: inventory.SourceSSH, IntegrationID: "pve", LastContact: old}},
		Integrations: ins, Now: now, Interval: interval,
	})
	if len(ms) != 1 || ms[0].State != MachineStale {
		t.Errorf("host of a failing integration: %+v", ms)
	}
}
