// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/discovery"
)

// A device that misses one scan is kept and marked; it goes after the
// second miss in a row, and an answer in between resets the count.
func TestDevicesSurviveOneMissedScan(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	all := func(string) bool { return true }
	pve := discovery.Device{Address: "10.10.1.253", Kind: discovery.KindProxmox, Label: "Proxmox VE"}
	scan := func(devs ...discovery.Device) []StoredDevice {
		t.Helper()
		now = now.Add(time.Hour)
		if err := s.RecordDevices(ctx, devs, all, now); err != nil {
			t.Fatal(err)
		}
		got, err := s.Devices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := scan(pve); len(got) != 1 || got[0].Missed {
		t.Fatalf("found: %+v", got)
	}
	if got := scan(); len(got) != 1 || !got[0].Missed {
		t.Fatalf("after one missed scan: %+v", got)
	}
	if got := scan(pve); len(got) != 1 || got[0].Missed {
		t.Fatalf("answering again: %+v", got)
	}
	scan()
	if got := scan(); len(got) != 0 {
		t.Fatalf("after two missed scans: %+v", got)
	}
}
