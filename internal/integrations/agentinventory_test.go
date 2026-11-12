// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// An agent delivers the output of the inventory command run on its host;
// it is stored like the SSH inventory, for the agent's host record.
func TestStoreAgentInventory(t *testing.T) {
	m, st := newManager(t)
	ctx := t.Context()
	now := time.Now()
	hash := auth.HashToken("enroll-secret")
	if err := st.CreateEnrollmentToken(ctx, store.EnrollmentToken{ID: "t1", Name: "x", TokenHash: hash, CreatedBy: "admin",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	hostID := "0123456789abcdef0123456789abcdef"
	if err := st.EnrollAgent(ctx, hash, inventory.Host{ID: hostID, Name: "web", Kind: inventory.HostDocker},
		store.AgentCert{Fingerprint: "fp", Expires: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/inventory2-debian.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.StoreAgentInventory(ctx, hostID, raw, now); err != nil {
		t.Fatal(err)
	}
	pk, ok, err := st.HostPackageList(ctx, hostID)
	if err != nil || !ok || len(pk.Packages) < 70 || pk.Distro != "debian-13" {
		t.Fatalf("packages: ok=%v err=%v n=%d distro=%q", ok, err, len(pk.Packages), pk.Distro)
	}
	inv, _ := ParseInventory(raw)
	h, err := st.Host(ctx, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if h.MachineID != inv.MachineID || len(h.MACs) != len(inv.MACs) {
		t.Fatalf("identity keys: %q %v, want %q %v", h.MachineID, h.MACs, inv.MachineID, inv.MACs)
	}

	if _, err := m.StoreAgentInventory(ctx, hostID, []byte("hello\n"), now); !errors.Is(err, wire.ErrBadInventory) {
		t.Fatalf("garbage: %v", err)
	}
	if err := st.RevokeAgent(ctx, hostID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := m.StoreAgentInventory(ctx, hostID, raw, now); !errors.Is(err, store.ErrInvalidState) {
		t.Fatalf("revoked agent: %v", err)
	}
	if _, err := m.StoreAgentInventory(ctx, "ffffffffffffffffffffffffffffffff", raw, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
}
