// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
)

// What was read of an image's packages survives the store, and its absence
// stays absent.
func TestIdentificationPackagesRoundTrip(t *testing.T) {
	s, _ := openTest(t)
	ctx, now := t.Context(), time.Now()
	if err := s.UpsertHost(ctx, localHost(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplySnapshot(ctx, inventory.LocalHostID, inventory.KindContainer,
		[]inventory.Workload{container("a", "web", "nginx:1"), container("b", "db", "postgres:16")}, now); err != nil {
		t.Fatal(err)
	}
	a := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "a")
	b := inventory.WorkloadID(inventory.LocalHostID, inventory.KindContainer, "b")
	pc := &identify.PackageCheck{Count: 3, Ecosystems: map[string]int{"Debian:13": 2, "Go": 1}}
	if err := s.ReplaceIdentifications(ctx, []identify.Result{{WorkloadID: a, Packages: pc}, {WorkloadID: b}}, now); err != nil {
		t.Fatal(err)
	}
	ids, err := s.Identifications(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids[a].Packages; got == nil || got.Count != 3 || got.Ecosystems["Debian:13"] != 2 {
		t.Errorf("packages of a: %+v", got)
	}
	if ids[b].Packages != nil {
		t.Errorf("packages of b: %+v", ids[b].Packages)
	}
}
