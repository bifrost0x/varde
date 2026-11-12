// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

// Reads wait for the next report; failed reads only set the read time.
func TestImageStore(t *testing.T) {
	s := newImageStore()
	ctx := t.Context()
	_ = s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "a", Read: time.Now(), Distro: "debian-12"})
	_ = s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "b", Read: time.Now(), Error: "refused"})
	_ = s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "a", Read: time.Now(), Distro: "debian-13"})
	pending := s.take()
	if len(pending) != 1 || pending[0].Distro != "debian-13" {
		t.Fatalf("pending %+v", pending)
	}
	read, _ := s.ImagePackagesRead(ctx)
	if len(read) != 2 || read["b"].Error != "refused" {
		t.Fatalf("read %+v", read)
	}
	s.delivered(pending)
	if len(s.take()) != 0 {
		t.Fatal("delivered record still pending")
	}
}
