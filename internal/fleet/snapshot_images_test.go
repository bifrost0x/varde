// SPDX-License-Identifier: Apache-2.0

package fleet_test

import (
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func TestImagePackagesSurviveRequestedSnapshot(t *testing.T) {
	e := newEnv(t)
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	w := container("c1", "web", "nginx:1.27")
	w.Container.ImageID = "sha256:" + strings.Repeat("a", 64)
	if err := push(t, a, w); err != nil {
		t.Fatal(err)
	}
	h := agentHost(t, e.st)
	// A restored database has the agent identity but lacks its current containers.
	if _, err := e.st.ApplySnapshot(t.Context(), h.ID, inventory.KindContainer, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetSnapshotHash(t.Context(), h.ID, ""); err != nil {
		t.Fatal(err)
	}
	p := inventory.ImagePackages{ImageID: w.Container.ImageID, Distro: "debian-12", Read: time.Now(), Packages: []inventory.Package{{Manager: "dpkg", Name: "libc6", Version: "2.36-9", Source: "glibc"}}}
	if err := a.PackageReader().Store.RecordImagePackages(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if err := push(t, a, w); err != nil {
		t.Fatal(err)
	}
	got, err := e.st.ImagePackagesFor(t.Context(), []store.ImageRef{{ImageID: p.ImageID, HostID: h.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if read := got[store.ImageRef{ImageID: p.ImageID, HostID: h.ID}]; len(read.Packages) != 1 {
		t.Fatalf("pending image packages lost during heartbeat-to-full-snapshot retry: %+v", got)
	}
}
