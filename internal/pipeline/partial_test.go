// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"log/slog"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

func TestPartialImageReadDoesNotResolveKnownFinding(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	cat, err := catalog.Load(fstest.MapFS{"immich.yaml": {Data: []byte(entry)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err = st.UpsertHost(ctx, inventory.Host{ID: "nas", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now}); err != nil {
		t.Fatal(err)
	}
	_, err = st.ApplySnapshot(ctx, "nas", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0", ImageID: "sha256:test"}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	ip := inventory.ImagePackages{ImageID: "sha256:test", Distro: "debian-12", Read: now, Packages: []inventory.Package{{Manager: "dpkg", Name: "libc6", Version: "2.36-9", Source: "glibc"}}}
	if err = st.RecordImagePackages(ctx, ip); err != nil {
		t.Fatal(err)
	}
	rec := store.AdvisoryRecord{Source: match.SourceDistro, Vuln: advisory.Vulnerability{ID: "DEBIAN-CVE-2023-4911", Modified: now, Affected: []advisory.Affected{{Package: advisory.Package{Ecosystem: "Debian:12", Name: "glibc"}, Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.36-9+deb12u3"}}}}}}}}
	if err = st.ReplaceAdvisories(ctx, "os:Debian:12/glibc", match.SourceDistro, []store.AdvisoryRecord{rec}, now); err != nil {
		t.Fatal(err)
	}
	p := New(cat, st, slog.New(slog.DiscardHandler), Options{})
	if _, err = p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	fs, err := st.Findings(ctx, store.FindingFilter{})
	if err != nil || len(fs) != 1 {
		t.Fatalf("initial findings %v: %v", fs, err)
	}
	id := fs[0].ID
	if err := st.Acknowledge(ctx, id, now); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkNotified(ctx, []string{id}, "P3", now); err != nil {
		t.Fatal(err)
	}
	ip.Partial = true
	ip.Packages = nil
	if err = st.RecordImagePackages(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	fs, err = st.Findings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("known vulnerability disappeared after partial read of the same image: %+v", fs)
	}
	if f := fs[0]; f.ID != id || f.State != store.StateAcknowledged || f.ResolvedAt != nil || f.LastNotifiedPriority != "P3" || f.NotifiedAt == nil {
		t.Fatalf("partial read changed the finding's lifecycle or notification history: %+v", f)
	}
	// A later complete read may confirm that the package really is gone.
	ip.Partial = false
	if err := st.RecordImagePackages(ctx, ip); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	f, err := st.GetFinding(ctx, id)
	if err != nil || f.State != store.StateResolved {
		t.Fatalf("complete read did not resolve the removed package: %+v (%v)", f, err)
	}
}
