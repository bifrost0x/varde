// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

func TestImagePackages(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	pkgs := []inventory.Package{{Manager: "dpkg", Name: "jellyfin-server", Version: "10.10.7+deb13", Distro: "debian-13"}}
	if err := s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "sha256:a", Distro: "debian-13", OS: "Debian GNU/Linux 13", Packages: pkgs, Read: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "sha256:b", Read: now}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ImagePackages(ctx, []string{"sha256:a", "sha256:b", "sha256:missing"})
	if err != nil {
		t.Fatal(err)
	}
	if a := got["sha256:a"]; a.Distro != "debian-13" || a.OS != "Debian GNU/Linux 13" || len(a.Packages) != 1 || a.Packages[0] != pkgs[0] || !a.Read.Equal(now) {
		t.Errorf("a: %+v", a)
	}
	if b, ok := got["sha256:b"]; !ok || b.Packages == nil || len(b.Packages) != 0 {
		t.Errorf("image without packages: %+v %v", b, ok)
	}
	if _, ok := got["sha256:missing"]; ok || len(got) != 2 {
		t.Errorf("unknown image returned: %d", len(got))
	}
	if got, err := s.ImagePackages(ctx, nil); err != nil || len(got) != 0 {
		t.Errorf("no IDs: %v %v", got, err)
	}

	// A failed read keeps what an earlier read found.
	later := now.Add(8 * 24 * time.Hour)
	if err := s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "sha256:a", Read: later, Error: "forbidden"}); err != nil {
		t.Fatal(err)
	}
	read, err := s.ImagePackagesRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a := read["sha256:a"]; a.Error != "forbidden" || !a.Read.Equal(later) || len(read) != 2 {
		t.Errorf("read state: %+v", read)
	}
	got, _ = s.ImagePackages(ctx, []string{"sha256:a"})
	if a := got["sha256:a"]; len(a.Packages) != 1 || a.Error != "forbidden" {
		t.Errorf("failed read dropped the packages: %+v", a)
	}
	// A successful read clears the error.
	if err := s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "sha256:a", Packages: pkgs, Read: later}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ImagePackages(ctx, []string{"sha256:a"}); got["sha256:a"].Error != "" {
		t.Error("error kept after a successful read")
	}

	// Rows of images no container runs any more expire.
	if err := s.PurgeLogs(ctx, now.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	read, _ = s.ImagePackagesRead(ctx)
	if _, ok := read["sha256:b"]; ok || len(read) != 1 {
		t.Errorf("after purge: %+v", read)
	}
}

func TestRepositoryTags(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	if err := s.RecordRepositoryTags(ctx, RepositoryTags{Repository: "ghcr.io/a/b", Tags: []string{"v1.0.0", "", "v1.1.0"}, Checked: now}); err != nil {
		t.Fatal(err)
	}
	// A failed listing keeps the tags.
	if err := s.RecordRepositoryTags(ctx, RepositoryTags{Repository: "ghcr.io/a/b", Checked: now.Add(time.Hour), Error: "timeout"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.RepositoryTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := got["ghcr.io/a/b"]
	if len(r.Tags) != 2 || r.Tags[1] != "v1.1.0" || r.Error != "timeout" || !r.Checked.Equal(now.Add(time.Hour)) {
		t.Errorf("tags: %+v", r)
	}
}

// One agent's record never decides what another host's containers are
// checked against; Varde's own read wins for every host; a revoked agent's
// records go.
func TestImagePackagesPerSource(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	rec := func(v string) inventory.ImagePackages {
		return inventory.ImagePackages{ImageID: "sha256:img", Distro: "debian-12", Read: now,
			Packages: []inventory.Package{{Manager: "dpkg", Name: "openssl", Version: v}}}
	}
	if _, err := s.RecordAgentImagePackages(ctx, "evil", rec("99.0")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordAgentImagePackages(ctx, "good", rec("3.0.11-1")); err != nil {
		t.Fatal(err)
	}
	refs := []ImageRef{{"sha256:img", "evil"}, {"sha256:img", "good"}, {"sha256:img", "local"}}
	got, err := s.ImagePackagesFor(ctx, refs)
	if err != nil {
		t.Fatal(err)
	}
	if got[refs[0]].Packages[0].Version != "99.0" || got[refs[1]].Packages[0].Version != "3.0.11-1" {
		t.Fatalf("own records: %+v", got)
	}
	if _, ok := got[refs[2]]; ok {
		t.Fatal("a host without its own record used an agent's")
	}
	if err := s.RecordImagePackages(ctx, rec("3.0.11-1+deb12u1")); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ImagePackagesFor(ctx, refs)
	for _, r := range refs {
		if got[r].Packages[0].Version != "3.0.11-1+deb12u1" {
			t.Fatalf("%s: Varde's own read must win: %+v", r.HostID, got[r])
		}
	}
	// Varde's reader schedules by its own reads only.
	read, _ := s.ImagePackagesRead(ctx)
	if len(read) != 1 {
		t.Fatalf("reads: %+v", read)
	}
}

// The reader format is kept, so records of an older reader can be read
// again; a failed read keeps the format of the packages it kept.
func TestImageReaderFormat(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	if err := s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "sha256:f", Read: now, Format: 1,
		Packages: []inventory.Package{{Manager: "dpkg", Name: "libssl3", Version: "3.0.11-1", Source: "openssl"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordImagePackages(ctx, inventory.ImagePackages{ImageID: "sha256:f", Read: now.Add(time.Hour), Error: "boom"}); err != nil {
		t.Fatal(err)
	}
	read, err := s.ImagePackagesRead(ctx)
	if err != nil || read["sha256:f"].Format != 1 {
		t.Fatalf("format after a failed read: %+v %v", read["sha256:f"], err)
	}
}
