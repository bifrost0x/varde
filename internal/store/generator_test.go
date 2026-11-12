// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"testing"
	"time"
)

func TestAllCandidates(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	for _, c := range []Candidate{
		{Image: "b", Repo: "r", Weight: 1},
		{Image: "a", Repo: "r", Weight: 2, Status: CandidateShipped, EntryYAML: "id: a", CheckedAt: now, ShippedAt: now},
	} {
		if err := s.UpsertCandidate(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.AllCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Image != "a" || got[1].Image != "b" || !got[0].ShippedAt.Equal(now) || !got[1].CheckedAt.IsZero() {
		t.Fatalf("got %+v", got)
	}
}

func TestLayerReadRoundTrip(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	if _, _, ok, err := s.LayerRead(ctx, "sha256:a"); err != nil || ok {
		t.Fatalf("missing: %v %v", ok, err)
	}
	if err := s.PutLayerRead(ctx, "sha256:a", []byte{0x1f, 0x8b, 0}, true, at); err != nil {
		t.Fatal(err)
	}
	files, partial, ok, err := s.LayerRead(ctx, "sha256:a")
	if err != nil || !ok || !partial || !bytes.Equal(files, []byte{0x1f, 0x8b, 0}) {
		t.Fatalf("read: %v %v %v %v", files, partial, ok, err)
	}
	if err := s.PutLayerRead(ctx, "sha256:a", []byte("x"), false, at); err != nil {
		t.Fatal(err)
	}
	if files, partial, ok, _ := s.LayerRead(ctx, "sha256:a"); string(files) != "x" || partial || !ok {
		t.Errorf("replace: %q %v %v", files, partial, ok)
	}
}

func TestReleaseReads(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	if _, _, _, ok, err := s.ReleaseRead(ctx, "a", "img", "linux/amd64"); ok || err != nil {
		t.Fatalf("missing: %v %v", ok, err)
	}
	for _, p := range []string{"linux/arm64", "linux/amd64"} {
		if err := s.PutReleaseRead(ctx, "a", "img", p, "1.0", "sha256:i", []byte(`{"p":"`+p+`"}`), at); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutReleaseRead(ctx, "a", "img", "linux/amd64", "1.1", "sha256:j", []byte(`{"v":2}`), at); err != nil {
		t.Fatal(err)
	}
	tag, dig, line, ok, err := s.ReleaseRead(ctx, "a", "img", "linux/amd64")
	if err != nil || !ok || tag != "1.1" || dig != "sha256:j" || string(line) != `{"v":2}` {
		t.Fatalf("read: %q %q %q %v %v", tag, dig, line, ok, err)
	}
	if l, err := s.ReleaseReadLimits(ctx, "a", "img", "linux/amd64"); err != nil || l != "" {
		t.Fatalf("limits before: %q %v", l, err)
	}
	if err := s.SetReleaseReadLimits(ctx, "a", "img", "linux/amd64", "k1"); err != nil {
		t.Fatal(err)
	}
	if l, err := s.ReleaseReadLimits(ctx, "a", "img", "linux/amd64"); err != nil || l != "k1" {
		t.Fatalf("limits: %q %v", l, err)
	}
	// A new read clears the limits of the one it replaces.
	if err := s.PutReleaseRead(ctx, "a", "img", "linux/amd64", "1.1", "sha256:j", []byte(`{"v":2}`), at); err != nil {
		t.Fatal(err)
	}
	if l, err := s.ReleaseReadLimits(ctx, "a", "img", "linux/amd64"); err != nil || l != "" {
		t.Fatalf("limits after a new read: %q %v", l, err)
	}
	all, err := s.ReleaseReads(ctx)
	if err != nil || len(all) != 2 || string(all[0]) != `{"v":2}` {
		t.Fatalf("all: %q %v", all, err)
	}
}

func TestReplaceReleasePackagesIsAtomic(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	if m, err := s.ReleasePackagesMarker(ctx); err != nil || m != "" {
		t.Fatalf("marker of a new store = %q, %v", m, err)
	}
	row := func(app, plat string) ReleasePackageRow {
		return ReleasePackageRow{AppID: app, Image: "img", Platform: plat, Tag: "1", Version: "1.0", Line: []byte(app + plat)}
	}
	if err := s.ReplaceReleasePackages(ctx, "m1", []ReleasePackageRow{row("a", "amd64"), row("a", "arm64"), row("b", "amd64")}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReleasePackagesFor(ctx, "a", "img")
	if err != nil || len(got) != 2 || string(got[0]) != "aamd64" {
		t.Fatalf("for a: %q %v", got, err)
	}

	// A duplicate key fails the replacement; the old lists stay.
	if err := s.ReplaceReleasePackages(ctx, "m2", []ReleasePackageRow{row("c", "amd64"), row("c", "amd64")}); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if got, _ := s.ReleasePackagesFor(ctx, "a", "img"); len(got) != 2 {
		t.Errorf("old lists lost: %q", got)
	}
	if got, _ := s.ReleasePackagesFor(ctx, "c", "img"); len(got) != 0 {
		t.Errorf("partial replacement visible: %q", got)
	}
	if m, err := s.ReleasePackagesMarker(ctx); err != nil || m != "m1" {
		t.Errorf("marker after a failed replacement = %q, %v", m, err)
	}

	// A successful replacement drops what is not in the new set.
	if err := s.ReplaceReleasePackages(ctx, "m3", []ReleasePackageRow{row("b", "amd64")}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ReleasePackagesFor(ctx, "a", "img"); len(got) != 0 {
		t.Errorf("stale rows: %q", got)
	}
	if err := s.ReplaceReleasePackages(ctx, "", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ReleasePackagesFor(ctx, "b", "img"); len(got) != 0 {
		t.Errorf("not emptied: %q", got)
	}
	if m, err := s.ReleasePackagesMarker(ctx); err != nil || m != "" {
		t.Errorf("marker after emptying = %q, %v", m, err)
	}
}
