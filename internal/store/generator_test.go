// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"os"
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
	of, err := s.ReleasePackagesOf(ctx, []ReleaseImage{{"a", "img"}, {"b", "img"}, {"a", "other"}})
	if err != nil || len(of) != 2 || len(of[ReleaseImage{"a", "img"}]) != 2 || string(of[ReleaseImage{"b", "img"}][0]) != "bamd64" {
		t.Fatalf("of a and b: %q %v", of, err)
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

// Leaving the feed drops the release package lists it installed, with
// their marker: a later return writes them afresh, and no page claims a
// release fix from a package no longer in use.
func TestClearFeedDropsReleasePackages(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	row := ReleasePackageRow{AppID: "a", Image: "img", Platform: "linux/amd64", Tag: "1", Version: "1.0", Line: []byte("{}")}
	if err := s.ReplaceReleasePackages(ctx, "m1", []ReleasePackageRow{row}); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearFeed(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ReleasePackagesFor(ctx, "a", "img"); err != nil || len(got) != 0 {
		t.Fatalf("release packages after leaving the feed: %q, %v", got, err)
	}
	if m, err := s.ReleasePackagesMarker(ctx); err != nil || m != "" {
		t.Fatalf("marker after leaving the feed = %q, %v", m, err)
	}
}

// Pruning keeps the release reads named and the layer reads they use;
// what is left of the layer reads beyond the byte bound goes oldest first,
// and the file shrinks with it.
func TestPruneBuilderReads(t *testing.T) {
	s, path := openTest(t)
	ctx := t.Context()
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	put := func(app, plat, layers string) {
		t.Helper()
		if err := s.PutReleaseRead(ctx, app, "img", plat, "1", "sha256:i", []byte(`{}`), at); err != nil {
			t.Fatal(err)
		}
		if err := s.SetReleaseReadLayers(ctx, app, "img", plat, layers); err != nil {
			t.Fatal(err)
		}
	}
	put("a", "linux/amd64", `["cfg-a","l1","l2"]`)
	put("a", "linux/arm64", `["cfg-a","l3"]`)
	put("b", "linux/amd64", `["l1","l4"]`)
	put("gone", "linux/amd64", `["l5"]`)
	put("old", "linux/amd64", ``)
	big := bytes.Repeat([]byte{1}, 1<<20)
	for i, d := range []string{"cfg-a", "l1", "l2", "l3", "l4", "l5", "unnamed"} {
		if err := s.PutLayerRead(ctx, d, big, false, at.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if l, err := s.ReleaseReadLayers(ctx, "a", "img", "linux/arm64"); err != nil || l != `["cfg-a","l3"]` {
		t.Fatalf("layers = %q, %v", l, err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	keep := []ReleaseReadKey{{"a", "img", "linux/amd64"}, {"a", "img", "linux/arm64"}, {"b", "img", "linux/amd64"}, {"old", "img", "linux/amd64"}}
	// Room for four of the five layer reads still named.
	st, err := s.PruneBuilderReads(ctx, keep, 4<<20+1)
	if err != nil {
		t.Fatal(err)
	}
	if st.Reads != 1 || st.Layers != 3 || st.LayerBytes != 4<<20 {
		t.Fatalf("stats %+v", st)
	}
	if _, _, _, ok, _ := s.ReleaseRead(ctx, "gone", "img", "linux/amd64"); ok {
		t.Error("release read outside keep left")
	}
	for d, want := range map[string]bool{"cfg-a": false, "l1": true, "l2": true, "l3": true, "l4": true, "l5": false, "unnamed": false} {
		if _, _, ok, err := s.LayerRead(ctx, d); err != nil || ok != want {
			t.Errorf("layer read %s kept %v, want %v (%v)", d, ok, want, err)
		}
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() >= before.Size()-2<<20 {
		t.Errorf("file %d bytes after pruning, %d before", after.Size(), before.Size())
	}
	// A new read clears the layers of the read it replaces.
	if err := s.PutReleaseRead(ctx, "a", "img", "linux/amd64", "2", "sha256:j", []byte(`{}`), at); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ReleaseReadLayers(ctx, "a", "img", "linux/amd64"); l != "" {
		t.Errorf("layers of a replaced read = %q", l)
	}
	if n, err := s.DropLayerReads(ctx); err != nil || n != 4 {
		t.Fatalf("dropped %d, %v", n, err)
	}
}
