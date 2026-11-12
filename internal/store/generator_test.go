// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"testing"
	"time"
)

func TestCandidatesOrderAndDue(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	for _, c := range []Candidate{
		{Image: "light", Repo: "r", Weight: 1},
		{Image: "heavy", Repo: "r", Weight: 100},
		{Image: "old", Repo: "r", Weight: 500, Status: CandidateShipped, EntryYAML: "id: old", InputsHash: "h", CheckedAt: now.Add(-60 * 24 * time.Hour), ShippedAt: now.Add(-60 * 24 * time.Hour)},
		{Image: "older", Repo: "r", Weight: 5, Status: CandidateShipped, CheckedAt: now.Add(-90 * 24 * time.Hour)},
		{Image: "fresh", Repo: "r", Weight: 900, Status: CandidateShipped, CheckedAt: now.Add(-2 * 24 * time.Hour)},
		{Image: "failed", Repo: "r", Weight: 900, Status: "failed", FailedCheck: "x", CheckedAt: now.Add(-90 * 24 * time.Hour)},
	} {
		if err := s.UpsertCandidate(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Candidates(ctx, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, c := range got {
		order = append(order, c.Image)
	}
	want := []string{"heavy", "light", "older", "old"}
	if len(order) != len(want) {
		t.Fatalf("order %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order %v, want %v", order, want)
		}
	}
	if !got[0].CheckedAt.IsZero() || !got[0].ShippedAt.IsZero() {
		t.Errorf("unchecked times: %+v", got[0])
	}
	if o := got[3]; o.EntryYAML != "id: old" || o.InputsHash != "h" || !o.CheckedAt.Equal(now.Add(-60*24*time.Hour)) || !o.ShippedAt.Equal(o.CheckedAt) {
		t.Errorf("round trip: %+v", o)
	}
	if got, _ := s.Candidates(ctx, 3, now); len(got) != 3 || got[2].Image != "older" {
		t.Errorf("limit 3: %+v", got)
	}
	if got, _ := s.Candidates(ctx, 1, now); len(got) != 1 || got[0].Image != "heavy" {
		t.Errorf("limit 1: %+v", got)
	}

	// Checking a candidate moves it out of the queue; an upsert replaces.
	if err := s.UpsertCandidate(ctx, Candidate{Image: "heavy", Repo: "r", Weight: 100, Status: "failed", CheckedAt: now}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Candidates(ctx, 1, now); len(got) != 1 || got[0].Image != "light" {
		t.Errorf("after check: %+v", got)
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
	all, err := s.ReleaseReads(ctx)
	if err != nil || len(all) != 2 || string(all[0]) != `{"v":2}` {
		t.Fatalf("all: %q %v", all, err)
	}
}

func TestReplaceReleasePackagesIsAtomic(t *testing.T) {
	s, _ := openTest(t)
	ctx := t.Context()
	row := func(app, plat string) ReleasePackageRow {
		return ReleasePackageRow{AppID: app, Image: "img", Platform: plat, Tag: "1", Version: "1.0", Line: []byte(app + plat)}
	}
	if err := s.ReplaceReleasePackages(ctx, []ReleasePackageRow{row("a", "amd64"), row("a", "arm64"), row("b", "amd64")}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReleasePackagesFor(ctx, "a", "img")
	if err != nil || len(got) != 2 || string(got[0]) != "aamd64" {
		t.Fatalf("for a: %q %v", got, err)
	}

	// A duplicate key fails the replacement; the old lists stay.
	if err := s.ReplaceReleasePackages(ctx, []ReleasePackageRow{row("c", "amd64"), row("c", "amd64")}); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if got, _ := s.ReleasePackagesFor(ctx, "a", "img"); len(got) != 2 {
		t.Errorf("old lists lost: %q", got)
	}
	if got, _ := s.ReleasePackagesFor(ctx, "c", "img"); len(got) != 0 {
		t.Errorf("partial replacement visible: %q", got)
	}

	// A successful replacement drops what is not in the new set.
	if err := s.ReplaceReleasePackages(ctx, []ReleasePackageRow{row("b", "amd64")}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ReleasePackagesFor(ctx, "a", "img"); len(got) != 0 {
		t.Errorf("stale rows: %q", got)
	}
	if err := s.ReplaceReleasePackages(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ReleasePackagesFor(ctx, "b", "img"); len(got) != 0 {
		t.Errorf("not emptied: %q", got)
	}
}
