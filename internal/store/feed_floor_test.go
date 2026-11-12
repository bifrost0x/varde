// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
)

func TestFloorPerChannel(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	apply := func(channel string, seq int64, hash string) error {
		return s.ApplyFeed(ctx, FeedData{State: FeedState{Channel: channel, Sequence: seq, ManifestSHA256: hash,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), VerifiedAt: now}}, now)
	}
	if err := apply("uplink", 200, "u200"); err != nil {
		t.Fatal(err)
	}
	if err := apply("package", 100, "p100"); err != nil {
		t.Fatalf("lower sequence on another channel: %v", err)
	}
	if err := apply("package", 90, "p90"); !errors.Is(err, ErrFeedRollback) {
		t.Fatalf("older package: %v", err)
	}
	if err := apply("uplink", 150, "u150"); !errors.Is(err, ErrFeedRollback) {
		t.Fatalf("older uplink: %v", err)
	}
	st, err := s.FeedState(ctx)
	if err != nil || st.Channel != "package" || st.Sequence != 100 {
		t.Fatalf("state = %+v, %v", st, err)
	}
	fl, err := s.FeedFloor(ctx, "uplink")
	if err != nil || fl.Sequence != 200 || fl.ManifestSHA256 != "u200" {
		t.Fatalf("uplink floor = %+v, %v", fl, err)
	}
	if fl, err := s.FeedFloor(ctx, "other"); err != nil || fl.Sequence != 0 {
		t.Fatalf("unknown channel floor = %+v, %v", fl, err)
	}
	if err := apply("", 300, "x"); err == nil {
		t.Fatal("a feed without a channel was applied")
	}
}

// The package carries EPSS scores for its own CVEs only. Scores of other
// CVEs (distribution packages, NVD, apps asked about directly) come from
// the EPSS source and must survive the next package.
func TestApplyFeedKeepsOtherScores(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	if err := s.UpsertEPSS(ctx, []EPSSEntry{{CVE: "CVE-2026-1000", Score: 0.4, Percentile: 0.9, Date: "2026-11-10"},
		{CVE: "CVE-2026-2000", Score: 0.1, Percentile: 0.5, Date: "2026-11-10"}}); err != nil {
		t.Fatal(err)
	}
	err = s.ApplyFeed(ctx, FeedData{State: FeedState{Channel: "package", Sequence: 1, ManifestSHA256: "a", CreatedAt: now, ExpiresAt: now.Add(time.Hour), VerifiedAt: now},
		EPSS: []EPSSEntry{{CVE: "CVE-2026-2000", Score: 0.7, Percentile: 0.99, Date: "2026-11-11"}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	scores, err := s.EPSS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if scores["CVE-2026-1000"] != 0.4 || scores["CVE-2026-2000"] != 0.7 {
		t.Fatalf("scores = %v", scores)
	}
}

// The CVEs the EPSS source asks FIRST about while a feed is in use: those
// of the other sources only. The feed brings the scores of its own.
func TestAdvisoryCVEsExcept(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	rec := func(id string) []AdvisoryRecord {
		return []AdvisoryRecord{{AppID: "immich", Vuln: advisory.Vulnerability{SchemaVersion: "1.6.0", ID: id, Modified: now}}}
	}
	err = s.ApplyFeed(ctx, FeedData{State: FeedState{Channel: "package", Sequence: 1, ManifestSHA256: "a", CreatedAt: now, ExpiresAt: now.Add(time.Hour), VerifiedAt: now},
		Advisories: rec("CVE-2026-1111")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceAdvisories(ctx, "immich", "nvd", rec("CVE-2026-2222"), now); err != nil {
		t.Fatal(err)
	}
	all, err := s.AdvisoryCVEs(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("all CVEs = %v, %v", all, err)
	}
	other, err := s.AdvisoryCVEsExcept(ctx, FeedSource)
	if err != nil || len(other) != 1 || other[0] != "CVE-2026-2222" {
		t.Fatalf("CVEs outside the feed = %v, %v", other, err)
	}
}
