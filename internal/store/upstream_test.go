// SPDX-License-Identifier: Apache-2.0

package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestUpstreamChecksRoundTripAndPrune(t *testing.T) {
	ctx := t.Context()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	a := UpstreamKey{Repository: "docker.io/org/app", Tag: "latest", RunningDigest: "sha256:a", Platform: "linux/amd64"}
	b := UpstreamKey{Repository: "docker.io/org/other", Tag: "1.0", RunningDigest: "sha256:b", Platform: "linux/amd64"}
	if err := st.RecordUpstreamCheck(ctx, UpstreamCheck{UpstreamKey: a, HeadDigest: "sha256:n", CandidateTag: "latest", CandidateDigest: "sha256:n",
		Candidate: []byte{1, 2}, CandidateReadAt: now, Checked: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUpstreamCheck(ctx, UpstreamCheck{UpstreamKey: b, Error: "the registry limits requests", Checked: now}); err != nil {
		t.Fatal(err)
	}
	cs, err := st.UpstreamChecks(ctx)
	if err != nil || len(cs) != 2 {
		t.Fatalf("checks %v: %v", cs, err)
	}
	if c := cs[a]; c.CandidateDigest != "sha256:n" || len(c.Candidate) != 2 || !c.CandidateReadAt.Equal(now) || !c.Checked.Equal(now) {
		t.Errorf("check a %+v", c)
	}
	if c := cs[b]; c.Candidate != nil || !c.CandidateReadAt.IsZero() || c.Error == "" {
		t.Errorf("check b %+v", c)
	}
	if err := st.PruneUpstreamChecks(ctx, map[UpstreamKey]bool{a: true}); err != nil {
		t.Fatal(err)
	}
	if cs, _ = st.UpstreamChecks(ctx); len(cs) != 1 {
		t.Errorf("after prune %v", cs)
	}
}

func TestTrimLayerReadsKeepsTheNewest(t *testing.T) {
	ctx := t.Context()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	for i, d := range []string{"old", "mid", "new"} {
		if err := st.PutLayerRead(ctx, d, make([]byte, 100), false, now.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := st.TrimLayerReads(ctx, 250)
	if err != nil || n != 1 {
		t.Fatalf("trimmed %d: %v", n, err)
	}
	if _, _, ok, _ := st.LayerRead(ctx, "old"); ok {
		t.Error("the oldest read stayed")
	}
	if _, _, ok, _ := st.LayerRead(ctx, "new"); !ok {
		t.Error("the newest read went")
	}
}
