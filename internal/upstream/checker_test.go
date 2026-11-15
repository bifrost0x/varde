// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/store"
)

const (
	running = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	rebuilt = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	newer   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// fakeRegistry answers digests and tag lists from maps; err, when set,
// answers every request.
type fakeRegistry struct {
	digests map[string]string // "repository:tag" -> digest
	tags    map[string][]string
	err     error
	heads   int
	lists   int
}

func (f *fakeRegistry) Digest(_ context.Context, repo, tag string) (string, error) {
	f.heads++
	if f.err != nil {
		return "", f.err
	}
	d, ok := f.digests[repo+":"+tag]
	if !ok {
		return "", &httpx.StatusError{Status: http.StatusNotFound}
	}
	return d, nil
}

func (f *fakeRegistry) Tags(_ context.Context, repo string) ([]string, error) {
	f.lists++
	if f.err != nil {
		return nil, f.err
	}
	return f.tags[repo], nil
}

type fakeReader struct {
	cand  remedy.Candidate
	err   error
	reads int
}

func (f *fakeReader) ReadImage(context.Context, string, string, registry.Platform, int64) (remedy.Candidate, error) {
	f.reads++
	return f.cand, f.err
}

// checkerLab is a store with one container with an image finding.
func checkerLab(t *testing.T, imageRef, repo string) (*store.Store, time.Time) {
	t.Helper()
	ctx := t.Context()
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.UpsertHost(ctx, inventory.Host{ID: "docker", Name: "docker", Kind: inventory.HostDocker, Source: inventory.SourceLocal, Arch: "x86_64", LastContact: now}); err != nil {
		t.Fatal(err)
	}
	c := &inventory.Container{ImageRef: imageRef, RepoDigests: []string{repo + "@" + running}}
	if _, err := st.ApplySnapshot(ctx, "docker", inventory.KindContainer, []inventory.Workload{{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "app-1", Container: c}}, now); err != nil {
		t.Fatal(err)
	}
	wid := inventory.WorkloadID("docker", inventory.KindContainer, "c1")
	detail := map[string]any{"advisory_id": "DEBIAN-CVE-2099-1", "match_state": "affected", "image": true, "kev": true,
		"evidence": map[string]any{"package": "Debian:12/openssl", "version": "3.0.11-1"}}
	if _, err := st.SyncFindings(ctx, []store.FindingInput{{WorkloadID: wid, AppID: "os:Debian:12/openssl", AdvisoryID: "DEBIAN-CVE-2099-1",
		MatchState: "affected", FixedIn: "3.0.15-1", Detail: detail}}, now); err != nil {
		t.Fatal(err)
	}
	return st, now
}

func newChecker(st *store.Store, reg *fakeRegistry, rd *fakeReader, now time.Time) *Checker {
	c := &Checker{Client: reg, Store: st, Enabled: func() bool { return true }, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }}
	if rd != nil {
		c.Reader, c.ReadCandidates = rd, func() bool { return true }
	}
	return c
}

func onlyCheck(t *testing.T, st *store.Store) store.UpstreamCheck {
	t.Helper()
	cs, err := st.UpstreamChecks(t.Context())
	if err != nil || len(cs) != 1 {
		t.Fatalf("checks %v: %v", cs, err)
	}
	for _, c := range cs {
		return c
	}
	return store.UpstreamCheck{}
}

func TestCheckerFloatingTagUnchanged(t *testing.T) {
	st, now := checkerLab(t, "mpepping/cyberchef:latest", "mpepping/cyberchef")
	reg := &fakeRegistry{digests: map[string]string{"docker.io/mpepping/cyberchef:latest": running}}
	n, err := newChecker(st, reg, nil, now).Once(t.Context())
	if err != nil || n != 1 {
		t.Fatalf("changed %d: %v", n, err)
	}
	ck := onlyCheck(t, st)
	if ck.HeadDigest != running || ck.CandidateDigest != "" || ck.Error != "" || ck.Platform != "linux/amd64" {
		t.Errorf("check %+v", ck)
	}
	if reg.lists != 0 {
		t.Error("a floating tag listed tags")
	}
	// Within the TTL nothing is asked again.
	if n, err := newChecker(st, reg, nil, now.Add(time.Hour)).Once(t.Context()); err != nil || n != 0 || reg.heads != 1 {
		t.Errorf("second run: changed %d, %d HEADs, %v", n, reg.heads, err)
	}
	// After it, the image is asked again.
	if _, err := newChecker(st, reg, nil, now.Add(DefaultTTL)).Once(t.Context()); err != nil || reg.heads != 2 {
		t.Errorf("after the TTL: %d HEADs, %v", reg.heads, err)
	}
}

func TestCheckerRebuiltFloatingTagIsRead(t *testing.T) {
	st, now := checkerLab(t, "mpepping/cyberchef:latest", "mpepping/cyberchef")
	reg := &fakeRegistry{digests: map[string]string{"docker.io/mpepping/cyberchef:latest": rebuilt}}
	rd := &fakeReader{cand: remedy.Candidate{Distro: "debian-12", Packages: []inventory.Package{{Manager: "dpkg", Name: "openssl", Version: "3.0.15-1"}}}}
	if _, err := newChecker(st, reg, rd, now).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	ck := onlyCheck(t, st)
	if ck.CandidateTag != "latest" || ck.CandidateDigest != rebuilt || ck.Candidate == nil || rd.reads != 1 {
		t.Fatalf("check %+v, %d reads", ck, rd.reads)
	}
	cand, err := DecodeCandidate(ck.Candidate)
	if err != nil || len(cand.Packages) != 1 {
		t.Errorf("candidate %+v: %v", cand, err)
	}
	// The same candidate is never read twice.
	if _, err := newChecker(st, reg, rd, now.Add(DefaultTTL)).Once(t.Context()); err != nil || rd.reads != 1 {
		t.Errorf("read again: %d reads, %v", rd.reads, err)
	}
}

func TestCheckerPinnedTagFindsNewerOnTrack(t *testing.T) {
	repo := "ghcr.io/immich-app/immich-machine-learning"
	st, now := checkerLab(t, repo+":v3.4.1-cuda", repo)
	reg := &fakeRegistry{
		digests: map[string]string{repo + ":v3.4.1-cuda": running, repo + ":v3.5.0-cuda": newer},
		tags:    map[string][]string{repo: {"v3.4.1", "v3.4.1-cuda", "v3.5.0", "v3.5.0-cuda", "v3.6.0-rc1-cuda", "v4.0.0-cuda", "release"}},
	}
	if _, err := newChecker(st, reg, nil, now).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	ck := onlyCheck(t, st)
	if ck.CandidateTag != "v3.5.0-cuda" || ck.CandidateDigest != newer || ck.Candidate != nil {
		t.Errorf("check %+v", ck)
	}
}

func TestCheckerPinnedTagWithoutNewer(t *testing.T) {
	repo := "ghcr.io/immich-app/immich-machine-learning"
	st, now := checkerLab(t, repo+":v3.4.1", repo)
	reg := &fakeRegistry{digests: map[string]string{repo + ":v3.4.1": running}, tags: map[string][]string{repo: {"v3.4.0", "v3.4.1", "v3.5.0-cuda", "v4.0.0"}}}
	if _, err := newChecker(st, reg, nil, now).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ck := onlyCheck(t, st); ck.CandidateDigest != "" || ck.Error != "" {
		t.Errorf("check %+v", ck)
	}
}

func TestCheckerRecordsRegistryFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"429", &httpx.StatusError{Status: http.StatusTooManyRequests}, registry.ReasonRateLimited},
		{"401", &httpx.StatusError{Status: http.StatusUnauthorized}, registry.ReasonCredentials},
		{"403", &httpx.StatusError{Status: http.StatusForbidden, RateLimit: httpx.RateLimit{Remaining: 5}}, registry.ReasonCredentials},
		{"timeout", context.DeadlineExceeded, registry.ReasonTimeout},
		{"auth scheme", registry.ErrAuthentication, registry.ReasonCredentials},
		{"other", errors.New("connection refused"), registry.ReasonUnreachable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, now := checkerLab(t, "mpepping/cyberchef:latest", "mpepping/cyberchef")
			if _, err := newChecker(st, &fakeRegistry{err: c.err}, nil, now).Once(t.Context()); err != nil {
				t.Fatal(err)
			}
			ck := onlyCheck(t, st)
			if ck.Error != c.want || ck.CandidateDigest != "" {
				t.Errorf("check %+v", ck)
			}
			s := Evaluate(Input{Container: &inventory.Container{ImageRef: "mpepping/cyberchef:latest", RepoDigests: []string{"mpepping/cyberchef@" + running}}, Check: &ck, RegistryOn: true})
			if s.Kind != Unknown || s.Reason != c.want || s.Actionable() {
				t.Errorf("status %+v", s)
			}
		})
	}
}

func TestCheckerSkipsLocalImages(t *testing.T) {
	st, now := checkerLab(t, "cyberchef-local:dev", "unused/other")
	reg := &fakeRegistry{}
	if _, err := newChecker(st, reg, nil, now).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reg.heads != 0 {
		t.Error("asked the registry about an image without a registry digest")
	}
}

func TestCheckerCandidateTooLarge(t *testing.T) {
	st, now := checkerLab(t, "mpepping/cyberchef:latest", "mpepping/cyberchef")
	reg := &fakeRegistry{digests: map[string]string{"docker.io/mpepping/cyberchef:latest": rebuilt}}
	rd := &fakeReader{err: remedy.ErrImageTooLarge}
	if _, err := newChecker(st, reg, rd, now).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	ck := onlyCheck(t, st)
	if ck.Candidate != nil || ck.CandidateError != "it is larger than Varde reads" {
		t.Errorf("check %+v", ck)
	}
	s := Evaluate(Input{Container: &inventory.Container{ImageRef: "mpepping/cyberchef:latest", RepoDigests: []string{"mpepping/cyberchef@" + running}}, Check: &ck, RegistryOn: true})
	if s.Kind != Unknown || s.TargetTag != "latest" {
		t.Errorf("status %+v", s)
	}
}
