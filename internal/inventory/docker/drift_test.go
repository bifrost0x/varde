// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

const imgNew = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

func byRuntimeID(ws []inventory.Workload) map[string]*inventory.Container {
	out := map[string]*inventory.Container{}
	for i := range ws {
		out[ws[i].RuntimeID] = ws[i].Container
	}
	return out
}

func TestDrift(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/v1.51/images/ghcr.io/immich-app/immich-server:v1.120.0/json":
			// The tag was pulled again and points to a newer image.
			_, _ = w.Write([]byte(`{"Id": "` + imgNew + `"}`))
			return true
		case "/v1.51/containers/" + idA + "/changes":
			_, _ = w.Write([]byte(`[{"Path": "/var/lib/dpkg/status", "Kind": 0}, {"Path": "/tmp/x", "Kind": 1}, {"Path": "/app/package.json", "Kind": 0}]`))
			return true
		case "/v1.51/containers/" + idC + "/changes":
			_, _ = w.Write([]byte(`null`))
			return true
		}
		return false
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	// The images were read already; only the drift checks run here.
	fresh := map[string]inventory.ImagePackages{imgA: {ImageID: imgA, Read: now.Add(100 * 24 * time.Hour), Format: ReaderFormat}, imgB: {ImageID: imgB, Read: now.Add(100 * 24 * time.Hour), Format: ReaderFormat}}
	col.Packages = &PackageReader{Store: &memPackages{m: fresh}, Now: func() time.Time { return now }}
	snap, err := col.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cs := byRuntimeID(snap.Workloads)
	if cs[idA].PulledImageID != imgNew {
		t.Errorf("pulled image not seen: %+v", cs[idA])
	}
	// Only evidence files count; /app is the parent of the working directory.
	if got := strings.Join(cs[idA].ChangedFiles, " "); got != "/var/lib/dpkg/status /app/package.json" {
		t.Errorf("changed files: %q", got)
	}
	if len(cs[idC].ChangedFiles) != 0 {
		t.Errorf("unchanged container: %v", cs[idC].ChangedFiles)
	}
	// One inspect per reference and sync.
	if n := f.count("/v1.51/images/ghcr.io/immich-app/immich-server:v1.120.0/json"); n != 1 {
		t.Errorf("reference inspected %d times", n)
	}
	// Changes are checked once a day; the answer is kept in between.
	path := "/v1.51/containers/" + idA + "/changes"
	snap, _ = col.List(t.Context())
	if f.count(path) != 1 || len(byRuntimeID(snap.Workloads)[idA].ChangedFiles) != 2 {
		t.Errorf("changes checked again within a day or answer lost: %d", f.count(path))
	}
	now = now.Add(changesEvery)
	_, _ = col.List(t.Context())
	if f.count(path) != 2 {
		t.Errorf("changes not checked after a day: %d", f.count(path))
	}
	// Switched off with the package reader, nothing is checked.
	col.Packages.Enabled = func() bool { return false }
	now = now.Add(changesEvery)
	snap, _ = col.List(t.Context())
	if f.count(path) != 2 || len(byRuntimeID(snap.Workloads)[idA].ChangedFiles) != 0 {
		t.Error("changes checked while switched off")
	}
}

func TestDriftLimits(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)
	ctx := context.Background()
	if _, err := col.client.Negotiate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"../../containers/x", "a//b", "-x", "nginx@sha256:aa", "a b", strings.Repeat("a", 300)} {
		if _, err := col.client.ImageIDByRef(ctx, ref); err == nil {
			t.Errorf("%q accepted", ref)
		}
	}
	if _, err := col.client.Changes(ctx, "../x"); err == nil {
		t.Error("invalid container ID accepted")
	}
	// An oversized change list is not read; the container gets no statement.
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/changes") {
			entry := `{"Path": "/var/lib/dpkg/status", "Kind": 0},`
			_, _ = w.Write([]byte("[" + strings.Repeat(entry, maxChangesBytes/len(entry)+1) + `{"Path": "/x", "Kind": 0}]`))
			return true
		}
		return false
	}
	col.Packages = &PackageReader{Store: &memPackages{m: map[string]inventory.ImagePackages{}}}
	snap, err := col.List(ctx)
	if err != nil {
		t.Fatalf("oversized change list failed the sync: %v", err)
	}
	if c := byRuntimeID(snap.Workloads)[idA]; len(c.ChangedFiles) != 0 {
		t.Errorf("oversized list used: %v", c.ChangedFiles)
	}
}

// A container whose Python, Ruby or Java packages changed at runtime is
// not clean: its read would stand for the whole image and hide the
// vulnerable versions of untouched containers.
func TestEvidenceChangesLanguage(t *testing.T) {
	cfg := ImageConfig{WorkingDir: "/srv/app"}
	changes := []Change{
		{Path: "/usr/local/lib/python3.12/site-packages/requests-2.31.0.dist-info", Kind: 2},
		{Path: "/usr/local/lib/python3.12/site-packages/requests-2.32.3.dist-info/METADATA", Kind: 1},
		{Path: "/usr/local/bundle/specifications/rack-3.0.0.gemspec", Kind: 1},
		{Path: "/opt/app/lib/log4j-core-2.17.1.jar", Kind: 0},
		{Path: "/usr/local/bin/gosu", Kind: 0},
		{Path: "/usr/local/lib/python3.12/site-packages/requests/api.py", Kind: 0},
		{Path: "/tmp/cache.jar", Kind: 1},
		{Path: "/var/log/app.log", Kind: 0},
	}
	got := strings.Join(evidenceChanges(changes, cfg), ",")
	for _, want := range []string{"requests-2.31.0.dist-info", "requests-2.32.3.dist-info/METADATA", "rack-3.0.0.gemspec", "log4j-core-2.17.1.jar", "/usr/local/bin/gosu"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s not counted as evidence: %s", want, got)
		}
	}
	for _, not := range []string{"api.py", "/tmp/cache.jar", "app.log"} {
		if strings.Contains(got, not) {
			t.Errorf("%s counted as evidence: %s", not, got)
		}
	}
}
