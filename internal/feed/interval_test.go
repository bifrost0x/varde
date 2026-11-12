// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// counting counts the manifest requests that reach a mirror.
type counting struct {
	Fetcher
	manifests atomic.Int64
}

func (c *counting) Get(ctx context.Context, path, etag string, limit int64) ([]byte, string, bool, error) {
	if path == "v1/manifest.json" {
		c.manifests.Add(1)
	}
	return c.Fetcher.Get(ctx, path, etag, limit)
}

func TestRefreshHonoursMinInterval(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 1)
	mirror := &counting{Fetcher: f.client.Mirrors[0]}
	f.client.Mirrors = []Fetcher{mirror}
	src := &Source{Client: f.client, Store: f.st, MinInterval: func() time.Duration { return 24 * time.Hour }}
	ctx := context.Background()
	if _, err := src.Refresh(ctx, nil); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	res, err := src.Refresh(ctx, nil)
	if err != nil || res.Requests != 0 {
		t.Fatalf("early refresh: %+v, %v", res, err)
	}
	if n := mirror.manifests.Load(); n != 1 {
		t.Fatalf("manifest requests = %d, want 1", n)
	}
	// Check does not wait.
	if _, err := src.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if n := mirror.manifests.Load(); n != 2 {
		t.Fatalf("manifest requests after Check = %d, want 2", n)
	}
	f.now = f.now.Add(25 * time.Hour)
	if _, err := src.Refresh(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if n := mirror.manifests.Load(); n != 3 {
		t.Fatalf("manifest requests a day later = %d, want 3", n)
	}
}

// A failed check is repeated with the next run: waiting a day after a
// short outage would leave the installation without data for no reason.
func TestFailedCheckIsRepeated(t *testing.T) {
	f := newFixture(t)
	mirror := &counting{Fetcher: f.client.Mirrors[0]}
	f.client.Mirrors = []Fetcher{mirror}
	src := &Source{Client: f.client, Store: f.st, MinInterval: func() time.Duration { return 24 * time.Hour }}
	ctx := context.Background()
	if _, err := src.Refresh(ctx, nil); err == nil {
		t.Fatal("update without a published manifest succeeded")
	}
	f.now = f.now.Add(time.Hour)
	f.publish(5, 1)
	if res, err := src.Refresh(ctx, nil); err != nil || res.Updated != 1 {
		t.Fatalf("refresh after a failure: %+v, %v", res, err)
	}
}
