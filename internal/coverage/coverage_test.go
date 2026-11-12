// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func routed(id, rule string) inventory.Workload {
	return inventory.Workload{ID: id, Kind: inventory.KindContainer, Name: id, Container: &inventory.Container{
		ImageRef: "example/" + id + ":1", Labels: map[string]string{"traefik.http.routers." + id + ".rule": rule},
	}}
}

func TestPublicRouteNotices(t *testing.T) {
	ws := []inventory.Workload{
		routed("unknown", "Host(`wiki.example.com`)"),                                   // not in catalog: notice
		routed("noversion", "Host(`photos.example.com`)"),                               // identified, version unknown: notice
		routed("ok", "Host(`music.example.com`)"),                                       // assessable: no notice
		routed("internal", "Host(`dash.home.arpa`)"),                                    // not public: no notice
		routed("two", "Host(`a.example.com`) || Host(`b.example.com`)"),                 // two routes: two notices
		routed("weak", "Host(`x.example.com`) && PathPrefix(`/api`)"),                   // weak match: notice
		{ID: "plain", Kind: inventory.KindContainer, Container: &inventory.Container{}}, // no labels
	}
	ids := map[string]identify.Result{
		"noversion": {AppID: "immich", Confidence: identify.Exact},
		"ok":        {AppID: "navidrome", Confidence: identify.Exact, Version: "0.60.0"},
		"weak":      {AppID: "outline", Confidence: identify.Weak, Version: "1.0.0"},
	}
	got := PublicRouteNotices(ws, ids, []string{"example.com"}, nil)
	titles := map[string]string{}
	for _, n := range got {
		titles[n.Title] = n.Detail
		if !strings.HasPrefix(n.Key, store.NoticePublicRoute+":") {
			t.Errorf("key %q", n.Key)
		}
	}
	for host, reason := range map[string]string{
		"wiki.example.com":   "not in the catalog",
		"photos.example.com": "version is unknown",
		"a.example.com":      "not in the catalog",
		"b.example.com":      "not in the catalog",
		"x.example.com":      "probable match",
	} {
		d, ok := titles["Public route "+host+" is not checked"]
		if !ok || !strings.Contains(d, reason) {
			t.Errorf("%s: %q present=%v", host, d, ok)
		}
	}
	if len(got) != 5 {
		t.Errorf("got %d notices: %v", len(got), titles)
	}
	if n := PublicRouteNotices(ws, ids, nil, nil); len(n) != 0 {
		t.Errorf("without public domains: %d", len(n))
	}
}

func TestNoticeEpisodes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	n := store.Notice{Key: "k1", Subject: "w", Title: "Public route a is not checked"}
	if err := st.SyncNotices(ctx, store.NoticePublicRoute, []store.Notice{n}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkNoticesNotified(ctx, []string{"k1"}, now); err != nil {
		t.Fatal(err)
	}
	// Still present: stays notified.
	_ = st.SyncNotices(ctx, store.NoticePublicRoute, []store.Notice{n}, now.Add(time.Hour))
	ns, _ := st.ActiveNotices(ctx)
	if len(ns) != 1 || ns[0].NotifiedAt == nil {
		t.Fatalf("refresh lost the notified mark: %+v", ns)
	}
	// Other kinds are not touched by a sync.
	_ = st.SyncNotices(ctx, store.NoticeHostStale, nil, now)
	if ns, _ := st.ActiveNotices(ctx); len(ns) != 1 {
		t.Fatal("sync of another kind resolved the notice")
	}
	// Gone: resolved. Back: a new episode that is notified again.
	_ = st.SyncNotices(ctx, store.NoticePublicRoute, nil, now.Add(2*time.Hour))
	if ns, _ := st.ActiveNotices(ctx); len(ns) != 0 {
		t.Fatal("not resolved")
	}
	_ = st.SyncNotices(ctx, store.NoticePublicRoute, []store.Notice{n}, now.Add(3*time.Hour))
	ns, _ = st.ActiveNotices(ctx)
	if len(ns) != 1 || ns[0].NotifiedAt != nil || !ns[0].FirstSeen.After(now.Add(2*time.Hour)) {
		t.Fatalf("new episode: %+v", ns)
	}
}

func TestNotAnApp(t *testing.T) {
	img := func(ref string) inventory.Workload {
		return inventory.Workload{ID: ref, Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: ref}}
	}
	none := identify.Result{}
	cases := []struct {
		wl     inventory.Workload
		id     identify.Result
		marked map[string]bool
		want   string
	}{
		{img("pgvector/pgvector:pg16"), none, nil, KindDatabase},
		// PostgreSQL itself is a catalog entry and counts as an app.
		{img("postgres:16-alpine"), none, nil, ""},
		{img("tecnativa/docker-socket-proxy:v0.5.0"), none, nil, KindProxy},
		{img("ghcr.io/linuxserver/socket-proxy:latest"), none, nil, KindProxy},
		{img("ghcr.io/acme/thing:1"), none, map[string]bool{"ghcr.io/acme/thing": true}, KindUser},
		{img("ghcr.io/acme/thing:1"), none, nil, ""},
		// A catalog match always counts, even for a marked repository.
		{img("ghcr.io/acme/thing:1"), identify.Result{AppID: "x", Confidence: identify.Exact}, map[string]bool{"ghcr.io/acme/thing": true}, ""},
		{inventory.Workload{ID: "m", Kind: inventory.KindManual}, none, nil, ""},
	}
	for _, c := range cases {
		got, ok := NotAnApp(c.wl, c.id, c.marked)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s: %q %v, want %q", c.wl.ID, got, ok, c.want)
		}
	}
}

func TestPublicRouteNoticesSkipNotAnApp(t *testing.T) {
	db := routed("db", "Host(`db.example.com`)")
	db.Container.ImageRef = "pgvector/pgvector:pg16"
	marked := routed("tool", "Host(`tool.example.com`)")
	got := PublicRouteNotices([]inventory.Workload{db, marked}, nil, []string{"example.com"}, map[string]bool{"docker.io/example/tool": true})
	if len(got) != 0 {
		t.Fatalf("helper and marked containers produced notices: %v", got)
	}
	if got := PublicRouteNotices([]inventory.Workload{marked}, nil, []string{"example.com"}, nil); len(got) != 1 {
		t.Fatalf("unmarked container: %d notices, want 1", len(got))
	}
}
