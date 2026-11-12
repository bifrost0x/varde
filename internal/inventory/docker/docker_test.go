// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

type fakeEngine struct {
	t       *testing.T
	mu      sync.Mutex
	methods map[string]bool
	paths   []string
	events  func(w http.ResponseWriter, r *http.Request)
	archive func(w http.ResponseWriter, r *http.Request)
	// extra answers requests before the fixed routes when it returns true.
	extra    func(w http.ResponseWriter, r *http.Request) bool
	versionJ string
}

func newFakeEngine(t *testing.T) (*fakeEngine, *httptest.Server) {
	t.Helper()
	f := &fakeEngine{t: t, methods: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.methods[r.Method] = true
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if f.extra != nil && f.extra(w, r) {
		return
	}
	switch p := r.URL.Path; {
	case p == "/version":
		if f.versionJ != "" {
			_, _ = w.Write([]byte(f.versionJ))
			return
		}
		_, _ = w.Write(fixture(f.t, "version.json"))
	case p == "/v1.51/info":
		_, _ = w.Write(fixture(f.t, "info.json"))
	case p == "/v1.51/containers/json":
		if r.URL.Query().Get("all") != "1" {
			http.Error(w, "all missing", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(fixture(f.t, "containers.json"))
	case p == "/v1.51/containers/2222222222222222222222222222222222222222222222222222222222222222/json":
		_, _ = w.Write(fixture(f.t, "container-2222.json"))
	case strings.HasPrefix(p, "/v1.51/images/sha256:aaaa"):
		_, _ = w.Write(fixture(f.t, "image-aaaa.json"))
	case strings.HasSuffix(p, "/archive") && f.archive != nil:
		f.archive(w, r)
	case p == "/v1.51/events" && f.events != nil:
		f.events(w, r)
	default:
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}
}

func (f *fakeEngine) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.paths {
		if p == path {
			n++
		}
	}
	return n
}

func newTestCollector(t *testing.T, url string) *Collector {
	t.Helper()
	c, err := New("tcp://" + strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	col := NewCollector(c, slog.New(slog.DiscardHandler))
	col.minBackoff, col.maxBackoff = 10*time.Millisecond, 50*time.Millisecond
	return col
}

func TestListBuildsSnapshot(t *testing.T) {
	f, srv := newFakeEngine(t)
	col := newTestCollector(t, srv.URL)

	snap, err := col.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if snap.Host.Name != "homelab-nas" || snap.Host.Arch != "x86_64" || !strings.HasPrefix(snap.Host.OS, "Debian") {
		t.Errorf("host: %+v", snap.Host)
	}
	if len(snap.Workloads) != 3 {
		t.Fatalf("workloads: %d", len(snap.Workloads))
	}
	byName := map[string]inventory.Workload{}
	for _, w := range snap.Workloads {
		byName[w.Name] = w
	}

	im := byName["immich_server"]
	if im.Kind != inventory.KindContainer || im.State != "running" || im.Container == nil {
		t.Fatalf("immich: %+v", im)
	}
	c := im.Container
	if c.ImageRef != "ghcr.io/immich-app/immich-server:v1.120.0" || c.ComposeProject != "immich" || c.ComposeService != "immich-server" {
		t.Errorf("immich container: %+v", c)
	}
	if c.ImageLabels["org.opencontainers.image.version"] != "v1.120.0" || len(c.RepoDigests) != 1 {
		t.Errorf("immich image data: %+v", c)
	}
	if len(c.Ports) != 2 || c.Ports[0].IP != "0.0.0.0" || c.Ports[1].IP != "::" {
		t.Errorf("ports: %+v", c.Ports)
	}
	if len(c.Networks) != 1 || c.Networks[0].IPAddress != "172.20.0.5" {
		t.Errorf("networks: %+v", c.Networks)
	}

	// Moved tag: list shows the image ID; the reference comes from inspect.
	// The image itself is gone (404) and must not fail the snapshot.
	vw := byName["vaultwarden"]
	if vw.Container.ImageRef != "vaultwarden/server:1.32.0" || vw.State != "exited" || vw.Container.ImageLabels != nil {
		t.Errorf("vaultwarden: %+v", vw.Container)
	}
	if len(vw.Container.Networks) != 2 || vw.Container.Networks[0].Name != "bridge" {
		t.Errorf("networks not sorted: %+v", vw.Container.Networks)
	}

	// Shared image inspected once per List.
	if n := f.count("/v1.51/images/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/json"); n != 1 {
		t.Errorf("image inspected %d times", n)
	}
	// Cache carries over to the next List.
	if _, err := col.List(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.count("/v1.51/images/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/json"); n != 1 {
		t.Errorf("image cache not used: %d inspections", n)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	for m := range f.methods {
		if m != http.MethodGet {
			t.Errorf("non-GET request %s", m)
		}
	}
}

func TestNegotiation(t *testing.T) {
	cases := []struct {
		version string
		want    string
		ok      bool
	}{
		{`{"ApiVersion":"1.56","MinAPIVersion":"1.40"}`, "1.51", true},
		{`{"ApiVersion":"1.43","MinAPIVersion":"1.12"}`, "1.43", true},
		{`{"ApiVersion":"1.39","MinAPIVersion":"1.12"}`, "", false},
		{`{"ApiVersion":"1.60","MinAPIVersion":"1.55"}`, "", false},
	}
	for _, tc := range cases {
		f, srv := newFakeEngine(t)
		f.versionJ = tc.version
		c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Negotiate(t.Context())
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v", tc.version, err)
			continue
		}
		if tc.ok && c.versionedPath("/x") != "/v"+tc.want+"/x" {
			t.Errorf("%s: path %s", tc.version, c.versionedPath("/x"))
		}
	}
}

func TestReadOnlyTransport(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req, _ := http.NewRequestWithContext(t.Context(), m, srv.URL+"/containers/x/kill", nil)
		if _, err := c.http.Do(req); !errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("%s: err=%v", m, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server received %d non-GET requests", hits.Load())
	}
}

func TestErrorsAndLimits(t *testing.T) {
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer forbidden.Close()
	c, _ := New("tcp://" + strings.TrimPrefix(forbidden.URL, "http://"))
	_, err := c.Negotiate(t.Context())
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusForbidden || !strings.Contains(err.Error(), "socket proxy") {
		t.Errorf("403: %v", err)
	}

	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", maxInspectBytes+10)))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer huge.Close()
	c, _ = New("tcp://" + strings.TrimPrefix(huge.URL, "http://"))
	if _, err := c.Negotiate(t.Context()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversized: %v", err)
	}

	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer garbage.Close()
	c, _ = New("tcp://" + strings.TrimPrefix(garbage.URL, "http://"))
	if _, err := c.Negotiate(t.Context()); err == nil {
		t.Error("malformed response accepted")
	}
}

func TestIDValidation(t *testing.T) {
	c, _ := New("tcp://127.0.0.1:1")
	for _, id := range []string{"../../secrets", "abc", "1111111111111111111111111111111111111111111111111111111111111111/../x", "ABCDEF0123456789"} {
		if _, err := c.InspectContainer(t.Context(), id); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("%q: %v", id, err)
		}
	}
	if !validID("sha256:aaaaaaaaaaaa") || !validID(strings.Repeat("f", 64)) {
		t.Error("valid ids rejected")
	}
}

func TestNewRejectsUnknownScheme(t *testing.T) {
	if _, err := New("ssh://host"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := New("unix:///var/run/docker.sock"); err != nil {
		t.Fatalf("unix: %v", err)
	}
}

func TestWatchFiltersAndReconnects(t *testing.T) {
	f, srv := newFakeEngine(t)
	var connections atomic.Int32
	f.events = func(w http.ResponseWriter, r *http.Request) {
		n := connections.Add(1)
		if !strings.Contains(r.URL.Query().Get("filters"), "container") {
			t.Errorf("missing filters: %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		_, _ = fmt.Fprintln(w, `{"Type":"container","Action":"exec_start: sh","Actor":{"ID":"x"}}`)
		_, _ = fmt.Fprintln(w, `{"Type":"container","Action":"health_status: healthy","Actor":{"ID":"x"}}`)
		fl.Flush()
		if n == 1 {
			// First connection: one relevant event, then drop.
			_, _ = fmt.Fprintln(w, `{"Type":"container","Action":"start","Actor":{"ID":"x"}}`)
			fl.Flush()
			return
		}
		<-r.Context().Done()
	}
	col := newTestCollector(t, srv.URL)
	if _, err := col.client.Negotiate(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	ch := col.Watch(ctx)

	got := map[string]bool{}
	deadline := time.After(5 * time.Second)
	// Signals coalesce, so assert on what was forwarded and on the
	// reconnect itself rather than on every individual signal.
	for !got["container start"] || connections.Load() < 2 {
		select {
		case ev := <-ch:
			got[ev.Reason] = true
			if strings.Contains(ev.Reason, "exec") || strings.Contains(ev.Reason, "health") {
				t.Errorf("noise event forwarded: %s", ev.Reason)
			}
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("events seen: %v, connections: %d", got, connections.Load())
		}
	}
	cancel()
	for range ch { //nolint:revive // drain until closed
	}
}
