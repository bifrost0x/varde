// SPDX-License-Identifier: Apache-2.0

package uplink

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/store"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Settings(context.Context) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.m {
		out[k] = v
	}
	return out, nil
}

func (s *memStore) PutSettings(_ context.Context, values map[string]string, _ string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range values {
		if v == "" {
			delete(s.m, k)
		} else {
			s.m[k] = v
		}
	}
	return nil
}

func (s *memStore) get(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k]
}

// fakeFeed verifies licenses with a real root; updates are scripted.
type fakeFeed struct {
	root      *feed.Root
	mu        sync.Mutex
	updateErr error
	loadErr   error
	updates   int
	loads     int
	leaves    int
	authSeen  []string
	auth      func() string
	leaveErr  error
	// authAtLeave is what Authorization returned when the feed was left.
	authAtLeave string
}

func (f *fakeFeed) VerifyLicense(doc []byte, now time.Time) (*feed.License, error) {
	return f.root.VerifyLicense(doc, now)
}
func (f *fakeFeed) Development() bool { return true }
func (f *fakeFeed) Update(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates++
	if f.auth != nil {
		f.authSeen = append(f.authSeen, f.auth())
	}
	return f.updateErr
}
func (f *fakeFeed) LoadActive(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	return f.loadErr
}
func (f *fakeFeed) Leave(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaves++
	if f.auth != nil {
		f.authAtLeave = f.auth()
	}
	// Like the real feed, leaving fails on a cancelled context.
	f.leaveErr = ctx.Err()
	return f.leaveErr
}

func (f *fakeFeed) lastLeaveErr() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.leaveErr
}

// memNotices records the active notices per kind.
type memNotices struct {
	mu sync.Mutex
	m  map[string][]store.Notice
}

func (n *memNotices) SyncNotices(_ context.Context, kind string, current []store.Notice, _ time.Time) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.m == nil {
		n.m = map[string][]store.Notice{}
	}
	n.m[kind] = current
	return nil
}

func (n *memNotices) title() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ns := n.m[store.NoticeUplink]; len(ns) == 1 {
		return ns[0].Title
	}
	return ""
}
func (f *fakeFeed) count() (updates, loads, leaves int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updates, f.loads, f.leaves
}

type fixture struct {
	t       *testing.T
	now     atomic.Pointer[time.Time]
	feed    *fakeFeed
	store   *memStore
	box     *integrations.Box
	boxPath string
	key     ed25519.PrivateKey
	changes atomic.Int32
	notices *memNotices
	// loadLeaves is how often the last manager left the feed while loading.
	loadLeaves int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, store: &memStore{m: map[string]string{}}, boxPath: filepath.Join(t.TempDir(), "secret.key"), notices: &memNotices{}}
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	f.now.Store(&now)
	rk, _ := feed.NewKey()
	fk, _ := feed.NewKey()
	f.key, _ = feed.NewKey()
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	data, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: now.Add(365 * 24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{pub(rk)}, FeedKeys: []ed25519.PublicKey{pub(fk)}, LicenseKeys: []ed25519.PublicKey{pub(f.key)},
		RootThreshold: 1, FeedThreshold: 1}, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := feed.ParseRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	f.feed = &fakeFeed{root: root}
	if f.box, err = integrations.OpenBox(f.boxPath); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) clock() time.Time { return *f.now.Load() }
func (f *fixture) advance(d time.Duration) {
	n := f.clock().Add(d)
	f.now.Store(&n)
}

func (f *fixture) manager(mut func(*Options)) *Manager {
	o := Options{Feed: f.feed, Box: f.box, Store: f.store, Now: f.clock, Log: slog.New(slog.DiscardHandler),
		OnChange: func() { f.changes.Add(1) }, Notices: f.notices}
	if mut != nil {
		mut(&o)
	}
	m := New(o)
	f.feed.auth = m.Authorization
	f.feed.mu.Lock()
	before := f.feed.leaves
	f.feed.mu.Unlock()
	m.Load(context.Background())
	// Tests count the leaves of their own actions, not those of loading.
	f.feed.mu.Lock()
	f.loadLeaves = f.feed.leaves - before
	f.feed.leaves = before
	f.feed.mu.Unlock()
	return m
}

func (f *fixture) license(valid time.Duration, key ed25519.PrivateKey) []byte {
	f.t.Helper()
	doc, err := feed.IssueLicense(feed.License{ID: "lic_0123456789abcdefABCDEF", Plan: feed.PlanUplink,
		NotBefore: f.clock().Add(-time.Hour), ExpiresAt: f.clock().Add(valid)}, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return doc
}

func TestEnable(t *testing.T) {
	f := newFixture(t)
	m := f.manager(nil)
	ctx := context.Background()
	if s := m.Status(); s.State != Off || m.Active() || m.Authorization() != "" {
		t.Fatalf("fresh: %+v", s)
	}
	doc := f.license(30*24*time.Hour, f.key)
	if err := m.Enable(ctx, doc, "admin"); err != nil {
		t.Fatal(err)
	}
	s := m.Status()
	if s.State != Active || s.LicenseID != "lic_0123456789abcdefABCDEF" || !s.ExpiresAt.Equal(f.clock().Add(30*24*time.Hour)) || !s.Development {
		t.Fatalf("status = %+v", s)
	}
	if !m.Active() || !strings.HasPrefix(m.Authorization(), "Varde-License ") {
		t.Fatalf("active %v, authorization %q", m.Active(), m.Authorization())
	}
	// The license went out with the verifying update, not before.
	if u, _, _ := f.feed.count(); u != 1 || len(f.feed.authSeen) != 1 || f.feed.authSeen[0] != m.Authorization() {
		t.Errorf("updates %d, authorization seen %q", u, f.feed.authSeen)
	}
	if f.store.get(keyEnabled) != "true" || f.store.get(keyLicense) == "" || strings.Contains(f.store.get(keyLicense), "lic_") {
		t.Errorf("stored: enabled %q, license sealed %v", f.store.get(keyEnabled), !strings.Contains(f.store.get(keyLicense), "lic_"))
	}
	if f.changes.Load() != 1 {
		t.Errorf("OnChange called %d times", f.changes.Load())
	}
}

func TestEnableRefused(t *testing.T) {
	ctx := context.Background()
	other, _ := feed.NewKey()
	t.Run("bad signature", func(t *testing.T) {
		f := newFixture(t)
		m := f.manager(nil)
		err := m.Enable(ctx, f.license(time.Hour, other), "admin")
		if !errors.Is(err, feed.ErrSignature) {
			t.Fatalf("err = %v", err)
		}
		if u, _, _ := f.feed.count(); u != 0 {
			t.Error("the feed was asked with an unverified license")
		}
		if m.Status().State != Off || m.Authorization() != "" || len(f.store.m) != 0 || f.changes.Load() != 0 {
			t.Errorf("state %+v, stored %v", m.Status(), f.store.m)
		}
	})
	t.Run("feed does not verify", func(t *testing.T) {
		f := newFixture(t)
		f.feed.updateErr = errors.New("mirror unreachable")
		m := f.manager(nil)
		err := m.Enable(ctx, f.license(time.Hour, f.key), "admin")
		if err == nil || !strings.Contains(err.Error(), "mirror unreachable") {
			t.Fatalf("err = %v", err)
		}
		if m.Status().State != Off || m.Active() || m.Authorization() != "" || len(f.store.m) != 0 {
			t.Errorf("state %+v, authorization %q, stored %v", m.Status(), m.Authorization(), f.store.m)
		}
		if _, _, l := f.feed.count(); l != 1 {
			t.Errorf("a failed switch-on must leave the feed again; leaves = %d", l)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		f := newFixture(t)
		m := f.manager(nil)
		if err := m.Enable(ctx, []byte("hello"), "admin"); !errors.Is(err, feed.ErrLicense) {
			t.Fatalf("err = %v", err)
		}
		if err := m.Enable(ctx, nil, "admin"); !errors.Is(err, ErrNoLicense) {
			t.Fatalf("no stored license: %v", err)
		}
	})
}

func TestExpiry(t *testing.T) {
	f := newFixture(t)
	m := f.manager(nil)
	ctx := context.Background()
	if err := m.Enable(ctx, f.license(time.Hour, f.key), "admin"); err != nil {
		t.Fatal(err)
	}
	f.advance(59 * time.Minute)
	if !m.Active() {
		t.Fatal("inactive before expiry")
	}
	f.advance(2 * time.Minute)
	if m.Active() || m.Authorization() != "" {
		t.Fatal("active after expiry")
	}
	m.Active()
	s := m.Status()
	if s.State != Expired || s.Reason == "" || s.LicenseID == "" {
		t.Fatalf("status = %+v", s)
	}
	if _, _, l := f.feed.count(); l != 1 {
		t.Errorf("feed left %d times, want once", l)
	}
	if f.store.get(keyEnabled) != "false" || f.changes.Load() != 2 {
		t.Errorf("enabled %q, changes %d", f.store.get(keyEnabled), f.changes.Load())
	}
	// A restart reports the same.
	if s := f.manager(nil).Status(); s.State != Expired {
		t.Errorf("after restart: %+v", s)
	}
}

func TestDisableEnableRemove(t *testing.T) {
	f := newFixture(t)
	m := f.manager(nil)
	ctx := context.Background()
	if err := m.Enable(ctx, f.license(time.Hour*24, f.key), "admin"); err != nil {
		t.Fatal(err)
	}
	if err := m.Disable(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	s := m.Status()
	if s.State != Off || s.LicenseID == "" || m.Active() || m.Authorization() != "" {
		t.Fatalf("after disable: %+v", s)
	}
	if _, _, l := f.feed.count(); l != 1 {
		t.Errorf("leaves = %d", l)
	}
	// The stored license switches the uplink on again without pasting it.
	if err := m.Enable(ctx, nil, "admin"); err != nil || m.Status().State != Active {
		t.Fatalf("enable from stored license: %v, %+v", err, m.Status())
	}
	if err := m.Remove(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if s := m.Status(); s.State != Off || s.LicenseID != "" || len(f.store.m) != 1 || f.store.get(keyEnabled) != "false" {
		t.Fatalf("after remove: %+v, stored %v", s, f.store.m)
	}
}

func TestLoad(t *testing.T) {
	ctx := context.Background()
	t.Run("active survives a failing mirror", func(t *testing.T) {
		f := newFixture(t)
		if err := f.manager(nil).Enable(ctx, f.license(24*time.Hour, f.key), "admin"); err != nil {
			t.Fatal(err)
		}
		f.feed.loadErr = errors.New("blob cache damaged")
		f.feed.updateErr = errors.New("mirror unreachable")
		m := f.manager(nil)
		if s := m.Status(); s.State != Active || !m.Active() || m.Authorization() == "" {
			t.Fatalf("status = %+v", s)
		}
		if _, l, _ := f.feed.count(); l != 1 || f.loadLeaves != 0 {
			t.Errorf("loads %d, leaves while loading %d", l, f.loadLeaves)
		}
	})
	t.Run("switched off stays off", func(t *testing.T) {
		f := newFixture(t)
		m := f.manager(nil)
		_ = m.Enable(ctx, f.license(24*time.Hour, f.key), "admin")
		_ = m.Disable(ctx, "admin")
		m2 := f.manager(nil)
		if s := m2.Status(); s.State != Off || s.LicenseID == "" || m2.Authorization() != "" {
			t.Fatalf("status = %+v", s)
		}
		if _, l, _ := f.feed.count(); l != 0 {
			t.Errorf("feed loaded while off: %d", l)
		}
	})
	t.Run("secret key changed", func(t *testing.T) {
		f := newFixture(t)
		_ = f.manager(nil).Enable(ctx, f.license(24*time.Hour, f.key), "admin")
		other, err := integrations.OpenBox(filepath.Join(t.TempDir(), "other.key"))
		if err != nil {
			t.Fatal(err)
		}
		m := f.manager(func(o *Options) { o.Box = other })
		s := m.Status()
		if s.State != Failed || s.Reason == "" || m.Active() || m.Authorization() != "" {
			t.Fatalf("status = %+v", s)
		}
		if f.loadLeaves != 1 {
			t.Errorf("feed data must be left when the license is unreadable; leaves = %d", f.loadLeaves)
		}
		if f.notices.title() == "" {
			t.Error("no notice although the uplink went off by itself")
		}
		// Entering the license again repairs it.
		if err := m.Enable(ctx, f.license(24*time.Hour, f.key), "admin"); err != nil || m.Status().State != Active {
			t.Fatalf("re-enter: %v %+v", err, m.Status())
		}
	})
	t.Run("license key removed from the root", func(t *testing.T) {
		f := newFixture(t)
		_ = f.manager(nil).Enable(ctx, f.license(24*time.Hour, f.key), "admin")
		g := newFixture(t) // another root that does not know the key
		f.feed.root = g.feed.root
		m := f.manager(nil)
		if s := m.Status(); s.State != Failed || m.Active() {
			t.Fatalf("status = %+v", s)
		}
	})
}

func TestLockedAndUnavailable(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	m := f.manager(func(o *Options) { o.Locked = true })
	if err := m.Enable(ctx, f.license(time.Hour, f.key), "admin"); !errors.Is(err, ErrLocked) {
		t.Errorf("enable while locked: %v", err)
	}
	if err := m.Disable(ctx, "admin"); !errors.Is(err, ErrLocked) {
		t.Errorf("disable while locked: %v", err)
	}
	if !m.Status().Locked {
		t.Error("status not locked")
	}

	f = newFixture(t)
	m = New(Options{Box: f.box, Store: f.store, Now: f.clock, Unavailable: "no trust root in this build"})
	m.Load(ctx)
	if s := m.Status(); s.State != Unavailable || s.Reason != "no trust root in this build" || m.Active() {
		t.Fatalf("status = %+v", s)
	}
	if err := m.Enable(ctx, f.license(time.Hour, f.key), "admin"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("enable while unavailable: %v", err)
	}
}

func TestConcurrentSwitch(t *testing.T) {
	f := newFixture(t)
	m := f.manager(nil)
	ctx := context.Background()
	doc := f.license(24*time.Hour, f.key)
	stop := make(chan struct{})
	var poll sync.WaitGroup
	poll.Add(1)
	go func() {
		defer poll.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = m.Active()
				_ = m.Authorization()
				_ = m.Status()
			}
		}
	}()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if i%2 == 0 {
					_ = m.Enable(ctx, doc, "admin")
				} else {
					_ = m.Disable(ctx, "admin")
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	poll.Wait()
	s := m.Status()
	want := map[State]string{Active: "true", Off: "false"}[s.State]
	if want == "" || f.store.get(keyEnabled) != want || (s.State == Active) != m.Active() || (m.Authorization() != "") != m.Active() {
		t.Fatalf("inconsistent: status %+v, stored %q, active %v", s, f.store.get(keyEnabled), m.Active())
	}
}

// The uplink ending by itself must reach the overview and the notifier,
// not only the settings page.
func TestNotices(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	m := f.manager(nil)
	if err := m.Enable(ctx, f.license(time.Hour, f.key), "admin"); err != nil {
		t.Fatal(err)
	}
	if f.notices.title() != "" {
		t.Fatalf("notice while active: %q", f.notices.title())
	}
	f.advance(2 * time.Hour)
	m.Active()
	if got := f.notices.title(); got != "Uplink license expired" {
		t.Fatalf("after expiry: %q", got)
	}
	// It stays across a restart and goes when the user acts.
	m = f.manager(nil)
	if f.notices.title() == "" {
		t.Fatal("notice lost by a restart")
	}
	f.advance(-2 * time.Hour)
	if err := m.Enable(ctx, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if f.notices.title() != "" {
		t.Errorf("notice after switching on again: %q", f.notices.title())
	}
	// Switching off on purpose raises nothing.
	if err := m.Disable(ctx, "admin"); err != nil || f.notices.title() != "" {
		t.Errorf("disable: %v, notice %q", err, f.notices.title())
	}
	// Expiry found at start, with the uplink on.
	if err := m.Enable(ctx, f.license(time.Hour, f.key), "admin"); err != nil {
		t.Fatal(err)
	}
	f.advance(2 * time.Hour)
	f.manager(nil)
	if f.notices.title() != "Uplink license expired" || f.loadLeaves != 1 {
		t.Errorf("expired at start: notice %q, leaves %d", f.notices.title(), f.loadLeaves)
	}
}

// Leaving must not depend on the request that asked for it: a cancelled
// request would otherwise leave feed data behind for good.
func TestLeaveSurvivesCancelledRequest(t *testing.T) {
	f := newFixture(t)
	m := f.manager(nil)
	if err := m.Enable(context.Background(), f.license(time.Hour, f.key), "admin"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Disable(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, l := f.feed.count(); l != 1 {
		t.Fatalf("leaves = %d", l)
	}
	if got := f.feed.lastLeaveErr(); got != nil {
		t.Errorf("leave ran with the cancelled request context: %v", got)
	}
}

// A start in any state but active clears what an interrupted leave left.
func TestLoadLeavesWhenNotActive(t *testing.T) {
	f := newFixture(t)
	f.manager(nil)
	if f.loadLeaves != 1 {
		t.Errorf("fresh install with a feed: leaves while loading = %d, want 1", f.loadLeaves)
	}
	m := f.manager(nil)
	_ = m.Enable(context.Background(), f.license(time.Hour, f.key), "admin")
	_ = m.Disable(context.Background(), "admin")
	f.manager(nil)
	if f.loadLeaves != 1 {
		t.Errorf("switched off: leaves while loading = %d, want 1", f.loadLeaves)
	}
}

// The feed is marked as out of use before it is left, so a refresh that
// already chose the feed finds it closed (feed.Client.InUse).
func TestOutOfUseBeforeLeaving(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	m := f.manager(nil)
	if err := m.Enable(ctx, f.license(time.Hour, f.key), "admin"); err != nil {
		t.Fatal(err)
	}
	if !m.InUse() {
		t.Fatal("active uplink not in use")
	}
	if err := m.Disable(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if f.feed.authAtLeave != "" || m.InUse() {
		t.Errorf("switch off: still in use while leaving (authorization %q)", f.feed.authAtLeave)
	}
	if err := m.Enable(ctx, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	f.feed.authAtLeave = "unset"
	f.advance(2 * time.Hour)
	m.Active()
	if f.feed.authAtLeave != "" || m.InUse() {
		t.Errorf("expiry: still in use while leaving (authorization %q)", f.feed.authAtLeave)
	}
}
