// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
)

// second publishes into another directory and returns a fetcher for it:
// the mirrors of a second channel under the same root.
func (f *fixture) second(channel string, seq int64, advisories int) Fetcher {
	f.t.Helper()
	defer func(c string) { f.channel = c }(f.channel)
	f.channel = channel
	dir := f.t.TempDir()
	if err := WriteRoot(dir, 1, f.rootData); err != nil {
		f.t.Fatal(err)
	}
	first := f.pub
	f.pub = dir
	f.publish(seq, advisories)
	f.pub = first
	fetch, err := NewFetcher("file://"+filepath.ToSlash(dir), nil, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return fetch
}

func TestChannelSwitchInstalls(t *testing.T) {
	f := newFixture(t)
	uplink := f.second(ChannelUplink, 200, 3)
	pkg := f.second(ChannelPackage, 100, 1)
	ch := Channel{Name: ChannelUplink, Mirrors: []Fetcher{uplink}}
	f.client.Pick = func() Channel { return ch }
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	if got := f.client.ActiveChannel(context.Background()); got != ChannelUplink {
		t.Fatalf("active channel = %q", got)
	}
	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err := f.client.Deactivate(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	if got := f.client.ActiveChannel(context.Background()); got != "" {
		t.Fatalf("active channel after leaving = %q", got)
	}
	ch = Channel{Name: ChannelPackage, Mirrors: []Fetcher{pkg}}
	res, err := f.update()
	if err != nil || !res.Applied {
		t.Fatalf("package after uplink: %+v, %v", res, err)
	}
	if got := f.client.ActiveChannel(context.Background()); got != ChannelPackage {
		t.Fatalf("active channel = %q", got)
	}
	if f.feedAdvisories() != 1 {
		t.Fatalf("advisories = %d, want the package's 1", f.feedAdvisories())
	}
}

// The picked channel changes while the other channel's manifest is still
// installed: the next update installs the picked one, lower sequence or not.
func TestInstalledManifestOfOtherChannelIsReplaced(t *testing.T) {
	f := newFixture(t)
	uplink := f.second(ChannelUplink, 200, 3)
	pkg := f.second(ChannelPackage, 100, 1)
	ch := Channel{Name: ChannelUplink, Mirrors: []Fetcher{uplink}}
	f.client.Pick = func() Channel { return ch }
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	ch = Channel{Name: ChannelPackage, Mirrors: []Fetcher{pkg}}
	res, err := f.update()
	if err != nil || !res.Applied || res.Unchanged {
		t.Fatalf("update = %+v, %v", res, err)
	}
	if f.feedAdvisories() != 1 {
		t.Fatalf("advisories = %d, want 1", f.feedAdvisories())
	}
	// And back: the uplink's own floor still holds, its manifest installs.
	ch = Channel{Name: ChannelUplink, Mirrors: []Fetcher{uplink}}
	if res, err := f.update(); err != nil || !res.Applied {
		t.Fatalf("back to uplink: %+v, %v", res, err)
	}
}

func TestReplayInsideChannelRefused(t *testing.T) {
	f := newFixture(t)
	uplink := f.second(ChannelUplink, 200, 3)
	ch := Channel{Name: ChannelPackage, Mirrors: f.client.Mirrors}
	f.client.Pick = func() Channel { return ch }
	f.channel = ChannelPackage
	f.publish(100, 2)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	// Away to the uplink and back: the package's floor is remembered.
	ch = Channel{Name: ChannelUplink, Mirrors: []Fetcher{uplink}}
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	ch = Channel{Name: ChannelPackage, Mirrors: f.client.Mirrors}
	f.publish(90, 1)
	if _, err := f.update(); !errors.Is(err, ErrRollback) {
		t.Fatalf("older package: %v", err)
	}
	f.publish(100, 1) // the sequence again, other content
	if _, err := f.update(); !errors.Is(err, ErrRollback) {
		t.Fatalf("reused sequence: %v", err)
	}
	if f.feedAdvisories() != 3 {
		t.Fatalf("advisories = %d, want the uplink's 3 untouched", f.feedAdvisories())
	}
}

func TestStaticChannelWithoutPick(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	if got := f.client.ActiveChannel(context.Background()); got != ChannelStatic {
		t.Fatalf("active channel = %q, want %q", got, ChannelStatic)
	}
}

// Both channels are signed by the same feed keys. A mirror of one channel
// must not be able to serve the other channel's manifest: an old package
// would pass as the uplink's first feed, and an uplink manifest would lift
// the package's floor above every real package.
func TestManifestIsBoundToItsChannel(t *testing.T) {
	f := newFixture(t)
	wrong := f.second(ChannelPackage, 100, 1)
	unnamed := f.second("", 100, 1)
	right := f.second(ChannelUplink, 100, 1)
	ch := Channel{Name: ChannelUplink, Mirrors: []Fetcher{wrong}}
	f.client.Pick = func() Channel { return ch }
	if _, err := f.update(); err == nil || !strings.Contains(err.Error(), "channel") {
		t.Fatalf("package manifest on the uplink channel: %v", err)
	}
	ch.Mirrors = []Fetcher{unnamed}
	if _, err := f.update(); err == nil || !strings.Contains(err.Error(), "channel") {
		t.Fatalf("manifest without a channel on the uplink channel: %v", err)
	}
	if fl, _ := f.st.FeedFloor(context.Background(), ChannelUplink); fl.Sequence != 0 {
		t.Fatalf("a refused manifest moved the floor: %+v", fl)
	}
	ch.Mirrors = []Fetcher{right}
	if res, err := f.update(); err != nil || !res.Applied {
		t.Fatalf("the channel's own manifest: %+v, %v", res, err)
	}
	// The static channel of VARDE_MODE=feed takes a manifest that names no
	// channel, and none that names another.
	g := newFixture(t)
	g.publish(5, 1)
	if _, err := g.update(); err != nil {
		t.Fatalf("static feed without a channel: %v", err)
	}
	g.channel = ChannelPackage
	g.publish(6, 1)
	if _, err := g.update(); err == nil {
		t.Fatal("static channel took a package manifest")
	}
}

// Reading the active channel must not wait for a running update: pages
// and the scheduler ask for it.
func TestActiveChannelDoesNotWaitForAnUpdate(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	f.client.mu.Lock() // an update in progress
	defer f.client.mu.Unlock()
	got := make(chan string, 1)
	go func() { got <- f.client.ActiveChannel(context.Background()) }()
	select {
	case ch := <-got:
		if ch != ChannelStatic {
			t.Fatalf("active channel = %q", ch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ActiveChannel waits for the update lock")
	}
}

// An update whose requester gave up while it waited for another update
// does nothing and is not recorded as a failed check.
func TestCancelledUpdateIsNotAFailure(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 1)
	src := &Source{Client: f.client, Store: f.st}
	if _, err := src.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	st, err := f.st.SourceState(context.Background(), "feed", "manifest")
	if err != nil || st.LastError != "" {
		t.Fatalf("a cancelled check was recorded as failed: %+v, %v", st, err)
	}
}
