// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

func TestDeactivateAndReturn(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.publish(2, 2)
	if res, err := f.update(); err != nil || !res.Applied {
		t.Fatalf("install: %+v %v", res, err)
	}
	direct := []store.AdvisoryRecord{{AppID: "immich", Source: "github",
		Vuln: advisory.Vulnerability{SchemaVersion: "1.6.0", ID: "GHSA-direct-0001", Modified: f.now}}}
	if err := f.st.ReplaceAdvisories(ctx, "immich", "github", direct, f.now); err != nil {
		t.Fatal(err)
	}
	if f.feedAdvisories() != 3 || f.client.Catalog.Current().Len() != 1 {
		t.Fatalf("before: %d advisories, %d apps", f.feedAdvisories(), f.client.Catalog.Current().Len())
	}

	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err := f.client.Deactivate(ctx, base); err != nil {
		t.Fatal(err)
	}
	recs, _ := f.st.Advisories(ctx, "immich")
	if len(recs) != 1 || recs[0].Source != "github" {
		t.Fatalf("after leaving: %+v", recs)
	}
	if f.client.Catalog.Current() != base {
		t.Error("base catalog not restored")
	}

	// Coming back installs the same snapshot again.
	if res, err := f.update(); err != nil || !res.Applied {
		t.Fatalf("return: %+v %v", res, err)
	}
	if f.feedAdvisories() != 3 || f.client.Catalog.Current().Len() != 1 {
		t.Fatalf("after return: %d advisories, %d apps", f.feedAdvisories(), f.client.Catalog.Current().Len())
	}

	// Leaving does not open the door for a rollback.
	if err := f.client.Deactivate(ctx, base); err != nil {
		t.Fatal(err)
	}
	f.publish(1, 1)
	if _, err := f.update(); !errors.Is(err, ErrRollback) {
		t.Fatalf("older feed after leaving: %v", err)
	}
}

func TestSourceLeaveClearsNotice(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	src := &Source{Client: f.client, Store: f.st, StaleAfter: 72 * time.Hour}
	stale := func() bool {
		ns, _ := f.st.ActiveNotices(ctx)
		for _, n := range ns {
			if n.Kind == store.NoticeFeedStale {
				return true
			}
		}
		return false
	}
	if _, err := src.Refresh(ctx, nil); err == nil || !stale() {
		t.Fatalf("no feed published: %v, notice %v", err, stale())
	}
	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err := src.Leave(ctx, base); err != nil {
		t.Fatal(err)
	}
	if stale() {
		t.Error("stale notice still active after leaving the feed")
	}
}

func TestClientVerifyLicense(t *testing.T) {
	f := newFixture(t)
	lk, _ := NewKey()
	// The fixture's root has no license key: every license is refused.
	doc, err := IssueLicense(License{ID: "lic_0123456789abcdefABCDEF", Plan: PlanUplink, NotBefore: f.now.Add(-time.Hour), ExpiresAt: f.now.Add(time.Hour)}, lk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.VerifyLicense(doc, f.now); !errors.Is(err, ErrSignature) {
		t.Fatalf("license without a license key in the root: %v", err)
	}
	// A root rotation that lists the key makes the same license valid.
	next, err := SignRoot(RootSpec{Version: 2, Expires: f.now.Add(365 * 24 * time.Hour), Environment: EnvDevelopment,
		RootKeys: []ed25519.PublicKey{pub(f.rootKey)}, FeedKeys: []ed25519.PublicKey{pub(f.feedKey)}, LicenseKeys: []ed25519.PublicKey{pub(lk)},
		RootThreshold: 1, FeedThreshold: 1}, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRoot(f.pub, 2, next); err != nil {
		t.Fatal(err)
	}
	f.publish(1, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	l, err := f.client.VerifyLicense(doc, f.now)
	if err != nil || l.ID != "lic_0123456789abcdefABCDEF" {
		t.Fatalf("after rotation: %+v %v", l, err)
	}
}

type failingClear struct{ Store }

func (failingClear) ClearFeed(context.Context) error { return errors.New("database is locked") }

// A leave that cannot clear the advisories still returns to the base
// catalog and reports the failure, so it can be repeated.
func TestDeactivateFailingClear(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.publish(1, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	real := f.client.Store
	f.client.Store = failingClear{real}
	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err := f.client.Deactivate(ctx, base); err == nil {
		t.Fatal("failing clear not reported")
	}
	if f.client.Catalog.Current() != base {
		t.Error("feed catalog still active after a failed leave")
	}
	// Repeating it finishes the job.
	f.client.Store = real
	if err := f.client.Deactivate(ctx, base); err != nil || f.feedAdvisories() != 0 {
		t.Fatalf("second leave: %v, %d feed advisories", err, f.feedAdvisories())
	}
}

// The feed's refresh state goes with the feed: a last failed attempt must
// not turn into a "source feed is not updating" notice days later.
func TestSourceLeaveForgetsSourceState(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	src := &Source{Client: f.client, Store: f.st, StaleAfter: 72 * time.Hour}
	if _, err := src.Refresh(ctx, nil); err == nil {
		t.Fatal("refresh without a published feed succeeded")
	}
	if st, _ := f.st.SourceState(ctx, "feed", "manifest"); st.LastError == "" {
		t.Fatal("no failed attempt recorded")
	}
	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err := src.Leave(ctx, base); err != nil {
		t.Fatal(err)
	}
	states, err := f.st.SourceStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range states {
		if st.Source == "feed" {
			t.Errorf("feed source state survives leaving: %+v", st)
		}
	}
}

// A refresh that was chosen while the feed was in use, but runs after the
// feed was left, must not install it again.
func TestUpdateRefusedWhenNotInUse(t *testing.T) {
	f := newFixture(t)
	f.publish(1, 1)
	inUse := false
	f.client.InUse = func() bool { return inUse }
	if _, err := f.update(); !errors.Is(err, ErrNotInUse) {
		t.Fatalf("update while not in use: %v", err)
	}
	if f.feedAdvisories() != 0 || f.client.Catalog.Current().Len() != 0 {
		t.Fatalf("feed installed although not in use: %d advisories", f.feedAdvisories())
	}
	// As a source it does nothing then, and records nothing: no failed
	// attempt that would later read as a source that stopped updating.
	src := &Source{Client: f.client, Store: f.st}
	if res, err := src.Refresh(context.Background(), nil); err != nil || res.Requests != 0 {
		t.Fatalf("refresh while not in use: %+v %v", res, err)
	}
	if states, _ := f.st.SourceStates(context.Background()); len(states) != 0 {
		t.Fatalf("source state recorded while not in use: %+v", states)
	}
	if ns, _ := f.st.ActiveNotices(context.Background()); len(ns) != 0 {
		t.Fatalf("notice raised while not in use: %+v", ns)
	}
	inUse = true
	if res, err := f.update(); err != nil || !res.Applied {
		t.Fatalf("update in use: %+v %v", res, err)
	}
}
