// SPDX-License-Identifier: Apache-2.0

// Package datapkg is the data package as the rest of Varde sees it: the
// signed file set the project builds once a day, holding the advisories
// and the recognition table every installation reads. The package is one
// channel of the feed client (internal/feed); this package reports its
// state and runs an update on demand.
package datapkg

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

// ErrUnavailable reports that this installation has no data package: no
// trust root, no mirror, or the mode is fixed in the environment.
var ErrUnavailable = errors.New("the data package is not available in this installation")

// Store is what the manager reads.
type Store interface {
	FeedState(ctx context.Context) (store.FeedState, error)
	SourceState(ctx context.Context, source, key string) (store.SourceState, error)
}

// Options configure a Manager.
type Options struct {
	// Source is the feed source that reads the package; nil when the
	// package is not available.
	Source *feed.Source
	Store  Store
	// Unavailable says why, in a sentence for the settings page.
	Unavailable string
	// OnChange is called after an update on demand installed new data.
	OnChange func()
	// NoSource, when set, reports that nothing tells Varde about the
	// advisories of an app: the feed in use does not cover it and the
	// public sources are not asked.
	NoSource func(app *catalog.App) bool
}

// Status is the state of the data package for the settings page.
type Status struct {
	Available bool
	// Reason says why the package is not available.
	Reason string
	// Channel is where the installed data came from (feed.ChannelPackage,
	// feed.ChannelUplink), "" when nothing is installed.
	Channel  string
	Sequence int64
	// BuiltAt is when the installed package was built, VerifiedAt when it
	// last verified, CheckedAt when a mirror was last asked.
	BuiltAt, VerifiedAt, CheckedAt time.Time
	// LastError is the reason the last check failed, "" when it did not.
	LastError string
	// TooOld: the package is in a newer format than this version reads.
	TooOld bool
}

// Manager reports on the data package and updates it on demand.
type Manager struct{ o Options }

// New returns a Manager.
func New(o Options) *Manager { return &Manager{o: o} }

// Available reports whether this installation reads the data package.
func (m *Manager) Available() bool { return m != nil && m.o.Source != nil }

// Status returns the current state.
func (m *Manager) Status(ctx context.Context) Status {
	if !m.Available() {
		reason := ""
		if m != nil {
			reason = m.o.Unavailable
		}
		return Status{Reason: reason}
	}
	st := Status{Available: true, Channel: m.o.Source.Client.ActiveChannel(ctx)}
	if st.Channel != "" {
		if fs, err := m.o.Store.FeedState(ctx); err == nil {
			st.Sequence, st.BuiltAt, st.VerifiedAt = fs.Sequence, fs.CreatedAt, fs.VerifiedAt
		}
	}
	if ss, err := m.o.Store.SourceState(ctx, m.o.Source.Name(), "manifest"); err == nil {
		st.CheckedAt, st.LastError = ss.LastAttempt, ss.LastError
		st.TooOld = strings.Contains(ss.LastError, feed.ErrTooOld.Error())
	}
	return st
}

// NoSource reports that nothing tells Varde about the advisories of app.
func (m *Manager) NoSource(app *catalog.App) bool {
	return m != nil && m.o.NoSource != nil && m.o.NoSource(app)
}

// UpdateNow checks the mirrors at once, whatever the daily schedule says.
// An unchanged package is a success. Concurrent calls run one after the
// other; the later ones find the package unchanged.
func (m *Manager) UpdateNow(ctx context.Context) (feed.Result, error) {
	if !m.Available() {
		return feed.Result{}, ErrUnavailable
	}
	res, err := m.o.Source.Check(ctx)
	if errors.Is(err, feed.ErrNotInUse) {
		return feed.Result{}, ErrUnavailable
	}
	if err == nil && res.Applied && m.o.OnChange != nil {
		m.o.OnChange()
	}
	return res, err
}
