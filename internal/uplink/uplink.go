// SPDX-License-Identifier: Apache-2.0

// Package uplink switches a running installation between the free direct
// mode and the paid data feed ("uplink", ADR 0037 and 0038). It verifies
// the license offline against the feed's trust root, keeps it sealed in
// the settings and tells the advisory sources and the feed fetchers which
// mode applies. Without a license nothing here changes how Varde works.
package uplink

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

// State of the uplink.
type State string

// States.
const (
	// Off: no license stored, or the uplink is switched off.
	Off State = "off"
	// Active: a valid license is in use and advisories come from the feed.
	Active State = "active"
	// Expired: the stored license is past its expiry; direct mode is used.
	Expired State = "expired"
	// Unavailable: this installation has no trust root or no feed mirrors.
	Unavailable State = "unavailable"
	// Failed: the stored license cannot be read or is refused.
	Failed State = "error"
)

// Status is what the UI shows.
type Status struct {
	State     State
	LicenseID string
	ExpiresAt time.Time
	// Reason explains Unavailable, Failed and Expired to the user.
	Reason string
	// Locked: the mode is set in the environment and cannot be changed here.
	Locked bool
	// Development: the trust root is a development root.
	Development bool
}

// Errors of Enable, Disable and Remove.
var (
	ErrLocked      = errors.New("the mode is set in the environment")
	ErrUnavailable = errors.New("the uplink is not available in this installation")
	ErrNoLicense   = errors.New("no license stored")
)

// Feed is the feed client as the manager uses it.
type Feed interface {
	// VerifyLicense checks a license against the current trust root.
	VerifyLicense(doc []byte, now time.Time) (*feed.License, error)
	// Update fetches and installs the current feed.
	Update(ctx context.Context) error
	// LoadActive activates the installed feed without the network.
	LoadActive(ctx context.Context) error
	// Leave removes the feed's data and restores the built-in catalog.
	Leave(ctx context.Context) error
	// Development reports a development trust root.
	Development() bool
}

// Box seals the license at rest.
type Box interface {
	Seal(id string, plaintext []byte) ([]byte, error)
	Open(id string, sealed []byte) ([]byte, error)
}

// Store keeps the switch and the sealed license with the other settings.
type Store interface {
	Settings(ctx context.Context) (map[string]string, error)
	PutSettings(ctx context.Context, values map[string]string, by string, now time.Time) error
}

// Notices raises and withdraws system notices (the store).
type Notices interface {
	SyncNotices(ctx context.Context, kind string, current []store.Notice, now time.Time) error
}

// Options configure a Manager.
type Options struct {
	// Feed is nil when the installation has no trust root or mirrors.
	Feed  Feed
	Box   Box
	Store Store
	Now   func() time.Time
	Log   *slog.Logger
	// Locked refuses changes: VARDE_MODE is set in the environment.
	Locked bool
	// Unavailable is the reason shown when Feed is nil.
	Unavailable string
	// OnChange runs after the mode changed (refresh the advisories).
	OnChange func()
	// Notices tells the user when the uplink went off by itself; optional.
	Notices Notices
	// After says, in notices, what Varde does once the uplink is off; the
	// default is that it asks the public sources itself again.
	After string
}

// Setting keys; not part of the settings form.
const (
	keyEnabled = "UPLINK_ENABLED"
	keyLicense = "UPLINK_LICENSE"
	boxID      = "uplink-license"
)

type snapshot struct {
	status Status
	// auth is the Authorization value sent to feed mirrors: set while the
	// uplink is active and during the verifying update of a switch-on.
	auth string
}

// Manager holds the uplink state.
type Manager struct {
	o    Options
	mu   sync.Mutex // serialises Load, Enable, Disable, Remove and expiry
	snap atomic.Pointer[snapshot]
	// doc is the stored license document; guarded by mu.
	doc []byte
}

// New returns a manager; call Load before use.
func New(o Options) *Manager {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	m := &Manager{o: o}
	m.set(m.base(Off), "")
	if o.Feed == nil {
		st := m.base(Unavailable)
		st.Reason = o.Unavailable
		m.set(st, "")
	}
	return m
}

func (m *Manager) base(s State) Status {
	st := Status{State: s, Locked: m.o.Locked}
	if m.o.Feed != nil {
		st.Development = m.o.Feed.Development()
	}
	return st
}

func (m *Manager) set(st Status, auth string) { m.snap.Store(&snapshot{status: st, auth: auth}) }

func authorization(doc []byte) string {
	return "Varde-License " + base64.StdEncoding.EncodeToString(doc)
}

func withLicense(st Status, l *feed.License) Status {
	st.LicenseID, st.ExpiresAt = l.ID, l.ExpiresAt
	return st
}

func expiredReason(l *feed.License) string {
	return fmt.Sprintf("The license expired on %s.", l.ExpiresAt.Format("2006-01-02"))
}

// Load restores the state after a start: with the uplink on and a valid
// license the installed feed is activated without the network; a failing
// feed leaves the uplink on (the last verified feed stays in use). A
// license that expired or cannot be used returns to direct mode.
func (m *Manager) Load(ctx context.Context) {
	if m.o.Feed == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load(ctx)
	if m.snap.Load().status.State != Active {
		// Also clears what an interrupted leave left behind; leaving is
		// cheap and can be repeated.
		m.leave(ctx)
	}
}

func (m *Manager) load(ctx context.Context) {
	values, err := m.o.Store.Settings(ctx)
	if err != nil {
		m.fail(ctx, false, "The settings could not be read: "+err.Error())
		return
	}
	enabled := values[keyEnabled] == "true"
	sealed := values[keyLicense]
	if sealed == "" {
		if enabled {
			m.fail(ctx, true, "The uplink was on but no license is stored. Enter the license again.")
		}
		return
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err == nil {
		raw, err = m.o.Box.Open(boxID, raw)
	}
	if err != nil {
		m.fail(ctx, enabled, "The stored license cannot be read ("+err.Error()+"). Enter the license again.")
		return
	}
	m.doc = raw
	now := m.o.Now()
	l, err := m.o.Feed.VerifyLicense(raw, now)
	switch {
	case errors.Is(err, feed.ErrExpired):
		if pl, _, perr := feed.ParseLicense(raw); perr == nil {
			l = pl
		} else {
			l = &feed.License{}
		}
		st := withLicense(m.base(Expired), l)
		st.Reason = expiredReason(l)
		m.set(st, "")
		if enabled {
			m.persistOff(ctx)
			m.notify(ctx, "Uplink license expired", st.Reason+" "+m.after()+" Renew the license under Settings › Uplink.")
		}
	case err != nil:
		m.fail(ctx, enabled, "The stored license is not accepted: "+err.Error())
	case !enabled:
		m.set(withLicense(m.base(Off), l), "")
	default:
		m.set(withLicense(m.base(Active), l), authorization(raw))
		if err := m.o.Feed.LoadActive(ctx); err != nil {
			m.o.Log.Error("installed uplink feed could not be loaded; the next update installs it again", "err", err)
		}
	}
}

// fail records a license problem; with the uplink on it also returns to
// direct mode, since no license can be sent.
func (m *Manager) fail(ctx context.Context, wasEnabled bool, reason string) {
	st := m.base(Failed)
	st.Reason = reason
	m.set(st, "")
	if wasEnabled {
		m.persistOff(ctx)
		m.notify(ctx, "Uplink switched off", reason+" "+m.after())
	}
	m.o.Log.Warn("uplink license problem; using direct mode", "reason", reason)
}

// notify raises the notice that the uplink went off by itself; an empty
// title withdraws it.
// after says what Varde does once the uplink is off.
func (m *Manager) after() string {
	if m.o.After != "" {
		return m.o.After
	}
	return "Varde asks the public sources itself again."
}

func (m *Manager) notify(ctx context.Context, title, detail string) {
	if m.o.Notices == nil {
		return
	}
	var current []store.Notice
	if title != "" {
		current = []store.Notice{{Key: store.NoticeUplink, Subject: "uplink", Title: title, Detail: detail}}
	}
	if err := m.o.Notices.SyncNotices(context.WithoutCancel(ctx), store.NoticeUplink, current, m.o.Now()); err != nil {
		m.o.Log.Error("uplink notice could not be stored", "err", err)
	}
}

// leave returns to direct mode. It does not depend on the request that
// caused it: a cancelled request must not leave feed data behind.
func (m *Manager) leave(ctx context.Context) {
	if err := m.o.Feed.Leave(context.WithoutCancel(ctx)); err != nil {
		m.o.Log.Error("leaving the uplink feed failed", "err", err)
	}
}

// persistOff records that the uplink went off by itself.
func (m *Manager) persistOff(ctx context.Context) {
	if err := m.o.Store.PutSettings(context.WithoutCancel(ctx), map[string]string{keyEnabled: "false"}, "system", m.o.Now()); err != nil {
		m.o.Log.Error("storing the uplink switch failed", "err", err)
	}
}

// Status returns the current state.
func (m *Manager) Status() Status { return m.snap.Load().status }

// Active reports whether advisories come from the uplink feed now. A
// license that expired since the last call switches back to direct mode.
func (m *Manager) Active() bool {
	s := m.snap.Load()
	if s.status.State != Active {
		return false
	}
	if m.o.Now().Before(s.status.ExpiresAt) {
		return true
	}
	if m.mu.TryLock() {
		changed := m.expireLocked(context.Background())
		m.mu.Unlock()
		if changed && m.o.OnChange != nil {
			m.o.OnChange()
		}
	}
	return false
}

// expireLocked leaves the feed when the active license has expired.
func (m *Manager) expireLocked(ctx context.Context) bool {
	s := m.snap.Load()
	if s.status.State != Active || m.o.Now().Before(s.status.ExpiresAt) {
		return false
	}
	st := m.base(Expired)
	st.LicenseID, st.ExpiresAt = s.status.LicenseID, s.status.ExpiresAt
	st.Reason = fmt.Sprintf("The license expired on %s.", s.status.ExpiresAt.Format("2006-01-02"))
	m.set(st, "")
	m.leave(ctx)
	m.persistOff(ctx)
	m.notify(ctx, "Uplink license expired", st.Reason+" "+m.after()+" Renew the license under Settings › Uplink.")
	m.o.Log.Warn("uplink license expired; using direct mode", "license", st.LicenseID)
	return true
}

// Authorization is the header value for feed mirrors: the license while
// the uplink is active or being switched on, empty otherwise.
func (m *Manager) Authorization() string {
	s := m.snap.Load()
	if s.status.State == Active && !m.o.Now().Before(s.status.ExpiresAt) {
		return ""
	}
	return s.auth
}

// InUse reports whether the feed may be fetched now: while the uplink is
// active or being switched on. It turns false before the feed is left.
func (m *Manager) InUse() bool { return m.Authorization() != "" }

// Enable switches the uplink on with the license in input (as pasted:
// JSON or base64), or with the stored license when input is empty. The
// license is verified offline, then one feed update must succeed with it;
// only then is anything stored. On failure the previous state stays.
func (m *Manager) Enable(ctx context.Context, input []byte, by string) error {
	if m.o.Locked {
		return ErrLocked
	}
	if m.o.Feed == nil {
		return ErrUnavailable
	}
	m.mu.Lock()
	changed, err := m.enableLocked(ctx, input, by)
	m.mu.Unlock()
	if changed && m.o.OnChange != nil {
		m.o.OnChange()
	}
	return err
}

func (m *Manager) enableLocked(ctx context.Context, input []byte, by string) (bool, error) {
	doc := m.doc
	if len(trimmed(input)) > 0 {
		_, canon, err := feed.ParseLicense(input)
		if err != nil {
			return false, err
		}
		doc = canon
	}
	if len(doc) == 0 {
		return false, ErrNoLicense
	}
	now := m.o.Now()
	l, err := m.o.Feed.VerifyLicense(doc, now)
	if err != nil {
		return false, err
	}
	prev := m.snap.Load()
	wasActive := prev.status.State == Active && now.Before(prev.status.ExpiresAt)
	// The license goes out with this update only; the state changes after it.
	m.snap.Store(&snapshot{status: prev.status, auth: authorization(doc)})
	undo := func() {
		m.snap.Store(prev)
		if !wasActive {
			m.leave(ctx)
		}
	}
	if err := m.o.Feed.Update(ctx); err != nil {
		undo()
		return false, fmt.Errorf("the feed did not verify with this license: %w", err)
	}
	sealed, err := m.o.Box.Seal(boxID, doc)
	if err == nil {
		err = m.o.Store.PutSettings(ctx, map[string]string{keyEnabled: "true", keyLicense: base64.StdEncoding.EncodeToString(sealed)}, by, now)
	}
	if err != nil {
		undo()
		return false, fmt.Errorf("store the license: %w", err)
	}
	m.doc = doc
	m.set(withLicense(m.base(Active), l), authorization(doc))
	m.notify(ctx, "", "")
	m.o.Log.Info("uplink switched on", "license", l.ID, "expires", l.ExpiresAt, "by", by)
	return true, nil
}

func trimmed(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

// Disable switches the uplink off and returns to direct mode. The license
// stays stored, so Enable without input switches it on again.
func (m *Manager) Disable(ctx context.Context, by string) error {
	return m.off(ctx, by, false)
}

// Remove switches the uplink off and deletes the stored license.
func (m *Manager) Remove(ctx context.Context, by string) error {
	return m.off(ctx, by, true)
}

func (m *Manager) off(ctx context.Context, by string, forget bool) error {
	if m.o.Locked {
		return ErrLocked
	}
	if m.o.Feed == nil {
		return ErrUnavailable
	}
	m.mu.Lock()
	prev := m.snap.Load()
	values := map[string]string{keyEnabled: "false"}
	if forget {
		values[keyLicense] = ""
	}
	if err := m.o.Store.PutSettings(ctx, values, by, m.o.Now()); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("store the uplink switch: %w", err)
	}
	wasActive := prev.status.State == Active
	st := m.base(Off)
	switch {
	case forget:
		m.doc = nil
	case prev.status.State == Expired:
		// Still expired; switching off does not change that.
		st = prev.status
	default:
		st.LicenseID, st.ExpiresAt = prev.status.LicenseID, prev.status.ExpiresAt
	}
	// Out of use first, then leave: a refresh that already chose the feed
	// finds it closed instead of installing it again.
	m.set(st, "")
	if wasActive {
		m.leave(ctx)
	}
	// The user acted; what went off by itself before is no longer news.
	m.notify(ctx, "", "")
	m.mu.Unlock()
	if wasActive {
		m.o.Log.Info("uplink switched off", "by", by)
		if m.o.OnChange != nil {
			m.o.OnChange()
		}
	}
	return nil
}
