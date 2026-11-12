// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// SnapshotStore persists hosts and snapshots.
type SnapshotStore interface {
	UpsertHost(ctx context.Context, h Host) error
	ApplySnapshot(ctx context.Context, hostID string, kind Kind, ws []Workload, now time.Time) (Changes, error)
	PurgeRemoved(ctx context.Context, cutoff time.Time) (int64, error)
}

// ErrNotSynced is reported by Ready before the first successful sync.
var ErrNotSynced = errors.New("inventory not synced yet")

// SyncerConfig configures a Syncer.
type SyncerConfig struct {
	HostID    string
	HostKind  HostKind
	Source    HostSource
	Collector Collector
	Store     SnapshotStore
	Log       *slog.Logger
	// IntegrationID and Addresses are recorded on the host for hosts read
	// through an integration.
	IntegrationID string
	Addresses     []string

	// Resync is the full resync period (default 6 h).
	Resync time.Duration
	// Debounce coalesces event bursts (default 5 s).
	Debounce time.Duration
	// Retention keeps removed workloads this long (default 90 days).
	Retention time.Duration
	// OnChange, if set, is called after the first successful sync and after
	// every later sync that changed something. It runs on the sync
	// goroutine.
	OnChange func(Changes)
}

// Syncer keeps the stored inventory of one host in sync with a collector:
// at startup, after debounced change events, and periodically.
type Syncer struct {
	cfg     SyncerConfig
	now     func() time.Time
	trigger chan struct{}

	minRetry, maxRetry time.Duration

	mu       sync.Mutex
	lastSync time.Time
	lastErr  error
}

// NewSyncer returns a Syncer with defaults applied.
func NewSyncer(cfg SyncerConfig) *Syncer {
	if cfg.Resync <= 0 {
		cfg.Resync = 6 * time.Hour
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = 5 * time.Second
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 90 * 24 * time.Hour
	}
	return &Syncer{
		cfg:      cfg,
		now:      time.Now,
		trigger:  make(chan struct{}, 1),
		minRetry: time.Second,
		maxRetry: time.Minute,
	}
}

// Trigger requests a sync as soon as possible without waiting.
func (s *Syncer) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Ready returns nil once the most recent sync attempt succeeded.
func (s *Syncer) Ready() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr != nil {
		return s.lastErr
	}
	if s.lastSync.IsZero() {
		return ErrNotSynced
	}
	return nil
}

// LastSync returns the time of the last successful sync.
func (s *Syncer) LastSync() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSync
}

// Run syncs until ctx is cancelled. Failures are retried with exponential
// backoff and never terminate the loop.
func (s *Syncer) Run(ctx context.Context) {
	events := s.cfg.Collector.Watch(ctx)
	resync := time.NewTicker(s.cfg.Resync)
	defer resync.Stop()

	// One timer schedules the next sync: immediately, after a debounce
	// window, or after a retry delay.
	next := time.NewTimer(0)
	defer next.Stop()
	pending := true
	retry := s.minRetry

	schedule := func(d time.Duration) {
		if pending {
			return
		}
		next.Reset(d)
		pending = true
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			s.cfg.Log.Debug("inventory change signalled", "host", s.cfg.HostID, "reason", ev.Reason)
			schedule(s.cfg.Debounce)
		case <-s.trigger:
			if pending {
				next.Stop()
				pending = false
			}
			schedule(0)
		case <-resync.C:
			schedule(0)
			s.purge(ctx)
		case <-next.C:
			pending = false
			if err := s.sync(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				s.cfg.Log.Warn("inventory sync failed", "host", s.cfg.HostID, "err", err, "retry_in", retry)
				schedule(retry)
				retry = min(retry*2, s.maxRetry)
				continue
			}
			retry = s.minRetry
		}
	}
}

func (s *Syncer) sync(ctx context.Context) error {
	start := s.now()
	snap, err := s.cfg.Collector.List(ctx)
	if err == nil {
		err = s.cfg.Store.UpsertHost(ctx, Host{
			ID: s.cfg.HostID, Name: snap.Host.Name, Kind: s.cfg.HostKind, Source: s.cfg.Source,
			OS: snap.Host.OS, Arch: snap.Host.Arch, LastContact: start,
			IntegrationID: s.cfg.IntegrationID, Addresses: s.cfg.Addresses,
		})
	}
	var changes Changes
	if err == nil {
		changes, err = s.cfg.Store.ApplySnapshot(ctx, s.cfg.HostID, s.cfg.Collector.Kind(), snap.Workloads, start)
	}

	s.mu.Lock()
	s.lastErr = err
	first := s.lastSync.IsZero()
	if err == nil {
		s.lastSync = start
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}

	s.cfg.Log.Info("inventory synced", "host", s.cfg.HostID, "workloads", len(snap.Workloads),
		"added", changes.Added, "changed", changes.Changed, "removed", changes.Removed,
		"duration", s.now().Sub(start).Round(time.Millisecond))
	// The first sync after start always counts as a change: the catalog or
	// the analysis code may differ from the previous run.
	if (changes.Any() || first) && s.cfg.OnChange != nil {
		s.cfg.OnChange(changes)
	}
	return nil
}

func (s *Syncer) purge(ctx context.Context) {
	n, err := s.cfg.Store.PurgeRemoved(ctx, s.now().Add(-s.cfg.Retention))
	if err != nil {
		s.cfg.Log.Warn("purging removed workloads failed", "err", err)
		return
	}
	if n > 0 {
		s.cfg.Log.Info("purged removed workloads", "count", n)
	}
}
