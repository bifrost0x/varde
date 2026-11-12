// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/inventory"
)

// StoredDevice is a scanned device with the times it was seen.
type StoredDevice struct {
	discovery.Device
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Missed is set when the device did not answer the last scan; it is
	// kept until it misses a second one.
	Missed bool `json:"missed,omitempty"`
}

// missedScans is how many scans in a row a device may miss before it is
// removed: one lost answer must not make a host disappear.
const missedScans = 2

// RecordDevices stores the result of a scan of the addresses for which
// scanned reports true. A device that no longer answers is marked and
// removed when it misses a second scan in a row. Devices outside the
// scanned ranges are kept. First-seen times survive for devices still
// present.
func (s *Store) RecordDevices(ctx context.Context, devs []discovery.Device, scanned func(addr string) bool, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		present := make(map[string]bool, len(devs))
		for _, d := range devs {
			present[d.Address] = true
		}
		rows, err := tx.QueryContext(ctx, `SELECT address FROM devices`)
		if err != nil {
			return fmt.Errorf("query devices: %w", err)
		}
		var gone []string
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan device address: %w", err)
			}
			if !present[a] && scanned != nil && scanned(a) {
				gone = append(gone, a)
			}
		}
		_ = rows.Close()
		for _, a := range gone {
			if _, err := tx.ExecContext(ctx, `UPDATE devices SET missed = missed + 1 WHERE address = ?`, a); err != nil {
				return fmt.Errorf("mark device %s: %w", a, err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE address = ? AND missed >= ?`, a, missedScans); err != nil {
				return fmt.Errorf("remove device %s: %w", a, err)
			}
		}
		for _, d := range devs {
			if d.Services == nil {
				d.Services = []discovery.Service{}
			}
			svcs, err := json.Marshal(d.Services)
			if err != nil {
				return fmt.Errorf("encode services: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO devices (address, hostname, kind, label, services_json, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (address) DO UPDATE SET hostname = excluded.hostname, kind = excluded.kind,
					label = excluded.label, services_json = excluded.services_json, last_seen = excluded.last_seen, missed = 0`,
				d.Address, truncate(d.Hostname, 253), d.Kind, truncate(d.Label, 200), string(svcs), millis(now), millis(now)); err != nil {
				return fmt.Errorf("record device %s: %w", d.Address, err)
			}
		}
		return nil
	})
}

// Devices returns every recorded device.
func (s *Store) Devices(ctx context.Context) ([]StoredDevice, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT address, hostname, kind, label, services_json, first_seen, last_seen, missed FROM devices`)
	if err != nil {
		return nil, fmt.Errorf("query devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []StoredDevice
	for rows.Next() {
		var d StoredDevice
		var svcs string
		var first, last, missed int64
		if err := rows.Scan(&d.Address, &d.Hostname, &d.Kind, &d.Label, &svcs, &first, &last, &missed); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		if err := json.Unmarshal([]byte(svcs), &d.Services); err != nil {
			return nil, fmt.Errorf("decode services of %s: %w", d.Address, err)
		}
		d.FirstSeen, d.LastSeen = fromMillis(first), fromMillis(last)
		d.Missed = missed > 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// ClearDevices forgets every scanned device.
func (s *Store) ClearDevices(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM devices`); err != nil {
		return fmt.Errorf("clear devices: %w", err)
	}
	return nil
}

// Integration is a connection to a platform through its official interface.
type Integration struct {
	ID, Kind, Name, Address string
	Config                  json.RawMessage
	// Secret is the encrypted credential; nil when the integration needs
	// none (an SSH integration uses Varde's own key).
	Secret      []byte
	Enabled     bool
	CreatedBy   string
	CreatedAt   time.Time
	LastSuccess *time.Time
	LastError   string
	// Status is the integration's last report, for display.
	Status json.RawMessage
}

const integrationColumns = `id, kind, name, address, config_json, secret, enabled, created_by, created_at, last_success, last_error, status_json`

// CreateIntegration stores a new integration; ErrConflict when the same
// kind already points at the address.
func (s *Store) CreateIntegration(ctx context.Context, in Integration) error {
	cfg := in.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage("{}")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO integrations (id, kind, name, address, config_json, secret, enabled, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ID, in.Kind, truncate(in.Name, 128), in.Address, string(cfg), in.Secret, boolInt(in.Enabled), truncate(in.CreatedBy, 128), millis(in.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("create integration: %w", err)
	}
	return nil
}

// Integrations returns all integrations ordered by kind and name.
func (s *Store) Integrations(ctx context.Context) ([]Integration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+integrationColumns+` FROM integrations ORDER BY kind, name, id`)
	if err != nil {
		return nil, fmt.Errorf("query integrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Integration
	for rows.Next() {
		in, err := scanIntegration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// GetIntegration returns one integration or ErrNotFound.
func (s *Store) GetIntegration(ctx context.Context, id string) (Integration, error) {
	in, err := scanIntegration(s.db.QueryRowContext(ctx, `SELECT `+integrationColumns+` FROM integrations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Integration{}, ErrNotFound
	}
	return in, err
}

func scanIntegration(sc scanner) (Integration, error) {
	var in Integration
	var cfg, status string
	var enabled int
	var created int64
	var success sql.NullInt64
	if err := sc.Scan(&in.ID, &in.Kind, &in.Name, &in.Address, &cfg, &in.Secret, &enabled, &in.CreatedBy, &created, &success, &in.LastError, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return in, err
		}
		return in, fmt.Errorf("scan integration: %w", err)
	}
	in.Config, in.Status, in.Enabled, in.CreatedAt = json.RawMessage(cfg), json.RawMessage(status), enabled == 1, fromMillis(created)
	if success.Valid {
		t := fromMillis(success.Int64)
		in.LastSuccess = &t
	}
	return in, nil
}

// SetIntegrationEnabled switches an integration on or off.
func (s *Store) SetIntegrationEnabled(ctx context.Context, id string, enabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE integrations SET enabled = ? WHERE id = ?`, boolInt(enabled), id)
	if err != nil {
		return fmt.Errorf("update integration: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordIntegrationRun stores the outcome of one collection run. A failed
// run keeps the last status, so the page still shows what was seen last.
func (s *Store) RecordIntegrationRun(ctx context.Context, id string, runErr error, status any, now time.Time) error {
	if runErr != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE integrations SET last_error = ? WHERE id = ?`, truncate(runErr.Error(), 1024), id)
		if err != nil {
			return fmt.Errorf("record integration error: %w", err)
		}
		return nil
	}
	b, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("encode integration status: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE integrations SET last_error = '', last_success = ?, status_json = ? WHERE id = ?`,
		millis(now), string(b), id); err != nil {
		return fmt.Errorf("record integration run: %w", err)
	}
	return nil
}

// DeleteIntegration removes an integration and every host it reported,
// with their workloads and findings.
func (s *Store) DeleteIntegration(ctx context.Context, id string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM integrations WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("delete integration: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE workload_id IN
			(SELECT w.id FROM workloads w JOIN hosts h ON h.id = w.host_id WHERE h.integration_id = ?)`, id); err != nil {
			return fmt.Errorf("delete integration findings: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE integration_id = ?`, id); err != nil {
			return fmt.Errorf("delete integration hosts: %w", err)
		}
		return nil
	})
}

// SyncIntegrationHosts makes the hosts of an integration equal to hosts:
// new and known ones are upserted, the ones the platform no longer reports
// are removed. Every host must carry the integration's ID.
func (s *Store) SyncIntegrationHosts(ctx context.Context, integrationID string, hosts []inventory.Host) error {
	keep := map[string]bool{}
	for _, h := range hosts {
		if h.IntegrationID != integrationID {
			return fmt.Errorf("host %s does not belong to integration %s", h.ID, integrationID)
		}
		if err := s.UpsertHost(ctx, h); err != nil {
			return err
		}
		keep[h.ID] = true
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM hosts WHERE integration_id = ?`, integrationID)
	if err != nil {
		return fmt.Errorf("query integration hosts: %w", err)
	}
	var stale []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan host id: %w", err)
		}
		if !keep[id] {
			stale = append(stale, id)
		}
	}
	_ = rows.Close()
	for _, id := range stale {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id); err != nil {
			return fmt.Errorf("remove host %s: %w", id, err)
		}
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
