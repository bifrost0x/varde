// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

// UpsertHost creates the host or updates its descriptive fields and last
// contact. CreatedAt is kept from the first insert.
func (s *Store) UpsertHost(ctx context.Context, h inventory.Host) error {
	addrs, err := json.Marshal(nonNil(h.Addresses))
	if err != nil {
		return fmt.Errorf("encode host addresses: %w", err)
	}
	macs, err := json.Marshal(nonNil(h.MACs))
	if err != nil {
		return fmt.Errorf("encode host MACs: %w", err)
	}
	created := h.CreatedAt
	if created.IsZero() {
		created = h.LastContact
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO hosts (id, name, kind, source, agent_version, os, arch, addresses_json, last_contact, created_at,
			integration_id, detail, macs_json, machine_id, parent_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = excluded.name, kind = excluded.kind, source = excluded.source,
			agent_version = excluded.agent_version, os = excluded.os, arch = excluded.arch,
			addresses_json = excluded.addresses_json, last_contact = excluded.last_contact,
			integration_id = excluded.integration_id, detail = excluded.detail,
			macs_json = excluded.macs_json, machine_id = excluded.machine_id, parent_id = excluded.parent_id`,
		h.ID, h.Name, string(h.Kind), string(h.Source), h.AgentVersion, h.OS, h.Arch, string(addrs),
		millis(h.LastContact), millis(created), h.IntegrationID, h.Detail, string(macs), h.MachineID, h.ParentID)
	if err != nil {
		return fmt.Errorf("upsert host %s: %w", h.ID, err)
	}
	return nil
}

const hostColumns = `id, name, kind, source, agent_version, os, arch, addresses_json, last_contact, created_at,
	state, agent_cert_expires, report_interval_ms, integration_id, detail, macs_json, machine_id, parent_id`

// Hosts returns all hosts ordered by name.
func (s *Store) Hosts(ctx context.Context) ([]inventory.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostColumns+` FROM hosts ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []inventory.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate hosts: %w", err)
	}
	return out, nil
}

// Host returns one host or ErrNotFound.
func (s *Store) Host(ctx context.Context, id string) (inventory.Host, error) {
	h, err := scanHost(s.db.QueryRowContext(ctx, `SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return inventory.Host{}, ErrNotFound
	}
	return h, err
}

type scanner interface{ Scan(dest ...any) error }

func scanHost(sc scanner) (inventory.Host, error) {
	var (
		h                 inventory.Host
		kind, source      string
		addrs, macs       string
		lastContact, crAt int64
		state             string
		certExp           sql.NullInt64
		interval          int64
	)
	if err := sc.Scan(&h.ID, &h.Name, &kind, &source, &h.AgentVersion, &h.OS, &h.Arch, &addrs, &lastContact, &crAt,
		&state, &certExp, &interval, &h.IntegrationID, &h.Detail, &macs, &h.MachineID, &h.ParentID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return h, err
		}
		return h, fmt.Errorf("scan host: %w", err)
	}
	h.Kind, h.Source = inventory.HostKind(kind), inventory.HostSource(source)
	h.LastContact, h.CreatedAt = fromMillis(lastContact), fromMillis(crAt)
	h.State, h.ReportInterval = inventory.HostState(state), time.Duration(interval)*time.Millisecond
	if certExp.Valid {
		t := fromMillis(certExp.Int64)
		h.CertExpires = &t
	}
	if err := json.Unmarshal([]byte(addrs), &h.Addresses); err != nil {
		return h, fmt.Errorf("decode host %s addresses: %w", h.ID, err)
	}
	if err := json.Unmarshal([]byte(macs), &h.MACs); err != nil {
		return h, fmt.Errorf("decode host %s MACs: %w", h.ID, err)
	}
	return h, nil
}

// ApplySnapshot makes the stored workloads of (hostID, kind) match ws in one
// transaction: new workloads are inserted, known ones updated, missing ones
// marked removed, and reappearing ones restored.
func (s *Store) ApplySnapshot(ctx context.Context, hostID string, kind inventory.Kind, ws []inventory.Workload, now time.Time) (inventory.Changes, error) {
	var res inventory.Changes
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var err error
		res, err = applySnapshotTx(ctx, tx, hostID, kind, ws, now)
		return err
	})
	return res, err
}

func applySnapshotTx(ctx context.Context, tx *sql.Tx, hostID string, kind inventory.Kind, ws []inventory.Workload, now time.Time) (inventory.Changes, error) {
	var res inventory.Changes
	err := func() error {
		known := map[string]storedWorkload{}
		byRuntime := map[string]string{}
		rows, err := tx.QueryContext(ctx,
			`SELECT id, runtime_id, name, state, data_json, COALESCE(removed_at, 0) FROM workloads WHERE host_id = ? AND kind = ?`,
			hostID, string(kind))
		if err != nil {
			return fmt.Errorf("query workloads: %w", err)
		}
		for rows.Next() {
			var id, runtimeID, name, state, data string
			var removedAt int64
			if err := rows.Scan(&id, &runtimeID, &name, &state, &data, &removedAt); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan workload: %w", err)
			}
			known[id] = storedWorkload{name: name, runtimeID: runtimeID, fingerprint: name + "\x00" + state + "\x00" + data, removedAt: removedAt}
			byRuntime[runtimeID] = id
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close workload rows: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate workloads: %w", err)
		}

		// A workload keeps the ID it is stored under. A new one gets the ID
		// derived from its runtime ID or, for a container, the ID of the
		// container of the same name it replaces.
		ids := make([]string, len(ws))
		claimed := map[string]bool{}
		for i, w := range ws {
			if w.Kind != kind {
				return fmt.Errorf("workload %s has kind %s, snapshot is for %s", w.RuntimeID, w.Kind, kind)
			}
			if id, ok := byRuntime[w.RuntimeID]; ok {
				ids[i], claimed[id] = id, true
			}
		}
		if kind == inventory.KindContainer {
			for i, w := range ws {
				if ids[i] == "" {
					if id := replacedContainer(w.Name, known, claimed); id != "" {
						ids[i], claimed[id] = id, true
					}
				}
			}
		}

		seen := make(map[string]bool, len(ws))
		for i := range ws {
			w := ws[i]
			w.HostID = hostID
			w.ID = ids[i]
			if w.ID == "" {
				w.ID = inventory.WorkloadID(hostID, kind, w.RuntimeID)
			}
			if seen[w.ID] {
				return fmt.Errorf("duplicate workload %s in snapshot", w.RuntimeID)
			}
			seen[w.ID] = true
			cols, err := workloadColumns(w)
			if err != nil {
				return err
			}
			prev, ok := known[w.ID]
			if ok && prev.runtimeID != w.RuntimeID {
				// Recreated: the same workload now runs as a new container.
				if _, err := tx.ExecContext(ctx, `UPDATE workloads SET runtime_id = ? WHERE id = ?`, w.RuntimeID, w.ID); err != nil {
					return fmt.Errorf("move workload %s to container %s: %w", w.ID, w.RuntimeID, err)
				}
			}
			switch {
			case !ok:
				res.Added++
				if err := insertWorkload(ctx, tx, w, cols, now); err != nil {
					return err
				}
			default:
				if prev.removedAt != 0 {
					res.Added++
				} else if prev.fingerprint != w.Name+"\x00"+w.State+"\x00"+cols.data {
					res.Changed++
				}
				if _, err := tx.ExecContext(ctx, `
					UPDATE workloads SET name = ?, state = ?, image_ref = ?, image_digest = ?, package_name = ?,
						package_version = ?, unit_name = ?, data_json = ?, last_seen = ?, removed_at = NULL
					WHERE id = ?`,
					w.Name, w.State, cols.imageRef, cols.imageDigest, cols.packageName, cols.packageVersion,
					cols.unitName, cols.data, millis(now), w.ID); err != nil {
					return fmt.Errorf("update workload %s: %w", w.ID, err)
				}
			}
		}

		for id, prev := range known {
			if seen[id] || prev.removedAt != 0 {
				continue
			}
			res.Removed++
			if _, err := tx.ExecContext(ctx, `UPDATE workloads SET removed_at = ? WHERE id = ?`, millis(now), id); err != nil {
				return fmt.Errorf("mark workload %s removed: %w", id, err)
			}
		}
		return nil
	}()
	return res, err
}

// storedWorkload is what a snapshot compares a reported workload with.
type storedWorkload struct {
	name, runtimeID, fingerprint string
	removedAt                    int64 // 0 while present
}

// replacedContainer returns the ID of the stored container named name that
// a new container replaces, or "": Docker keeps names unique on a host, so
// a new container under a known name is that container recreated (docker
// compose up -d after a pull). A present one is preferred, else the one
// removed last; one already matched is never taken twice.
func replacedContainer(name string, known map[string]storedWorkload, claimed map[string]bool) string {
	if name == "" {
		return ""
	}
	best := ""
	for id, w := range known {
		if claimed[id] || w.name != name {
			continue
		}
		if best == "" || better(w, known[best]) || (!better(known[best], w) && id < best) {
			best = id
		}
	}
	return best
}

// better reports whether a is a likelier predecessor than b: present beats
// removed, a later removal an earlier one.
func better(a, b storedWorkload) bool {
	if (a.removedAt == 0) != (b.removedAt == 0) {
		return a.removedAt == 0
	}
	return a.removedAt > b.removedAt
}

// AddManual stores a manual workload. Its ID is derived from host and
// runtime ID; adding an existing ID fails.
func (s *Store) AddManual(ctx context.Context, w inventory.Workload, now time.Time) (inventory.Workload, error) {
	if w.Kind != inventory.KindManual || w.Manual == nil {
		return w, errors.New("not a manual workload")
	}
	w.ID = inventory.WorkloadID(w.HostID, w.Kind, w.RuntimeID)
	cols, err := workloadColumns(w)
	if err != nil {
		return w, err
	}
	if err := s.inTx(ctx, func(tx *sql.Tx) error {
		return insertWorkload(ctx, tx, w, cols, now)
	}); err != nil {
		return w, err
	}
	return s.Workload(ctx, w.ID)
}

// RemoveWorkload marks a workload of the given kind removed. It returns
// ErrNotFound if no active workload of that kind has the ID.
func (s *Store) RemoveWorkload(ctx context.Context, id string, kind inventory.Kind, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE workloads SET removed_at = ? WHERE id = ? AND kind = ? AND removed_at IS NULL`,
		millis(now), id, string(kind))
	if err != nil {
		return fmt.Errorf("remove workload %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove workload %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeRemoved deletes workloads removed before cutoff.
func (s *Store) PurgeRemoved(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM workloads WHERE removed_at IS NOT NULL AND removed_at < ?`, millis(cutoff))
	if err != nil {
		return 0, fmt.Errorf("purge removed workloads: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("purge removed workloads: %w", err)
	}
	return n, nil
}

// WorkloadFilter narrows Workloads.
type WorkloadFilter struct {
	HostID         string
	Kind           inventory.Kind
	IncludeRemoved bool
}

const workloadSelect = `SELECT id, host_id, kind, runtime_id, name, state, data_json, first_seen, last_seen, removed_at FROM workloads`

// Workloads returns workloads matching f, ordered by host and name.
func (s *Store) Workloads(ctx context.Context, f WorkloadFilter) ([]inventory.Workload, error) {
	q := workloadSelect + ` WHERE 1 = 1`
	var args []any
	if f.HostID != "" {
		q += ` AND host_id = ?`
		args = append(args, f.HostID)
	}
	if f.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, string(f.Kind))
	}
	if !f.IncludeRemoved {
		q += ` AND removed_at IS NULL`
	}
	q += ` ORDER BY host_id, name, id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query workloads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []inventory.Workload{}
	for rows.Next() {
		w, err := scanWorkload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate workloads: %w", err)
	}
	return out, nil
}

// Workload returns one workload (including removed ones) or ErrNotFound.
func (s *Store) Workload(ctx context.Context, id string) (inventory.Workload, error) {
	w, err := scanWorkload(s.db.QueryRowContext(ctx, workloadSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return inventory.Workload{}, ErrNotFound
	}
	return w, err
}

func scanWorkload(sc scanner) (inventory.Workload, error) {
	var (
		w           inventory.Workload
		kind, data  string
		first, last int64
		removed     sql.NullInt64
	)
	if err := sc.Scan(&w.ID, &w.HostID, &kind, &w.RuntimeID, &w.Name, &w.State, &data, &first, &last, &removed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return w, err
		}
		return w, fmt.Errorf("scan workload: %w", err)
	}
	w.Kind = inventory.Kind(kind)
	w.FirstSeen, w.LastSeen = fromMillis(first), fromMillis(last)
	if removed.Valid {
		t := fromMillis(removed.Int64)
		w.RemovedAt = &t
	}
	var target any
	switch w.Kind {
	case inventory.KindContainer:
		w.Container = &inventory.Container{}
		target = w.Container
	case inventory.KindPackage:
		w.Package = &inventory.Package{}
		target = w.Package
	case inventory.KindService:
		w.Service = &inventory.Service{}
		target = w.Service
	case inventory.KindManual:
		w.Manual = &inventory.Manual{}
		target = w.Manual
	case inventory.KindEndpoint:
		w.Endpoint = &inventory.Endpoint{}
		target = w.Endpoint
	default:
		return w, fmt.Errorf("workload %s: unknown kind %q", w.ID, kind)
	}
	if err := json.Unmarshal([]byte(data), target); err != nil {
		return w, fmt.Errorf("decode workload %s: %w", w.ID, err)
	}
	return w, nil
}

type columns struct {
	imageRef, imageDigest, packageName, packageVersion, unitName, data string
}

func workloadColumns(w inventory.Workload) (columns, error) {
	var c columns
	var payload any
	switch w.Kind {
	case inventory.KindContainer:
		if w.Container == nil {
			return c, fmt.Errorf("container workload %s without container data", w.RuntimeID)
		}
		c.imageRef, c.imageDigest = w.Container.ImageRef, w.Container.ImageID
		payload = w.Container
	case inventory.KindPackage:
		if w.Package == nil {
			return c, fmt.Errorf("package workload %s without package data", w.RuntimeID)
		}
		c.packageName, c.packageVersion = w.Package.Name, w.Package.Version
		payload = w.Package
	case inventory.KindService:
		if w.Service == nil {
			return c, fmt.Errorf("service workload %s without service data", w.RuntimeID)
		}
		c.unitName = w.Service.Unit
		payload = w.Service
	case inventory.KindManual:
		if w.Manual == nil {
			return c, fmt.Errorf("manual workload %s without manual data", w.RuntimeID)
		}
		payload = w.Manual
	case inventory.KindEndpoint:
		if w.Endpoint == nil {
			return c, fmt.Errorf("endpoint workload %s without endpoint data", w.RuntimeID)
		}
		payload = w.Endpoint
	default:
		return c, fmt.Errorf("workload %s: unknown kind %q", w.RuntimeID, w.Kind)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return c, fmt.Errorf("encode workload %s: %w", w.RuntimeID, err)
	}
	c.data = string(b)
	return c, nil
}

func insertWorkload(ctx context.Context, tx *sql.Tx, w inventory.Workload, c columns, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO workloads (id, host_id, kind, runtime_id, name, state, image_ref, image_digest,
			package_name, package_version, unit_name, data_json, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w.ID, w.HostID, string(w.Kind), w.RuntimeID, w.Name, w.State, c.imageRef, c.imageDigest,
		c.packageName, c.packageVersion, c.unitName, c.data, millis(now), millis(now))
	if err != nil {
		return fmt.Errorf("insert workload %s: %w", w.RuntimeID, err)
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
