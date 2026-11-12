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

// HostPackages is the full package list of one host.
type HostPackages struct {
	HostID     string
	Distro, OS string
	Packages   []inventory.Package
	Read       time.Time
	// Kernel is the running kernel; Reboot says why the host needs a
	// restart for its updates to take effect, empty when it does not.
	Kernel, Reboot string
	// Listen are the sockets the host listens on (ADR 0034).
	Listen []inventory.Listener
}

// SetHostPackages replaces the package list of a host. The host must exist.
func (s *Store) SetHostPackages(ctx context.Context, p HostPackages) error {
	return setHostPackages(ctx, s.db, p)
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func setHostPackages(ctx context.Context, db execer, p HostPackages) error {
	pkgs := p.Packages
	if len(pkgs) > maxImagePackages {
		pkgs = pkgs[:maxImagePackages]
	}
	if pkgs == nil {
		pkgs = []inventory.Package{}
	}
	raw, err := json.Marshal(pkgs)
	if err != nil {
		return fmt.Errorf("encode host packages: %w", err)
	}
	listen := p.Listen
	if listen == nil {
		listen = []inventory.Listener{}
	}
	rawListen, err := json.Marshal(listen)
	if err != nil {
		return fmt.Errorf("encode listeners: %w", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO host_packages (host_id, distro, os, packages, read_at, kernel, reboot, listen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET distro = excluded.distro, os = excluded.os, packages = excluded.packages, read_at = excluded.read_at,
		kernel = excluded.kernel, reboot = excluded.reboot, listen = excluded.listen`,
		p.HostID, truncate(p.Distro, 64), truncate(p.OS, 128), string(raw), millis(p.Read), truncate(p.Kernel, 64), truncate(p.Reboot, 512), string(rawListen))
	if err != nil {
		return fmt.Errorf("record host packages: %w", err)
	}
	return nil
}

// HostPackageList returns the package list of a host; ok is false when none
// was read.
func (s *Store) HostPackageList(ctx context.Context, hostID string) (HostPackages, bool, error) {
	p := HostPackages{HostID: hostID}
	var raw string
	var read int64
	var listen string
	err := s.db.QueryRowContext(ctx, `SELECT distro, os, packages, read_at, kernel, reboot, listen FROM host_packages WHERE host_id = ?`, hostID).Scan(&p.Distro, &p.OS, &raw, &read, &p.Kernel, &p.Reboot, &listen)
	if errors.Is(err, sql.ErrNoRows) {
		return p, false, nil
	}
	if err != nil {
		return p, false, fmt.Errorf("query host packages: %w", err)
	}
	if err := json.Unmarshal([]byte(raw), &p.Packages); err != nil {
		return p, false, fmt.Errorf("decode host packages: %w", err)
	}
	if err := json.Unmarshal([]byte(listen), &p.Listen); err != nil {
		return p, false, fmt.Errorf("decode listeners: %w", err)
	}
	p.Read = fromMillis(read)
	return p, true, nil
}

// HostPackageCounts returns how many packages each host has, for lists.
func (s *Store) HostPackageCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, json_array_length(packages) FROM host_packages`)
	if err != nil {
		return nil, fmt.Errorf("query host package counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("scan host package count: %w", err)
		}
		out[id] = n
	}
	return out, rows.Err()
}

// HostReboots returns, per host, why it needs a restart; hosts that do not
// are left out.
func (s *Store) HostReboots(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, reboot FROM host_packages WHERE reboot != ''`)
	if err != nil {
		return nil, fmt.Errorf("query host reboots: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var id, why string
		if err := rows.Scan(&id, &why); err != nil {
			return nil, fmt.Errorf("scan host reboot: %w", err)
		}
		out[id] = why
	}
	return out, rows.Err()
}

// HostSurface is what the attack path analysis needs of a host's package
// list: the source packages installed and the sockets it listens on.
type HostSurface struct {
	Sources map[string]bool
	Listen  []inventory.Listener
	Kernel  string
}

// HostSurfaces returns the surface of every host with a package list.
func (s *Store) HostSurfaces(ctx context.Context) (map[string]HostSurface, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, packages, listen, kernel FROM host_packages`)
	if err != nil {
		return nil, fmt.Errorf("query host surfaces: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]HostSurface{}
	for rows.Next() {
		var id, raw, listen, kernel string
		if err := rows.Scan(&id, &raw, &listen, &kernel); err != nil {
			return nil, fmt.Errorf("scan host surface: %w", err)
		}
		var pkgs []inventory.Package
		if err := json.Unmarshal([]byte(raw), &pkgs); err != nil {
			return nil, fmt.Errorf("decode host packages of %s: %w", id, err)
		}
		hs := HostSurface{Sources: make(map[string]bool, len(pkgs)), Kernel: kernel}
		for _, p := range pkgs {
			hs.Sources[p.Name] = true
			if p.Source != "" {
				hs.Sources[p.Source] = true
			}
		}
		if err := json.Unmarshal([]byte(listen), &hs.Listen); err != nil {
			return nil, fmt.Errorf("decode listeners of %s: %w", id, err)
		}
		out[id] = hs
	}
	return out, rows.Err()
}
