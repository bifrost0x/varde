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

// EnrollmentToken is a one-time token for enrolling an agent. Only the
// SHA-256 of the secret is stored.
type EnrollmentToken struct {
	ID        string
	Name      string
	TokenHash string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateEnrollmentToken stores a new enrollment token.
func (s *Store) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens (id, name, token_hash, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, t.ID, t.Name, t.TokenHash, t.CreatedBy, millis(t.CreatedAt), millis(t.ExpiresAt))
	if err != nil {
		return fmt.Errorf("create enrollment token: %w", err)
	}
	return nil
}

// PendingEnrollmentTokens returns unused, unexpired tokens, newest first.
func (s *Store) PendingEnrollmentTokens(ctx context.Context, now time.Time) ([]EnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_by, created_at, expires_at FROM enrollment_tokens
		WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at DESC`, millis(now))
	if err != nil {
		return nil, fmt.Errorf("query enrollment tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		var cr, ex int64
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedBy, &cr, &ex); err != nil {
			return nil, fmt.Errorf("scan enrollment token: %w", err)
		}
		t.CreatedAt, t.ExpiresAt = fromMillis(cr), fromMillis(ex)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enrollment tokens: %w", err)
	}
	return out, nil
}

// DeleteEnrollmentToken removes an unused token.
func (s *Store) DeleteEnrollmentToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM enrollment_tokens WHERE id = ? AND used_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("delete enrollment token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AgentCert is the pinned certificate of an enrolled agent.
type AgentCert struct {
	Fingerprint string
	Expires     time.Time
}

// EnrollAgent consumes the token and creates the agent's host with its
// pinned certificate in one transaction. It returns ErrConflict when the
// token is unknown, used or expired.
func (s *Store) EnrollAgent(ctx context.Context, tokenHash string, h inventory.Host, cert AgentCert, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at = ?, host_id = ?
			WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`, millis(now), h.ID, tokenHash, millis(now))
		if err != nil {
			return fmt.Errorf("consume enrollment token: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO hosts (id, name, kind, source, agent_version, os, arch, last_contact, created_at,
			state, agent_cert_fingerprint, agent_cert_expires, report_interval_ms)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
			h.ID, h.Name, string(h.Kind), string(inventory.SourceAgent), h.AgentVersion, h.OS, h.Arch, millis(now), millis(now),
			cert.Fingerprint, millis(cert.Expires), h.ReportInterval.Milliseconds())
		if err != nil {
			return fmt.Errorf("create agent host: %w", err)
		}
		return nil
	})
}

// EnrollmentTokenValid reports whether an enrollment token exists, is
// unused and has not expired. EnrollAgent checks again when it consumes it.
func (s *Store) EnrollmentTokenValid(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM enrollment_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		tokenHash, millis(now)).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check enrollment token: %w", err)
	}
	return n == 1, nil
}

// AgentPins returns the state and the accepted certificate fingerprints of an
// agent host: the current one and, during rotation, the pending one.
func (s *Store) AgentPins(ctx context.Context, hostID string) (state inventory.HostState, current, pending string, err error) {
	var cur, pend sql.NullString
	var st string
	err = s.db.QueryRowContext(ctx, `SELECT state, agent_cert_fingerprint, agent_cert_pending FROM hosts
		WHERE id = ? AND source = 'agent'`, hostID).Scan(&st, &cur, &pend)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", ErrNotFound
	}
	if err != nil {
		return "", "", "", fmt.Errorf("query agent pins: %w", err)
	}
	return inventory.HostState(st), cur.String, pend.String, nil
}

// SetPendingCert records a newly issued certificate during rotation.
func (s *Store) SetPendingCert(ctx context.Context, hostID string, cert AgentCert) error {
	res, err := s.db.ExecContext(ctx, `UPDATE hosts SET agent_cert_pending = ?, agent_cert_pending_expires = ?
		WHERE id = ? AND source = 'agent' AND state != 'revoked'`, cert.Fingerprint, millis(cert.Expires), hostID)
	if err != nil {
		return fmt.Errorf("set pending certificate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PromotePendingCert makes the pending certificate the only accepted one. It
// is called when the agent first authenticates with it.
func (s *Store) PromotePendingCert(ctx context.Context, hostID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET agent_cert_fingerprint = agent_cert_pending,
		agent_cert_expires = agent_cert_pending_expires, agent_cert_pending = NULL, agent_cert_pending_expires = NULL
		WHERE id = ? AND agent_cert_pending IS NOT NULL AND state != 'revoked'`, hostID)
	if err != nil {
		return fmt.Errorf("promote certificate: %w", err)
	}
	return nil
}

// AgentReport describes what an agent announced with a report.
type AgentReport struct {
	Name         string
	AgentVersion string
	OS, Arch     string
	// Kind is the host kind; empty keeps the stored one.
	Kind inventory.HostKind
	// Addresses replace the stored ones; nil keeps them.
	Addresses []string
	Interval  time.Duration
}

// TouchAgent records contact from an agent and makes a stale host active
// again. Revoked hosts are not touched.
func (s *Store) TouchAgent(ctx context.Context, hostID string, r AgentReport, now time.Time) error {
	addrs := ""
	if r.Addresses != nil {
		raw, err := json.Marshal(r.Addresses)
		if err != nil {
			return fmt.Errorf("encode agent addresses: %w", err)
		}
		addrs = string(raw)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET name = ?, agent_version = ?, os = ?, arch = ?,
		kind = CASE WHEN ? = '' THEN kind ELSE ? END, addresses_json = CASE WHEN ? = '' THEN addresses_json ELSE ? END,
		report_interval_ms = ?, last_contact = ?, state = 'active'
		WHERE id = ? AND source = 'agent' AND state != 'revoked'`,
		r.Name, r.AgentVersion, r.OS, r.Arch, string(r.Kind), string(r.Kind), addrs, addrs, r.Interval.Milliseconds(), millis(now), hostID)
	if err != nil {
		return fmt.Errorf("touch agent: %w", err)
	}
	return nil
}

// RevokeAgent rejects the agent's certificates from now on and marks its
// workloads removed, so that its findings resolve. The host row stays for the
// audit trail.
func (s *Store) RevokeAgent(ctx context.Context, hostID string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE hosts SET state = 'revoked', agent_cert_fingerprint = NULL,
			agent_cert_pending = NULL, agent_cert_pending_expires = NULL
			WHERE id = ? AND source = 'agent' AND state != 'revoked'`, hostID)
		if err != nil {
			return fmt.Errorf("revoke agent: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `UPDATE workloads SET removed_at = ? WHERE host_id = ? AND removed_at IS NULL`,
			millis(now), hostID); err != nil {
			return fmt.Errorf("remove workloads of revoked agent: %w", err)
		}
		// What a revoked agent reported about images is no longer used.
		if _, err := tx.ExecContext(ctx, `DELETE FROM image_package_reads WHERE source = ?`, "agent:"+hostID); err != nil {
			return fmt.Errorf("remove image records of revoked agent: %w", err)
		}
		return nil
	})
}

// MarkStaleHosts sets agents to stale that have not reported for three of
// their announced intervals (at least one minute each).
func (s *Store) MarkStaleHosts(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET state = 'stale'
		WHERE source = 'agent' AND state = 'active'
		AND last_contact < ? - 3 * MAX(report_interval_ms, 60000)`, millis(now))
	if err != nil {
		return fmt.Errorf("mark stale hosts: %w", err)
	}
	return nil
}

// SnapshotHash returns the hash of the last snapshot accepted from an agent.
func (s *Store) SnapshotHash(ctx context.Context, hostID string) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT snapshot_hash FROM hosts WHERE id = ?`, hostID).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("query snapshot hash: %w", err)
	}
	return h, nil
}

// SetSnapshotHash records the hash of an accepted snapshot.
func (s *Store) SetSnapshotHash(ctx context.Context, hostID, hash string) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE hosts SET snapshot_hash = ? WHERE id = ?`, hash, hostID); err != nil {
		return fmt.Errorf("set snapshot hash: %w", err)
	}
	return nil
}

// ApplyAgentSnapshot applies an agent's container snapshot and records its
// hash in one transaction that also checks the host is not revoked, so a
// report racing a revocation cannot bring workloads back.
func (s *Store) ApplyAgentSnapshot(ctx context.Context, hostID string, ws []inventory.Workload, hash string, now time.Time) (inventory.Changes, error) {
	var res inventory.Changes
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var state string
		err := tx.QueryRowContext(ctx, `SELECT state FROM hosts WHERE id = ? AND source = 'agent'`, hostID).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read agent state: %w", err)
		}
		if inventory.HostState(state) == inventory.HostRevoked {
			return ErrInvalidState
		}
		if res, err = applySnapshotTx(ctx, tx, hostID, inventory.KindContainer, ws, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET snapshot_hash = ? WHERE id = ?`, hash, hostID); err != nil {
			return fmt.Errorf("set snapshot hash: %w", err)
		}
		return nil
	})
	return res, err
}

// AgentInventory is the host inventory an agent delivered: identity keys,
// the full package list, and the catalog apps among the packages and
// services as workloads.
type AgentInventory struct {
	MACs      []string
	MachineID string
	Packages  HostPackages
	Apps      []inventory.Workload // KindPackage
	Services  []inventory.Workload // KindService
}

// ApplyAgentInventory records an agent's host inventory in one transaction
// that also checks the host is not revoked, as ApplyAgentSnapshot does.
func (s *Store) ApplyAgentInventory(ctx context.Context, hostID string, inv AgentInventory, now time.Time) (inventory.Changes, error) {
	var res inventory.Changes
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var state string
		err := tx.QueryRowContext(ctx, `SELECT state FROM hosts WHERE id = ? AND source = 'agent'`, hostID).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read agent state: %w", err)
		}
		if inventory.HostState(state) == inventory.HostRevoked {
			return ErrInvalidState
		}
		macs := inv.MACs
		if macs == nil {
			macs = []string{}
		}
		raw, err := json.Marshal(macs)
		if err != nil {
			return fmt.Errorf("encode MACs: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET macs_json = ?, machine_id = ? WHERE id = ?`,
			string(raw), inv.MachineID, hostID); err != nil {
			return fmt.Errorf("record agent host identity: %w", err)
		}
		inv.Packages.HostID = hostID
		if err := setHostPackages(ctx, tx, inv.Packages); err != nil {
			return err
		}
		for _, set := range []struct {
			kind inventory.Kind
			ws   []inventory.Workload
		}{{inventory.KindPackage, inv.Apps}, {inventory.KindService, inv.Services}} {
			c, err := applySnapshotTx(ctx, tx, hostID, set.kind, set.ws, now)
			if err != nil {
				return err
			}
			res.Added += c.Added
			res.Changed += c.Changed
			res.Removed += c.Removed
		}
		return nil
	})
	return res, err
}
