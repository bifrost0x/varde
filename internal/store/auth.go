// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrConflict is returned when a unique value already exists.
var ErrConflict = errors.New("already exists")

// User is an account. All users are administrators in v1.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

// CountUsers returns the number of accounts.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// CreateUser stores u; usernames are unique case-insensitively.
func (s *Store) CreateUser(ctx context.Context, u User) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, millis(u.CreatedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrConflict
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// CreateFirstUser creates u only if no account exists yet and marks the
// setup token used, atomically. It returns ErrConflict when setup was
// already completed or the token is invalid, expired or used.
func (s *Store) CreateFirstUser(ctx context.Context, u User, setupTokenHash string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return fmt.Errorf("count users: %w", err)
		}
		if n > 0 {
			return ErrConflict
		}
		res, err := tx.ExecContext(ctx, `UPDATE setup_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
			millis(now), setupTokenHash, millis(now))
		if err != nil {
			return fmt.Errorf("consume setup token: %w", err)
		}
		if k, _ := res.RowsAffected(); k != 1 {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)`,
			u.ID, u.Username, u.PasswordHash, millis(u.CreatedAt)); err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		return nil
	})
}

// UserByName returns a user or ErrNotFound.
func (s *Store) UserByName(ctx context.Context, username string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at, last_login FROM users WHERE username = ?`, username))
}

// UserByID returns a user or ErrNotFound.
func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at, last_login FROM users WHERE id = ?`, id))
}

func (s *Store) scanUser(row *sql.Row) (User, error) {
	var u User
	var created int64
	var last sql.NullInt64
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &created, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, fmt.Errorf("read user: %w", err)
	}
	u.CreatedAt, u.LastLogin = fromMillis(created), optPtr(last)
	return u, nil
}

// Users lists all accounts.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, created_at, last_login FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var u User
		var created int64
		var last sql.NullInt64
		if err := rows.Scan(&u.ID, &u.Username, &created, &last); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.CreatedAt, u.LastLogin = fromMillis(created), optPtr(last)
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetPassword replaces a user's password hash and ends all their sessions.
func (s *Store) SetPassword(ctx context.Context, userID, hash string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID)
		if err != nil {
			return fmt.Errorf("set password: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
			return fmt.Errorf("end sessions: %w", err)
		}
		return nil
	})
}

// DeleteUser removes a user (and, by cascade, their sessions). The last
// account cannot be deleted.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return fmt.Errorf("count users: %w", err)
		}
		if n <= 1 {
			return fmt.Errorf("%w: the last account cannot be deleted", ErrInvalidState)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		if k, _ := res.RowsAffected(); k == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RecordLogin sets the last login time.
func (s *Store) RecordLogin(ctx context.Context, userID string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login = ? WHERE id = ?`, millis(now), userID)
	if err != nil {
		return fmt.Errorf("record login: %w", err)
	}
	return nil
}

// Session is a server-side session.
type Session struct {
	IDHash    string
	UserID    string
	CSRFToken string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, sess Session, userAgent, ip string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen, expires_at, user_agent, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, sess.IDHash, sess.UserID, sess.CSRFToken, millis(sess.CreatedAt), millis(sess.LastSeen),
		millis(sess.ExpiresAt), truncate(userAgent, 256), truncate(ip, 64))
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// SessionByHash returns a session or ErrNotFound.
func (s *Store) SessionByHash(ctx context.Context, idHash string) (Session, error) {
	var sess Session
	var created, seen, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT id_hash, user_id, csrf_token, created_at, last_seen, expires_at FROM sessions WHERE id_hash = ?`, idHash).
		Scan(&sess.IDHash, &sess.UserID, &sess.CSRFToken, &created, &seen, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, ErrNotFound
	}
	if err != nil {
		return sess, fmt.Errorf("read session: %w", err)
	}
	sess.CreatedAt, sess.LastSeen, sess.ExpiresAt = fromMillis(created), fromMillis(seen), fromMillis(expires)
	return sess, nil
}

// TouchSession updates the last-seen time.
func (s *Store) TouchSession(ctx context.Context, idHash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE id_hash = ?`, millis(now), idHash)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// PurgeSessions deletes sessions past their absolute expiry or idle limit.
func (s *Store) PurgeSessions(ctx context.Context, now time.Time, idle time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?`, millis(now), millis(now.Add(-idle)))
	if err != nil {
		return fmt.Errorf("purge sessions: %w", err)
	}
	return nil
}

// APIToken is a stored API token (hash only).
type APIToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	TokenHash string     `json:"-"`
	Scope     string     `json:"scope"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// CreateAPIToken stores t.
func (s *Store) CreateAPIToken(ctx context.Context, t APIToken) error {
	var expires any
	if t.ExpiresAt != nil {
		expires = millis(*t.ExpiresAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_tokens (id, name, token_hash, scope, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.TokenHash, t.Scope, t.CreatedBy, millis(t.CreatedAt), expires)
	if err != nil {
		return fmt.Errorf("create api token: %w", err)
	}
	return nil
}

// APITokenByHash returns a token or ErrNotFound.
func (s *Store) APITokenByHash(ctx context.Context, hash string) (APIToken, error) {
	var t APIToken
	var created int64
	var expires, used sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, token_hash, scope, created_by, created_at, expires_at, last_used FROM api_tokens WHERE token_hash = ?`, hash).
		Scan(&t.ID, &t.Name, &t.TokenHash, &t.Scope, &t.CreatedBy, &created, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, fmt.Errorf("read api token: %w", err)
	}
	t.CreatedAt, t.ExpiresAt, t.LastUsed = fromMillis(created), optPtr(expires), optPtr(used)
	return t, nil
}

// TouchAPIToken records use.
func (s *Store) TouchAPIToken(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used = ? WHERE id = ?`, millis(now), id)
	if err != nil {
		return fmt.Errorf("touch api token: %w", err)
	}
	return nil
}

// APITokens lists tokens without hashes.
func (s *Store) APITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, scope, created_by, created_at, expires_at, last_used FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("query api tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var created int64
		var expires, used sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Name, &t.Scope, &t.CreatedBy, &created, &expires, &used); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		t.CreatedAt, t.ExpiresAt, t.LastUsed = fromMillis(created), optPtr(expires), optPtr(used)
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken removes a token.
func (s *Store) DeleteAPIToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete api token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateSetupToken stores a one-time setup token hash, replacing unused ones.
func (s *Store) CreateSetupToken(ctx context.Context, hash string, now, expires time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM setup_tokens WHERE used_at IS NULL`); err != nil {
			return fmt.Errorf("clear setup tokens: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO setup_tokens (token_hash, created_at, expires_at) VALUES (?, ?, ?)`, hash, millis(now), millis(expires)); err != nil {
			return fmt.Errorf("create setup token: %w", err)
		}
		return nil
	})
}

// Settings returns all UI-managed settings.
func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("query settings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scan setting: %w", err)
		}
		out[k] = v
	}
	return out, rows.Err()
}

// PutSettings stores values; an empty value deletes the key (back to
// default).
func (s *Store) PutSettings(ctx context.Context, values map[string]string, by string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for k, v := range values {
			var err error
			if v == "" {
				_, err = tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, k)
			} else {
				_, err = tx.ExecContext(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
					ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
					k, v, millis(now), by)
			}
			if err != nil {
				return fmt.Errorf("store setting %s: %w", k, err)
			}
		}
		return nil
	})
}
