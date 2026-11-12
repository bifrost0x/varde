// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/store"
)

// runResetPassword sets a random password for username and ends the user's
// sessions. It needs the data directory, so it runs where the server runs
// (docker exec); access to that is already full control over Varde.
func runResetPassword(username string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: invalid configuration:\n%v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pw, err := resetPassword(ctx, filepath.Join(cfg.DataDir, "varde.db"), username)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "New password for %s (shown once; change it under Settings after signing in):\n%s\n", username, pw)
	return 0
}

func resetPassword(ctx context.Context, dbPath, username string) (string, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return "", fmt.Errorf("database %s: %w", dbPath, err)
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = st.Close() }()
	u, err := st.UserByName(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("no account named %q", username)
	}
	if err != nil {
		return "", err
	}
	pw, err := auth.RandomToken(18) // 24 characters, about 144 bits
	if err != nil {
		return "", err
	}
	hash, err := auth.HashPassword(ctx, pw)
	if err != nil {
		return "", err
	}
	if err := st.SetPassword(ctx, u.ID, hash); err != nil {
		return "", err
	}
	if err := st.Audit(ctx, store.AuditEntry{At: time.Now(), Actor: "cli", Action: "password.reset", Target: u.Username}); err != nil {
		return "", err
	}
	return pw, nil
}
