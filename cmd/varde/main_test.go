// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/store"
)

func TestRunUsage(t *testing.T) {
	cases := []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"bogus"}, 2},
		{[]string{"server", "extra"}, 2},
		{[]string{"agent"}, 1}, // configuration error: VARDE_SERVER_URL missing
		{[]string{"healthcheck", "agent", "x"}, 2},
		{[]string{"help"}, 0},
		{[]string{"version"}, 0},
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		if got := run(c.args, &out, &errOut); got != c.code {
			t.Errorf("run(%v) = %d, want %d (stderr %q)", c.args, got, c.code, errOut.String())
		}
	}
}

func TestVersionOutput(t *testing.T) {
	var out bytes.Buffer
	run([]string{"version"}, &out, &bytes.Buffer{})
	if !strings.HasPrefix(out.String(), "varde dev") {
		t.Fatalf("got %q", out.String())
	}
}

func TestProbe(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ok.Close()
	if err := probe(t.Context(), ok.URL); err != nil {
		t.Fatalf("healthy server: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if err := probe(t.Context(), bad.URL); err == nil {
		t.Fatal("expected error for 503")
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ok.URL, http.StatusFound)
	}))
	defer redirect.Close()
	if err := probe(t.Context(), redirect.URL); err == nil {
		t.Fatal("expected redirect not to be followed")
	}
}

func testConfig(t *testing.T, addr string) config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.ListenAddr = addr
	cfg.DataDir = t.TempDir()
	cfg.DockerHost = config.DockerHostOff
	return cfg
}

func testDeps(t *testing.T) serverDeps {
	return serverDeps{socketPath: filepath.Join(t.TempDir(), "docker.sock")}
}

func TestServeLifecycle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := testConfig(t, addr)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, slog.New(slog.DiscardHandler), testDeps(t)) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := probe(t.Context(), cfg.LocalHealthURL()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not become healthy")
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(shutdownTimeout + time.Second):
		t.Fatal("serve did not return after cancel")
	}
}

func TestServeReportsListenError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	cfg := testConfig(t, ln.Addr().String())
	if err := serve(t.Context(), cfg, slog.New(slog.DiscardHandler), testDeps(t)); err == nil {
		t.Fatal("expected error for occupied port")
	}
}

func TestDirectSocketRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets in temp dirs are not reliable on Windows")
	}
	dir, err := os.MkdirTemp("", "vs") // short path: unix socket paths are length-limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	logger := slog.New(slog.DiscardHandler)
	if err := checkDirectSocket(sock, false, logger); err == nil || !strings.Contains(err.Error(), "ALLOW_DIRECT_SOCKET") {
		t.Fatalf("mounted socket not refused: %v", err)
	}
	if err := checkDirectSocket(sock, true, logger); err != nil {
		t.Fatalf("explicit opt-in refused: %v", err)
	}
	if err := checkDirectSocket(filepath.Join(dir, "missing"), false, logger); err != nil {
		t.Fatalf("missing path: %v", err)
	}
	regular := filepath.Join(dir, "file")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkDirectSocket(regular, false, logger); err != nil {
		t.Fatalf("regular file: %v", err)
	}

	// serve refuses before opening anything.
	cfg := testConfig(t, "127.0.0.1:0")
	if err := serve(t.Context(), cfg, logger, serverDeps{socketPath: sock}); err == nil {
		t.Fatal("serve started with a mounted socket")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "varde.db")); !os.IsNotExist(err) {
		t.Fatal("database created despite refusal")
	}
}

func TestResetPassword(t *testing.T) {
	ctx := t.Context()
	db := filepath.Join(t.TempDir(), "varde.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword(ctx, "correct horse battery")
	if err := st.CreateUser(ctx, store.User{ID: "u1", Username: "admin", PasswordHash: hash, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	if _, err := resetPassword(ctx, db, "nobody"); err == nil {
		t.Fatal("unknown user accepted")
	}
	if _, err := resetPassword(ctx, filepath.Join(t.TempDir(), "missing.db"), "admin"); err == nil {
		t.Fatal("missing database created")
	}
	pw, err := resetPassword(ctx, db, "admin")
	if err != nil || len(pw) < auth.MinPasswordLength {
		t.Fatalf("reset: %q %v", pw, err)
	}
	st, _ = store.Open(ctx, db)
	defer func() { _ = st.Close() }()
	u, _ := st.UserByName(ctx, "admin")
	if auth.VerifyPassword(ctx, pw, u.PasswordHash) != nil || auth.VerifyPassword(ctx, "correct horse battery", u.PasswordHash) == nil {
		t.Fatal("password not replaced")
	}
	audit, _ := st.AuditLog(ctx, 10)
	if len(audit) == 0 || audit[0].Action != "password.reset" {
		t.Fatalf("not audited: %+v", audit)
	}
}
