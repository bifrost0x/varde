// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// A backup taken while the database is open restores into an empty data
// directory with its data and keys; restore refuses a directory in use and
// archives with foreign paths.
func TestBackupRestore(t *testing.T) {
	ctx := t.Context()
	src := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(src, "varde.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.UpsertHost(ctx, inventory.Host{ID: "h1", Name: "nas", Kind: inventory.HostLinux, Source: inventory.SourceManual, LastContact: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, d := range backupDirs {
		if err := os.MkdirAll(filepath.Join(src, d), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, d, "key"), []byte(d+"-secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "backup.tar")
	if err := backup(ctx, src, archive); err != nil {
		t.Fatal(err)
	}
	if err := backup(ctx, src, archive); err == nil {
		t.Fatal("an existing backup was overwritten")
	}

	dst := t.TempDir()
	if err := restore(dst, archive); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "ca", "key")); err != nil || string(b) != "ca-secret" {
		t.Fatalf("ca: %q %v", b, err)
	}
	back, err := store.Open(ctx, filepath.Join(dst, "varde.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = back.Close() }()
	if h, err := back.Host(ctx, "h1"); err != nil || h.Name != "nas" {
		t.Fatalf("restored host: %+v %v", h, err)
	}
	if err := restore(dst, archive); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Fatalf("restore over a database: %v", err)
	}

	evil := filepath.Join(t.TempDir(), "evil.tar")
	f, _ := os.Create(evil) //nolint:gosec // test file
	tw := tar.NewWriter(f)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = f.Close()
	if err := restore(t.TempDir(), evil); err == nil {
		t.Fatal("an entry outside the data directory was accepted")
	}
}

func TestBuildDate(t *testing.T) {
	if got := buildDate("1731234567"); got != "2024-11-10T10:29:27Z" {
		t.Fatalf("epoch: %q", got)
	}
	if got := buildDate("unknown"); got != "unknown" {
		t.Fatalf("other: %q", got)
	}
}
