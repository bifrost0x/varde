// SPDX-License-Identifier: Apache-2.0

package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A database of the schema before migration 0023, with data, upgrades in
// place: the image records of every source are taken over, and the data
// stays readable.
func TestUpgradeFromOlderSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "varde.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	migs, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migs {
		if m.version >= 23 {
			break
		}
		if _, err := db.ExecContext(ctx, m.sql); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations VALUES (?, ?, ?)`, m.version, m.name, time.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UnixMilli()
	for _, row := range [][]any{
		{"sha256:own", "", `[{"manager":"dpkg","name":"openssl","version":"3.0.11-1"}]`},
		{"sha256:agent", "agent:h2", `[{"manager":"apk","name":"musl","version":"1.2.4-r2"}]`},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO image_packages (image_id, distro, os, packages, read_at, error, source) VALUES (?, 'debian-12', '', ?, ?, '', ?)`,
			row[0], row[2], now, row[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	got, err := s.ImagePackagesFor(ctx, []ImageRef{{"sha256:own", "h1"}, {"sha256:agent", "h2"}, {"sha256:agent", "h3"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[ImageRef{"sha256:own", "h1"}].Packages[0].Name != "openssl" || got[ImageRef{"sha256:agent", "h2"}].Packages[0].Name != "musl" {
		t.Fatalf("after upgrade: %+v", got)
	}
}

// Release reads stored before migration 0034 under "os/architecture" move
// to the key of their line's platform with its variant; reads without a
// variant, and lines that do not decode, keep their key.
func TestUpgradeKeysReleaseReadsByVariant(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "builder.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	migs, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migs {
		if m.version >= 34 {
			break
		}
		if _, err := db.ExecContext(ctx, m.sql); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations VALUES (?, ?, ?)`, m.version, m.name, time.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range [][]any{
		{"app", "linux/arm64", []byte(`{"platform":{"os":"linux","architecture":"arm64","variant":"v8"}}`)},
		{"app", "linux/amd64", []byte(`{"platform":{"os":"linux","architecture":"amd64"}}`)},
		{"other", "linux/arm64", []byte(`not json`)},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO release_reads (app_id, image, platform, tag, index_digest, line, read_at) VALUES (?, 'img', ?, 't', 'd', ?, 0)`,
			row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for app, want := range map[string]string{"app": "linux/amd64,linux/arm64/v8", "other": "linux/arm64"} {
		got, err := s.ReleaseReadPlatforms(ctx, app, "img")
		if err != nil {
			t.Fatal(err)
		}
		if g := strings.Join(got, ","); g != want {
			t.Errorf("%s: platforms %s, want %s", app, g, want)
		}
	}
}
