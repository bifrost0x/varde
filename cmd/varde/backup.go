// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/store"
)

// backupDirs are the directories of the data directory a backup holds
// besides the database: the agent CA, the encryption keys of integration
// secrets and the SSH identity. Without them agents must enroll again and
// stored secrets cannot be read.
var backupDirs = []string{"ca", "keys", "ssh"}

// maxRestoreFile bounds one file of a restored backup.
const maxRestoreFile = 4 << 30

func runBackup(dest string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: invalid configuration:\n%v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := backup(ctx, cfg.DataDir, dest); err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: backup failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Backup written to %s. It holds the agent CA and encryption keys: keep it as safe as the data directory.\n", dest)
	return 0
}

func runRestore(src string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: invalid configuration:\n%v\n", err)
		return 1
	}
	if err := restore(cfg.DataDir, src); err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: restore failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Restored %s into %s. Start the server; it upgrades the database if the backup is older.\n", src, cfg.DataDir)
	return 0
}

// backup writes a tar archive with a consistent copy of the database,
// taken while the server runs, and the key directories.
func backup(ctx context.Context, dataDir, dest string) (err error) {
	if !filepath.IsAbs(dest) {
		return fmt.Errorf("the backup path must be absolute, got %q", dest)
	}
	dbPath := filepath.Join(dataDir, "varde.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("database %s: %w", dbPath, err)
	}
	snap, err := os.CreateTemp(filepath.Dir(dest), ".varde-backup-*.db")
	if err != nil {
		return fmt.Errorf("temporary file next to %s: %w", dest, err)
	}
	snapPath := snap.Name()
	_ = snap.Close()
	_ = os.Remove(snapPath)                    //nolint:gosec // our own temporary file; VACUUM INTO needs a path that does not exist
	defer func() { _ = os.Remove(snapPath) }() //nolint:gosec // our own temporary file
	if err := store.Snapshot(ctx, dbPath, snapPath); err != nil {
		return err
	}

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path given by the operator on the command line
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dest) //nolint:gosec // the incomplete backup this call created (O_EXCL)
		}
	}()
	tw := tar.NewWriter(out)
	if err := addFile(tw, snapPath, "varde.db"); err != nil {
		return err
	}
	for _, d := range backupDirs {
		root := filepath.Join(dataDir, d)
		err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !e.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(dataDir, p)
			if err != nil {
				return err
			}
			return addFile(tw, p, filepath.ToSlash(rel))
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("back up %s: %w", d, err)
		}
	}
	return tw.Close()
}

func addFile(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path) //nolint:gosec // files of the data directory
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// restore unpacks a backup into an empty data directory. It refuses one
// that holds a database already, and any entry outside the directory.
func restore(dataDir, src string) error {
	if _, err := os.Stat(filepath.Join(dataDir, "varde.db")); err == nil {
		return fmt.Errorf("%s already holds a database; restore into an empty data directory", dataDir)
	}
	f, err := os.Open(src) //nolint:gosec // path given by the operator on the command line
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	sawDB := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", src, err)
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		top, _, _ := strings.Cut(filepath.ToSlash(name), "/")
		if hdr.Typeflag != tar.TypeReg || filepath.IsAbs(name) || strings.HasPrefix(name, "..") ||
			(name != "varde.db" && !contains(backupDirs, top)) || hdr.Size > maxRestoreFile {
			return fmt.Errorf("unexpected entry %q in %s", hdr.Name, src)
		}
		target := filepath.Join(dataDir, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil { //nolint:gosec // inside the data directory, entry checked above
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside the data directory, checked above
		if err != nil {
			return err
		}
		_, cerr := io.Copy(out, io.LimitReader(tr, hdr.Size))
		if err := out.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return cerr
		}
		sawDB = sawDB || name == "varde.db"
	}
	if !sawDB {
		return fmt.Errorf("%s holds no database", src)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
