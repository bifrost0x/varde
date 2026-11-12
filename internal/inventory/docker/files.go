// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pkgdb"
)

// PackageFiles are the fixed paths Varde reads from a running container to
// learn its operating system packages. Nothing else is ever read: the
// Docker API (and the socket proxy) would allow any path. /etc/os-release
// is a symlink to /usr/lib/os-release on Debian and Alpine; symlinks are
// not followed, so the target is read directly (the fallback os-release(5)
// names).
var PackageFiles = append([]string{"/etc/os-release", "/usr/lib/os-release", "/var/lib/dpkg/status", "/lib/apk/db/installed"}, pkgdb.RPMDBFiles...)

// fileLimit bounds one file; a dpkg database of a large image is a few MB.
// An rpm database stores whole package headers and is larger.
const (
	fileLimit    = 16 << 20
	rpmFileLimit = 64 << 20
)

func limitFor(file string) int64 {
	if slices.Contains(pkgdb.RPMDBFiles, file) {
		return rpmFileLimit
	}
	return fileLimit
}

// ManifestFile is the one file name Varde reads in an image's working
// directory and its parent: the app's own package.json, which names it and
// its release. The directory comes from the image configuration, so the
// file name is fixed and the path must be absolute and clean.
const ManifestFile = "package.json"

// allowedFile reports whether file may be read from a container.
func allowedFile(file string) bool {
	for _, f := range PackageFiles {
		if f == file {
			return true
		}
	}
	base := path.Base(file)
	return cleanAbs(file) && (base == ManifestFile || base == pkgdb.LockFile)
}

// FileUse says how ReadPackages uses one path of an image.
type FileUse int

// The uses of a path.
const (
	Unread       FileUse = iota
	WholeFile            // read whole through ReadFile
	StatusFile           // a file of StatusDir
	Program              // a program scanned for its build information
	LanguageMeta         // language package metadata (or a JAR) in a language root
)

// Use reports how ReadPackages uses the file at p of an image with cfg,
// and the most bytes of it read. A source that copies an image's files
// ahead of the read, such as the squashed layers of a release, keeps
// exactly these, so it serves the same files with the same limits as a
// container.
func Use(cfg ImageConfig, p string) (FileUse, int64) {
	if !cleanAbs(p) {
		return Unread, 0
	}
	if slices.Contains(PackageFiles, p) {
		return WholeFile, limitFor(p)
	}
	for _, m := range manifestPaths(cfg.WorkingDir) {
		if p == m || p == path.Join(path.Dir(m), pkgdb.LockFile) {
			return WholeFile, fileLimit
		}
	}
	if path.Dir(p) == ProgramDir || slices.Contains(binaryPaths(cfg), p) {
		return Program, binaryLimit
	}
	if path.Dir(p) == StatusDir {
		return StatusFile, statusDirBytes
	}
	for _, root := range languageRoots(cfg.WorkingDir) {
		if !strings.HasPrefix(p, root+"/") {
			continue
		}
		switch languageFile(p) {
		case "":
		case "jar":
			return LanguageMeta, languageArchiveMax
		default:
			return LanguageMeta, languageMetaMax
		}
	}
	return Unread, 0
}

// ReadLocations are the files and directories ReadPackages reads of an
// image with cfg: the paths of WholeFile and Program files, and the
// directories holding StatusFile, Program and LanguageMeta files.
func ReadLocations(cfg ImageConfig) []string {
	out := append([]string(nil), PackageFiles...)
	for _, m := range manifestPaths(cfg.WorkingDir) {
		out = append(out, m, path.Join(path.Dir(m), pkgdb.LockFile))
	}
	out = append(out, binaryPaths(cfg)...)
	out = append(out, StatusDir, ProgramDir)
	return append(out, languageRoots(cfg.WorkingDir)...)
}

func cleanAbs(file string) bool {
	return path.IsAbs(file) && path.Clean(file) == file && len(file) <= 512
}

// binaryLimit bounds the bytes streamed from one executable; binaryTimeout
// the time it may take.
const (
	binaryLimit   = 512 << 20
	binaryTimeout = 3 * time.Minute
)

// ReadGoBuildInfo streams an executable of a container and returns the Go
// build information in it (pkgdb.ErrNotGo for other programs). The file is
// never kept: only the module list is taken from the stream. The path
// comes from the image configuration; a symlink is not followed.
func (c *Client) ReadGoBuildInfo(ctx context.Context, id, file string) (pkgdb.GoBinary, error) {
	if !cleanAbs(file) || !validID(id) {
		return pkgdb.GoBinary{}, fmt.Errorf("docker: refusing to read %q", file)
	}
	ctx, cancel := context.WithTimeout(ctx, binaryTimeout)
	defer cancel()
	var out pkgdb.GoBinary
	err := c.archive(ctx, id, file, binaryLimit, func(r io.Reader) error {
		bi, err := pkgdb.ScanGoBinary(r)
		out = bi
		return err
	})
	return out, err
}

// ProgramDir is where images put programs added on top of the
// distribution's packages: gosu in the official redis, postgres and
// mariadb images, the app itself in many others. Its Go programs are read
// like the one the image runs.
const ProgramDir = "/usr/local/bin"

// MaxPrograms bounds the files read from ProgramDir, in name order;
// MinProgramSize is the smallest file counted as a program.
const (
	MaxPrograms    = 32
	MinProgramSize = 1024
)

// GoProgram is the build information of one Go program in a container.
type GoProgram struct {
	Path string
	Info pkgdb.GoBinary
	// Crates are the crates.io dependencies a Rust program built with
	// cargo-auditable lists; Info is empty for such a program.
	Crates []inventory.Package
}

// programInMemory bounds a program read whole to look for a Rust
// dependency list; larger programs are only streamed for Go build
// information.
const programInMemory = 64 << 20

// ScanProgram reads one program of size bytes and returns its Go build
// information, or the crates.io dependencies of a Rust program built with
// cargo-auditable; pkgdb.ErrNotGo when it has neither. Path is left to the
// caller.
func ScanProgram(r io.Reader, size int64) (GoProgram, error) {
	if size > programInMemory {
		bi, err := pkgdb.ScanGoBinary(io.LimitReader(r, size))
		if err != nil {
			return GoProgram{}, err
		}
		return GoProgram{Info: bi}, nil
	}
	b, err := io.ReadAll(io.LimitReader(r, size))
	if err != nil {
		return GoProgram{}, err
	}
	bi, err := pkgdb.ScanGoBinary(bytes.NewReader(b))
	if errors.Is(err, pkgdb.ErrNotGo) {
		if crates := pkgdb.ParseCargoAuditable(bytes.NewReader(b)); len(crates) > 0 {
			return GoProgram{Crates: crates}, nil
		}
	}
	if err != nil {
		return GoProgram{}, err
	}
	return GoProgram{Info: bi}, nil
}

// ReadGoPrograms streams ProgramDir of a container and returns the Go
// programs in it, at most maxPrograms files and binaryLimit bytes in all.
// Nothing but their build information is kept; symlinks and other files
// are skipped.
func (c *Client) ReadGoPrograms(ctx context.Context, id string) ([]GoProgram, error) {
	if !validID(id) {
		return nil, fmt.Errorf("docker: refusing to read %q", ProgramDir)
	}
	ctx, cancel := context.WithTimeout(ctx, binaryTimeout)
	defer cancel()
	var out []GoProgram
	err := c.archiveTar(ctx, id, ProgramDir, binaryLimit, func(tr *tar.Reader) error {
		for files := 0; files < MaxPrograms; {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("docker archive: %w", err)
			}
			if hdr.Typeflag != tar.TypeReg || hdr.Size < MinProgramSize {
				continue
			}
			files++
			prog, err := ScanProgram(io.LimitReader(tr, hdr.Size), hdr.Size)
			switch {
			case errors.Is(err, pkgdb.ErrNotGo):
			case err != nil:
				return err
			default:
				prog.Path = path.Join(ProgramDir, path.Base(hdr.Name))
				out = append(out, prog)
			}
		}
		return nil
	})
	return out, err
}

// StatusDir is where distroless Debian images keep their package database:
// one file per package instead of /var/lib/dpkg/status.
const StatusDir = "/var/lib/dpkg/status.d"

// Bounds of a status directory.
const (
	statusDirFiles = 1024
	statusDirBytes = 16 << 20
)

// ReadStatusDir returns the regular files of StatusDir in a container, at
// most statusDirFiles of them and statusDirBytes in all; symlinks and
// anything else are skipped.
func (c *Client) ReadStatusDir(ctx context.Context, id string) ([][]byte, error) {
	if !validID(id) {
		return nil, fmt.Errorf("docker: refusing to read %q", StatusDir)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var out [][]byte
	err := c.archiveTar(ctx, id, StatusDir, statusDirBytes, func(tr *tar.Reader) error {
		var err error
		out, err = ReadStatusTar(tr)
		return err
	})
	return out, err
}

// ReadStatusTar reads the regular files of an archive of StatusDir, at
// most statusDirFiles of them and statusDirBytes in all; symlinks and
// anything else are skipped.
func ReadStatusTar(tr *tar.Reader) ([][]byte, error) {
	var out [][]byte
	total := 0
	for len(out) < statusDirFiles {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("docker archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > statusDirBytes-int64(total) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return out, err
		}
		total += len(b)
		out = append(out, b)
	}
	return out, nil
}

// archive streams the regular file at file of a container to read.
func (c *Client) archive(ctx context.Context, id, file string, limit int64, read func(io.Reader) error) error {
	return c.archiveTar(ctx, id, file, limit, func(tr *tar.Reader) error {
		hdr, err := tr.Next()
		if err != nil {
			return fmt.Errorf("docker archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name != path.Base(file) {
			// A symlink or something else under the fixed path: not read.
			return ErrNoFile
		}
		if hdr.Size > limit {
			return fmt.Errorf("docker archive: %s is larger than %d bytes", file, limit)
		}
		return read(io.LimitReader(tr, hdr.Size))
	})
}

// archiveTar streams the archive of a path in a container, at most limit
// bytes of it, to read.
func (c *Client) archiveTar(ctx context.Context, id, file string, limit int64, read func(*tar.Reader) error) error {
	req, err := c.request(ctx, c.versionedPath("/containers/"+id+"/archive"), url.Values{"path": {file}})
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker GET archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNoFile
	}
	if resp.StatusCode != http.StatusOK {
		return statusError("/containers/{id}/archive", resp)
	}
	return read(tar.NewReader(io.LimitReader(resp.Body, limit+64<<10)))
}

// ErrNoFile is returned when the container has no such file.
var ErrNoFile = errors.New("docker: no such file in the container")

// ReadFile returns the content of a regular file in a container through
// GET /containers/{id}/archive, which streams the path as a tar archive.
// Only paths in PackageFiles and package.json files are accepted; a symlink
// is not followed, so a container cannot point the read elsewhere.
func (c *Client) ReadFile(ctx context.Context, id, file string) ([]byte, error) {
	if !allowedFile(file) || !validID(id) {
		return nil, fmt.Errorf("docker: refusing to read %q", file)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var out []byte
	err := c.archive(ctx, id, file, limitFor(file), func(r io.Reader) error {
		b, err := io.ReadAll(r)
		out = b
		return err
	})
	return out, err
}
