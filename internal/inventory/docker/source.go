// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"path"

	"github.com/bifrost0x/varde/internal/pkgdb"
)

// FileSource is where the package reader finds files: a container's
// archive endpoint, or any other view of an image's filesystem such as its
// squashed layers. Every method reads only what the matching Client method
// of the same name reads, and a missing file is ErrNoFile, so one reader
// serves every source (ADR 0026).
type FileSource interface {
	ReadFile(ctx context.Context, file string) ([]byte, error)
	ReadStatusDir(ctx context.Context) ([][]byte, error)
	ReadGoBuildInfo(ctx context.Context, file string) (pkgdb.GoBinary, error)
	ReadGoPrograms(ctx context.Context) ([]GoProgram, error)
	ReadLanguagePackages(ctx context.Context, workDir string) (LanguageRead, error)
}

// ContainerSource reads the files of one container through the Docker
// archive endpoint.
func ContainerSource(c *Client, containerID string) FileSource {
	return containerSource{c: c, id: containerID}
}

type containerSource struct {
	c  *Client
	id string
}

func (s containerSource) ReadFile(ctx context.Context, file string) ([]byte, error) {
	return s.c.ReadFile(ctx, s.id, file)
}

func (s containerSource) ReadStatusDir(ctx context.Context) ([][]byte, error) {
	return s.c.ReadStatusDir(ctx, s.id)
}

func (s containerSource) ReadGoBuildInfo(ctx context.Context, file string) (pkgdb.GoBinary, error) {
	return s.c.ReadGoBuildInfo(ctx, s.id, file)
}

func (s containerSource) ReadGoPrograms(ctx context.Context) ([]GoProgram, error) {
	return s.c.ReadGoPrograms(ctx, s.id)
}

func (s containerSource) ReadLanguagePackages(ctx context.Context, workDir string) (LanguageRead, error) {
	return s.c.ReadLanguagePackages(ctx, s.id, workDir)
}

// LanguageFromTar reads the language packages from the archive of one
// root directory, in the form Docker's archive endpoint streams it: names
// relative to the root's parent, the root itself first. budget bounds the
// bytes walked; a tar that exceeds it, ends early, or holds more metadata
// files than the reader keeps yields what was read, marked Partial. It is
// the tar-walking part of Client.ReadLanguagePackages, for sources that
// build such a stream themselves.
func LanguageFromTar(tr *tar.Reader, root string, budget int64) (LanguageRead, error) {
	var out LanguageRead
	counter := &countingLimit{left: budget}
	files := 0
	err := readLanguageTree(tr, path.Dir(root), counter, &files, &out.Packages)
	out.Partial = counter.skipped
	switch {
	case err == nil:
	case errors.Is(err, errLanguageBound), errors.Is(err, io.ErrUnexpectedEOF):
		out.Partial = true
	default:
		return out, err
	}
	return out, nil
}
