// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pkgdb"
)

// LanguageRoots are the directories apps install language packages into
// outside the distribution's own package directories: pip's
// /usr/local/lib/python3.x/{site,dist}-packages, Bundler's
// /usr/local/bundle, apps under /opt, /app, /srv and /var/www. The
// distribution's /usr/lib is left out: what is there belongs to its
// package manager and is checked against the distribution's data.
var LanguageRoots = []string{"/usr/local/lib", "/usr/local/bundle", "/opt", "/app", "/srv", "/var/www"}

// Bounds of reading the language roots of one container: bytes streamed
// in all, time, metadata files kept, and the size of one archive (a JAR)
// read into memory to look inside.
const (
	languageBytes      = 1 << 30
	languageTimeout    = 4 * time.Minute
	languageFiles      = 20000
	languageArchiveMax = 64 << 20
	languageMetaMax    = 4 << 20
)

// errLanguageBound stops a read at a bound; the caller marks the result
// partial.
var errLanguageBound = errors.New("docker: language package read reached its bound")

// LanguageRead is what ReadLanguagePackages found, and whether it stopped
// at a bound before reading everything.
type LanguageRead struct {
	Packages []inventory.Package
	Partial  bool
}

// ReadLanguagePackages streams the language roots of a container, and its
// working directory when that lies outside them, and returns the packages
// their metadata names: Python (METADATA, PKG-INFO), PHP (Composer's
// installed.json), Ruby (gem specifications), .NET (*.deps.json) and Java
// (pom.properties inside JARs). Only these small files and JARs are read;
// everything else is skipped as it streams by.
func (c *Client) ReadLanguagePackages(ctx context.Context, id, workDir string) (LanguageRead, error) {
	if !validID(id) {
		return LanguageRead{}, fmt.Errorf("docker: refusing to read the language roots of %q", id)
	}
	ctx, cancel := context.WithTimeout(ctx, languageTimeout)
	defer cancel()
	roots := append([]string(nil), LanguageRoots...)
	if wd := path.Clean(workDir); workDir != "" && path.IsAbs(wd) && wd != "/" && !under(wd, roots) {
		roots = append(roots, wd)
	}
	var out LanguageRead
	budget := int64(languageBytes)
	files := 0
	for _, root := range roots {
		if budget <= 0 || files >= languageFiles {
			out.Partial = true
			break
		}
		counter := &countingLimit{left: budget}
		err := c.archiveTar(ctx, id, root, budget, func(tr *tar.Reader) error {
			return readLanguageTree(tr, path.Dir(root), counter, &files, &out.Packages)
		})
		budget -= counter.used
		out.Partial = out.Partial || counter.skipped
		switch {
		case err == nil, errors.Is(err, ErrNoFile):
		case errors.Is(err, errLanguageBound), errors.Is(err, io.ErrUnexpectedEOF):
			// The archive ran into the byte bound: what was read counts.
			out.Partial = true
		case ctx.Err() != nil:
			if errors.Is(ctx.Err(), context.DeadlineExceeded) && len(out.Packages) > 0 {
				out.Partial = true
				return out, nil
			}
			return out, ctx.Err()
		default:
			return out, err
		}
	}
	return out, nil
}

// under reports whether dir lies inside one of roots.
func under(dir string, roots []string) bool {
	for _, r := range roots {
		if dir == r || strings.HasPrefix(dir, r+"/") {
			return true
		}
	}
	return false
}

// countingLimit tracks the bytes a tar walk consumed of its budget, and
// whether it skipped package metadata too large to read.
type countingLimit struct {
	left, used int64
	skipped    bool
}

func (c *countingLimit) take(n int64) bool {
	c.used += n
	return c.used <= c.left
}

// readLanguageTree walks one root's archive. Names in the archive are
// relative to the root's parent (Docker names the root itself first).
func readLanguageTree(tr *tar.Reader, parent string, budget *countingLimit, files *int, out *[]inventory.Package) error {
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !budget.take(hdr.Size + 512) {
			return errLanguageBound
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		full := path.Join(parent, path.Clean("/"+hdr.Name))
		kind := languageFile(full)
		if kind == "" {
			continue
		}
		if *files >= languageFiles {
			return errLanguageBound
		}
		*files++
		limit := int64(languageMetaMax)
		if kind == "jar" {
			limit = languageArchiveMax
		}
		if hdr.Size > limit {
			// Its packages stay unknown: the read is incomplete.
			budget.skipped = true
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return err
		}
		var found []inventory.Package
		switch kind {
		case "python":
			if p, ok := pkgdb.ParsePythonMetadata(b); ok {
				found = append(found, p)
			}
		case "composer":
			found = pkgdb.ParseComposerInstalled(b)
		case "gem":
			if p, ok := pkgdb.ParseGemspecName(path.Base(full)); ok {
				found = append(found, p)
			}
		case "dotnet":
			found = pkgdb.ParseDepsJSON(b)
		case "jar":
			found = pkgdb.ParseJAR(bytes.NewReader(b), int64(len(b)))
		}
		for _, p := range found {
			p.Path = full
			*out = append(*out, p)
		}
	}
}

// languageFile says which metadata a path is, or "" for anything else.
func languageFile(p string) string {
	base := path.Base(p)
	dir := path.Base(path.Dir(p))
	switch {
	case base == "METADATA" && strings.HasSuffix(dir, ".dist-info") && sitePackages(p):
		return "python"
	case base == "PKG-INFO" && strings.HasSuffix(dir, ".egg-info") && sitePackages(p):
		return "python"
	case base == "installed.json" && strings.HasSuffix(path.Dir(p), "/vendor/composer"):
		return "composer"
	case strings.HasSuffix(base, ".gemspec") && dir == "specifications":
		return "gem"
	case strings.HasSuffix(base, ".deps.json"):
		return "dotnet"
	case strings.HasSuffix(base, ".jar") || strings.HasSuffix(base, ".war") || strings.HasSuffix(base, ".ear"):
		return "jar"
	}
	return ""
}

// sitePackages reports whether a Python metadata file belongs to an
// installed package (site-packages or dist-packages), not to a source
// tree that happens to contain one.
func sitePackages(p string) bool {
	return strings.Contains(p, "/site-packages/") || strings.Contains(p, "/dist-packages/")
}
