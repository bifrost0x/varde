// SPDX-License-Identifier: Apache-2.0

package pkgdb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"strings"

	"github.com/bifrost0x/varde/internal/inventory"
)

// maxDependencies bounds the dependencies read from one lock file or binary.
const maxDependencies = 10000

// LockFile is the npm lock file Varde reads next to an app's package.json.
const LockFile = "package-lock.json"

// ParseNPMLock reads the installed dependencies of an npm lock file
// (lockfileVersion 1 to 3). Development dependencies, links and versions
// that are not from the registry (git, file, tarball URLs) are left out.
func ParseNPMLock(b []byte) []inventory.Package {
	type dep struct {
		Version      string         `json:"version"`
		Name         string         `json:"name"`
		Dev          bool           `json:"dev"`
		Link         bool           `json:"link"`
		Dependencies map[string]any `json:"dependencies"`
	}
	var lock struct {
		Packages     map[string]dep  `json:"packages"`
		Dependencies json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []inventory.Package
	add := func(name, ver string) {
		// An alias installs another package: "npm:lodash@4.17.20".
		if alias, ok := strings.CutPrefix(ver, "npm:"); ok {
			if i := strings.LastIndex(alias, "@"); i > 0 {
				name, ver = alias[:i], alias[i+1:]
			}
		}
		if len(out) >= maxDependencies || name == "" || len(name) > 214 || !registryVersion(ver) || seen[name+"@"+ver] {
			return
		}
		seen[name+"@"+ver] = true
		out = append(out, inventory.Package{Manager: "npm", Name: name, Version: ver})
	}
	if len(lock.Packages) > 0 {
		for key, d := range lock.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || d.Dev || d.Link {
				continue
			}
			name := key[i+len("node_modules/"):]
			if d.Name != "" {
				// An alias ("node_modules/foo": {"name": "bar"}) installs bar.
				name = d.Name
			}
			add(name, d.Version)
		}
		return out
	}
	// Version 1: nested dependencies.
	var walk func(raw json.RawMessage, depth int)
	walk = func(raw json.RawMessage, depth int) {
		var deps map[string]struct {
			Version      string          `json:"version"`
			Dev          bool            `json:"dev"`
			Dependencies json.RawMessage `json:"dependencies"`
		}
		if depth > 32 || json.Unmarshal(raw, &deps) != nil {
			return
		}
		for name, d := range deps {
			if d.Dev {
				continue
			}
			add(name, d.Version)
			if len(d.Dependencies) > 0 {
				walk(d.Dependencies, depth+1)
			}
		}
	}
	if len(lock.Dependencies) > 0 {
		walk(lock.Dependencies, 0)
	}
	return out
}

// registryVersion reports whether a lock file version is a release from
// the registry ("1.2.3", "1.2.3-beta.1"), not a URL or a path.
func registryVersion(v string) bool {
	return v != "" && len(v) <= 64 && v[0] >= '0' && v[0] <= '9' && !strings.ContainsAny(v, ":/ ")
}

// GoBinary is the build information of a Go executable: the toolchain and
// every module compiled in.
type GoBinary struct {
	GoVersion string
	Packages  []inventory.Package
}

// buildInfoMagic starts the build information Go writes into every
// executable since Go 1.18 (debug/buildinfo).
var buildInfoMagic = []byte("\xff Go buildinf:")

// Bounds of the strings in the build information.
const (
	maxGoVersion = 64
	maxModInfo   = 1 << 20
)

// ErrNotGo is returned for an executable without Go build information.
var ErrNotGo = errors.New("no Go build information")

// ScanGoBinary reads an executable as a stream and returns its Go build
// information. It never keeps more than a window of the file: the
// information is a short block somewhere in the data section, found by its
// magic and checked by its header.
func ScanGoBinary(r io.Reader) (GoBinary, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	window := make([]byte, 0, 2<<20)
	for {
		chunk := make([]byte, 1<<20)
		n, err := io.ReadFull(br, chunk)
		window = append(window, chunk[:n]...)
		for {
			i := bytes.Index(window, buildInfoMagic)
			if i < 0 {
				break
			}
			// The header is 32 bytes and 16-byte aligned; the strings follow.
			need := i + 32 + binary.MaxVarintLen64*2 + maxGoVersion + maxModInfo
			if len(window) < need && err == nil {
				more := make([]byte, need-len(window))
				m, rerr := io.ReadFull(br, more)
				window = append(window, more[:m]...)
				if rerr != nil {
					err = rerr
				}
			}
			if bi, ok := parseBuildInfo(window[i:]); ok {
				return bi, nil
			}
			window = window[i+1:]
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return GoBinary{}, ErrNotGo
			}
			return GoBinary{}, err
		}
		// Keep the tail: the magic may span two chunks.
		if len(window) > len(buildInfoMagic) {
			window = append(window[:0], window[len(window)-len(buildInfoMagic)+1:]...)
		}
	}
}

// parseBuildInfo decodes an inline build information block (Go 1.18 and
// later); ok is false for anything else, such as the magic string inside a
// program that reads build information itself.
func parseBuildInfo(b []byte) (GoBinary, bool) {
	if len(b) < 32 {
		return GoBinary{}, false
	}
	ptr, flags := b[14], b[15]
	if (ptr != 4 && ptr != 8) || flags&^0x3 != 0 || flags&0x2 == 0 || !bytes.Equal(b[16:32], make([]byte, 16)) {
		return GoBinary{}, false
	}
	rest := b[32:]
	str := func(limit int) (string, bool) {
		n, w := binary.Uvarint(rest)
		if w <= 0 || n > maxModInfo {
			return "", false
		}
		size := int(n) //nolint:gosec // G115: n is at most maxModInfo
		if size > limit || len(rest)-w < size {
			return "", false
		}
		s := string(rest[w : w+size])
		rest = rest[w+size:]
		return s, true
	}
	goVersion, ok := str(maxGoVersion)
	if !ok || !strings.HasPrefix(goVersion, "go") {
		return GoBinary{}, false
	}
	mod, ok := str(maxModInfo)
	if !ok {
		return GoBinary{}, false
	}
	// The module information is framed by 16 bytes on either side.
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		mod = mod[16 : len(mod)-16]
	}
	out := GoBinary{GoVersion: goVersion}
	if v, ok := goRelease(goVersion); ok {
		out.Packages = append(out.Packages, inventory.Package{Manager: "go", Name: "stdlib", Version: v})
	}
	info, err := debug.ParseBuildInfo(mod)
	if err != nil {
		// Built without module support: only the toolchain is known.
		return out, true
	}
	add := func(m *debug.Module) {
		if m == nil || len(out.Packages) >= maxDependencies {
			return
		}
		if m.Replace != nil {
			m = m.Replace
		}
		if m.Path == "" || len(m.Path) > 256 || !strings.HasPrefix(m.Version, "v") || len(m.Version) > 128 {
			// A local replacement or a development build has no release.
			return
		}
		out.Packages = append(out.Packages, inventory.Package{Manager: "go", Name: m.Path, Version: m.Version})
	}
	add(&info.Main)
	for _, d := range info.Deps {
		add(d)
	}
	return out, true
}

// goRelease turns "go1.22.5" (or "go1.22.5 X:boringcrypto") into "1.22.5",
// the version osv.dev records for the standard library.
func goRelease(v string) (string, bool) {
	v, _, _ = strings.Cut(v, " ")
	v = strings.TrimPrefix(v, "go")
	// Release candidates and development builds are not releases.
	if v == "" || strings.Trim(v, "0123456789.") != "" {
		return "", false
	}
	return v, true
}
