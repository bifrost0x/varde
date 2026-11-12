// SPDX-License-Identifier: Apache-2.0

package pkgdb

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/varde/internal/inventory"
)

// Bounds of the language package parsers. The input comes from any
// container image, so every read is capped and an input over a cap is
// rejected rather than parsed in part.
const (
	// maxLangPackages caps the packages returned by one call.
	maxLangPackages = 5000
	// maxLangName and maxLangVersion bound a package name and version.
	maxLangName    = 214
	maxLangVersion = 128
	// maxPythonHeader bounds the header block of a METADATA or PKG-INFO
	// file; the long description after it is never read.
	maxPythonHeader = 256 << 10
	// maxLangJSON bounds installed.json and deps.json.
	maxLangJSON = 16 << 20
	// maxZipEntries caps the entries of one archive, and maxZipEntriesTotal
	// those of an archive and all the archives nested in it.
	maxZipEntries      = 20000
	maxZipEntriesTotal = 200000
	// maxZipDirectory bounds the central directory of one archive, read
	// whole by archive/zip.
	maxZipDirectory = 16 << 20
	// maxPomProperties bounds one pom.properties, and maxPomTotal all of
	// them read from one archive tree.
	maxPomProperties = 1 << 20
	maxPomTotal      = 32 << 20
	// maxNestedJar bounds one jar inside WEB-INF/lib or BOOT-INF/lib, and
	// maxNestedTotal all of them together.
	maxNestedJar   = 64 << 20
	maxNestedTotal = 1 << 30
	// maxCargoAuditable bounds the .dep-v0 section, compressed and
	// decompressed.
	maxCargoAuditable = 8 << 20
)

// printableToken reports whether s is valid UTF-8 of printable characters
// without spaces, at most limit bytes long.
func printableToken(s string, limit int) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func validLangVersion(v string) bool {
	return printableToken(v, maxLangVersion) && !strings.Contains(v, "${")
}

// asciiName reports whether s is 1 to limit bytes of ASCII letters, digits
// and the characters in extra.
func asciiName(s string, limit int, extra string) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte(extra, c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// langSet collects packages without duplicates, up to maxLangPackages.
type langSet struct {
	out  []inventory.Package
	seen map[string]bool
}

// add reports false once the set is full.
func (s *langSet) add(manager, name, version string) bool {
	if len(s.out) >= maxLangPackages {
		return false
	}
	key := name + "@" + version
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if !s.seen[key] {
		s.seen[key] = true
		s.out = append(s.out, inventory.Package{Manager: manager, Name: name, Version: version})
	}
	return len(s.out) < maxLangPackages
}

func (s *langSet) full() bool { return len(s.out) >= maxLangPackages }

// ParsePythonMetadata reads Name and Version from the header block of a
// *.dist-info/METADATA or *.egg-info/PKG-INFO file. The name is normalised
// as PEP 503 does (lowercase, runs of "-", "_" and "." become "-").
func ParsePythonMetadata(b []byte) (inventory.Package, bool) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	header := b
	end := -1
	for _, sep := range [][]byte{[]byte("\n\n"), []byte("\n\r\n")} {
		if i := bytes.Index(b, sep); i >= 0 && (end < 0 || i < end) {
			end = i
		}
	}
	if end >= 0 {
		header = b[:end+1]
	}
	if len(header) > maxPythonHeader {
		return inventory.Package{}, false
	}
	var name, version string
	var haveName, haveVersion bool
	for _, line := range strings.Split(string(header), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			// A continuation of a multi-line field.
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "name":
			if !haveName {
				name, haveName = v, true
			}
		case "version":
			if !haveVersion {
				version, haveVersion = v, true
			}
		}
	}
	name, ok := normalizePythonName(name)
	if !ok || !validLangVersion(version) {
		return inventory.Package{}, false
	}
	return inventory.Package{Manager: "pip", Name: name, Version: version}, true
}

// normalizePythonName applies PEP 503 to a name valid under PEP 508: ASCII
// letters and digits, with "-", "_" and "." inside.
func normalizePythonName(name string) (string, bool) {
	if !asciiName(name, maxLangName, "-_.") || strings.ContainsAny(name[:1]+name[len(name)-1:], "-_.") {
		return "", false
	}
	var sb strings.Builder
	sep := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '-' || c == '_' || c == '.' {
			sep = true
			continue
		}
		if sep {
			sb.WriteByte('-')
			sep = false
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		sb.WriteByte(c)
	}
	return sb.String(), true
}

// ParseComposerInstalled reads vendor/composer/installed.json, in the
// Composer 2 shape ({"packages": [...]}) and the Composer 1 array.
// Branches ("dev-main", "2.x-dev") are not releases and are left out.
func ParseComposerInstalled(b []byte) []inventory.Package {
	type entry struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if len(b) > maxLangJSON {
		return nil
	}
	var entries []entry
	b = bytes.TrimSpace(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
	if len(b) > 0 && b[0] == '[' {
		if json.Unmarshal(b, &entries) != nil {
			return nil
		}
	} else {
		var v2 struct {
			Packages []entry `json:"packages"`
		}
		if json.Unmarshal(b, &v2) != nil {
			return nil
		}
		entries = v2.Packages
	}
	var set langSet
	for _, e := range entries {
		name := strings.ToLower(strings.TrimSpace(e.Name))
		vendor, pkg, ok := strings.Cut(name, "/")
		if !ok || !asciiName(vendor, maxLangName, "-_.") || !asciiName(pkg, maxLangName, "-_.") || len(name) > maxLangName {
			continue
		}
		ver := strings.TrimSpace(e.Version)
		if strings.HasPrefix(ver, "dev-") || strings.HasSuffix(ver, "-dev") {
			continue
		}
		ver = strings.TrimPrefix(ver, "v")
		if !validLangVersion(ver) {
			continue
		}
		if !set.add("composer", name, ver) {
			break
		}
	}
	return set.out
}

// ParseGemspecName reads name and version from the file name of a Ruby
// specifications/<name>-<version>[-<platform>].gemspec. The name may hold
// "-"; the version is the first part that starts with a digit and holds
// only version characters.
func ParseGemspecName(file string) (inventory.Package, bool) {
	if i := strings.LastIndexAny(file, `/\`); i >= 0 {
		file = file[i+1:]
	}
	base, ok := strings.CutSuffix(file, ".gemspec")
	if !ok || base == "" {
		return inventory.Package{}, false
	}
	parts := strings.Split(base, "-")
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if p == "" || p[0] < '0' || p[0] > '9' || !asciiName(p, maxLangVersion, ".") {
			continue
		}
		name := strings.Join(parts[:i], "-")
		if !asciiName(name, maxLangName, "-_.") {
			return inventory.Package{}, false
		}
		return inventory.Package{Manager: "gem", Name: name, Version: p}, true
	}
	return inventory.Package{}, false
}

// ParseDepsJSON reads the NuGet packages of a .NET *.deps.json: the keys
// "Name/Version" of "libraries" whose type is "package". Projects and
// reference assemblies are left out.
func ParseDepsJSON(b []byte) []inventory.Package {
	if len(b) > maxLangJSON {
		return nil
	}
	var deps struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &deps) != nil {
		return nil
	}
	keys := make([]string, 0, len(deps.Libraries))
	for k, lib := range deps.Libraries {
		if lib.Type == "package" {
			keys = append(keys, k)
		}
	}
	// Sorted, so the cap always keeps the same packages.
	sort.Strings(keys)
	var set langSet
	for _, k := range keys {
		name, ver, ok := strings.Cut(k, "/")
		if !ok || !asciiName(name, maxLangName, "-_.") || strings.Contains(ver, "/") || !validLangVersion(ver) {
			continue
		}
		if !set.add("nuget", name, ver) {
			break
		}
	}
	return set.out
}

// jarScan carries the budgets shared by an archive and those nested in it.
type jarScan struct {
	set     langSet
	entries int
	pom     int64
	nested  int64
}

// ParseJAR reads the Maven coordinates of a .jar, .war or .ear: every
// META-INF/maven/<group>/<artifact>/pom.properties, also inside the jars of
// WEB-INF/lib/ and BOOT-INF/lib/ (one level deep). Nothing is extracted;
// entry names are only compared.
func ParseJAR(r io.ReaderAt, size int64) []inventory.Package {
	var s jarScan
	s.walk(r, size, 0)
	return s.set.out
}

func (s *jarScan) walk(r io.ReaderAt, size int64, depth int) {
	if !zipDirectoryOK(r, size) {
		return
	}
	zr, err := zip.NewReader(r, size)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return
	}
	if zr == nil || len(zr.File) > maxZipEntries || s.entries+len(zr.File) > maxZipEntriesTotal {
		return
	}
	s.entries += len(zr.File)
	for _, f := range zr.File {
		if s.set.full() {
			return
		}
		switch {
		case isPomProperties(f.Name):
			s.pomProperties(f)
		case depth == 0 && isNestedJar(f.Name):
			s.nestedJar(f, depth)
		}
	}
}

// isPomProperties matches META-INF/maven/<group>/<artifact>/pom.properties.
func isPomProperties(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 5 && parts[0] == "META-INF" && parts[1] == "maven" && parts[2] != "" && parts[3] != "" && parts[4] == "pom.properties"
}

func isNestedJar(name string) bool {
	return (strings.HasPrefix(name, "WEB-INF/lib/") || strings.HasPrefix(name, "BOOT-INF/lib/")) && strings.HasSuffix(strings.ToLower(name), ".jar")
}

// readEntry reads a whole entry of at most limit bytes; the declared size
// is checked first and the read is capped, since the declaration may lie.
// charged is independent of valid content: a failed ZIP read can consume
// decompression work without returning those bytes to its caller.
func readEntry(f *zip.File, limit int64) (data []byte, charged int64, ok bool) {
	if f.UncompressedSize64 > uint64(limit) { //nolint:gosec // G115: limit is a positive constant
		return nil, 0, false
	}
	rc, err := f.Open()
	if err != nil {
		return nil, 0, false
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil || int64(len(b)) > limit {
		// Charge the whole attempted allowance, including for size lies:
		// archive/zip may return zero bytes after detecting one internally.
		// The single overflow-probe byte never starts another entry.
		return nil, limit, false
	}
	return b, int64(len(b)), true
}

func (s *jarScan) pomProperties(f *zip.File) {
	if s.pom >= maxPomTotal {
		return
	}
	b, charged, ok := readEntry(f, min(maxPomProperties, maxPomTotal-s.pom))
	s.pom += charged
	if !ok {
		return
	}
	props := parseProperties(b)
	group, artifact, ver := props["groupId"], props["artifactId"], props["version"]
	if !asciiName(group, maxLangName, "-_.") || !asciiName(artifact, maxLangName, "-_.") || !validLangVersion(ver) {
		return
	}
	name := group + ":" + artifact
	if len(name) > maxLangName {
		return
	}
	s.set.add("maven", name, ver)
}

func (s *jarScan) nestedJar(f *zip.File, depth int) {
	if s.nested >= maxNestedTotal {
		return
	}
	b, charged, ok := readEntry(f, min(maxNestedJar, maxNestedTotal-s.nested))
	s.nested += charged
	if !ok {
		return
	}
	s.walk(bytes.NewReader(b), int64(len(b)), depth+1)
}

// parseProperties reads the key=value, key:value and "key value" lines of
// a Java properties file. Comments ("#", "!") are skipped; escapes and
// continued lines are not needed for pom.properties and are not decoded.
func parseProperties(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxPomProperties+1)
	for sc.Scan() {
		line := strings.TrimLeft(strings.TrimRight(sc.Text(), "\r"), " \t\f")
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		i := strings.IndexAny(line, "=: \t\f")
		if i <= 0 {
			continue
		}
		k := line[:i]
		v := strings.TrimLeft(line[i:], " \t\f")
		if v != "" && (v[0] == '=' || v[0] == ':') {
			v = v[1:]
		}
		if _, dup := out[k]; !dup {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// zipDirectoryOK checks the end of central directory record before
// archive/zip reads the directory whole: the entry count and directory size
// must be within bounds.
func zipDirectoryOK(r io.ReaderAt, size int64) bool {
	const eocdLen, maxComment = 22, 0xffff
	if size < eocdLen {
		return false
	}
	tail := min(size, eocdLen+maxComment)
	buf := make([]byte, tail)
	if _, err := r.ReadAt(buf, size-tail); err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	at := -1
	for i := len(buf) - eocdLen; i >= 0; i-- {
		if buf[i] == 'P' && buf[i+1] == 'K' && buf[i+2] == 5 && buf[i+3] == 6 {
			// The comment must end where the file ends, as archive/zip
			// expects.
			if i+eocdLen+int(binary.LittleEndian.Uint16(buf[i+20:])) <= len(buf) {
				at = i
				break
			}
		}
	}
	if at < 0 {
		return false
	}
	entries := uint64(binary.LittleEndian.Uint16(buf[at+10:]))
	dirSize := uint64(binary.LittleEndian.Uint32(buf[at+12:]))
	if entries == 0xffff || dirSize == 0xffffffff {
		// Zip64: the locator sits right before the record.
		loc := at - 20
		if loc < 0 || !bytes.Equal(buf[loc:loc+4], []byte("PK\x06\x07")) {
			return false
		}
		off := binary.LittleEndian.Uint64(buf[loc+8:])
		if size < 56 || off > uint64(size-56) { //nolint:gosec // G115: size is at least 56 here
			return false
		}
		rec := make([]byte, 56)
		if _, err := r.ReadAt(rec, int64(off)); err != nil && !errors.Is(err, io.EOF) { //nolint:gosec // G115: off is below size
			return false
		}
		if !bytes.Equal(rec[:4], []byte("PK\x06\x06")) {
			return false
		}
		entries = binary.LittleEndian.Uint64(rec[32:])
		dirSize = binary.LittleEndian.Uint64(rec[40:])
	}
	return entries <= maxZipEntries && dirSize <= maxZipDirectory
}

// ParseCargoAuditable reads the dependency list cargo-auditable embeds in
// a Rust ELF binary: zlib-compressed JSON in the section ".dep-v0". Only
// crates from crates.io are returned, the root package included when it
// is one. Anything that is not such a binary gives nil.
func ParseCargoAuditable(r io.ReaderAt) (out []inventory.Package) {
	// debug/elf reads attacker-controlled headers; a parser bug must not
	// take the scan down.
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	f, err := elf.NewFile(r)
	if err != nil {
		return nil
	}
	sec := f.Section(".dep-v0")
	if sec == nil || sec.Type == elf.SHT_NOBITS || sec.Size == 0 || sec.Size > maxCargoAuditable {
		return nil
	}
	compressed, err := io.ReadAll(io.LimitReader(sec.Open(), maxCargoAuditable+1))
	if err != nil || len(compressed) > maxCargoAuditable {
		return nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil
	}
	defer func() { _ = zr.Close() }()
	raw, err := io.ReadAll(io.LimitReader(zr, maxCargoAuditable+1))
	if err != nil || len(raw) > maxCargoAuditable {
		return nil
	}
	var deps struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Source  string `json:"source"`
		} `json:"packages"`
	}
	if json.Unmarshal(raw, &deps) != nil {
		return nil
	}
	var set langSet
	for _, p := range deps.Packages {
		if p.Source != "crates.io" || !asciiName(p.Name, 64, "-_") || !validLangVersion(p.Version) {
			continue
		}
		if !set.add("cargo", p.Name, p.Version) {
			break
		}
	}
	return set.out
}
