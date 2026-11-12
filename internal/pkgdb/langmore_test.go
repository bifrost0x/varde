// SPDX-License-Identifier: Apache-2.0

package pkgdb

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

func pkgMap(t *testing.T, manager string, pkgs []inventory.Package) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, p := range pkgs {
		if p.Manager != manager {
			t.Fatalf("manager %q, want %q", p.Manager, manager)
		}
		if p.Path != "" {
			t.Fatalf("path set: %q", p.Path)
		}
		got[p.Name] = p.Version
	}
	return got
}

func wantPkgs(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
}

func TestParsePythonMetadata(t *testing.T) {
	meta := "Metadata-Version: 2.1\r\nName: Flask_SQLAlchemy\r\nVersion: 3.1.1\r\nSummary: Adds SQLAlchemy\r\nLicense: BSD\r\n  continued line\r\nRequires-Dist: flask>=2.2.5\r\n\r\nName: other\nVersion: 9.9\n"
	p, ok := ParsePythonMetadata([]byte(meta))
	if !ok || p != (inventory.Package{Manager: "pip", Name: "flask-sqlalchemy", Version: "3.1.1"}) {
		t.Fatalf("got %+v %v", p, ok)
	}
	pkgInfo := "\xef\xbb\xbfMetadata-Version: 1.0\nname: zope.interface\nversion: 6.1\n"
	if p, ok := ParsePythonMetadata([]byte(pkgInfo)); !ok || p.Name != "zope-interface" || p.Version != "6.1" {
		t.Fatalf("PKG-INFO: %+v %v", p, ok)
	}
	// The body is never read, however large.
	big := "Name: requests\nVersion: 2.31.0\n\n" + strings.Repeat("x", 2*maxPythonHeader)
	if p, ok := ParsePythonMetadata([]byte(big)); !ok || p.Name != "requests" {
		t.Fatalf("long body: %+v %v", p, ok)
	}
}

func TestNormalizePythonName(t *testing.T) {
	for in, want := range map[string]string{
		"Django":            "django",
		"ruamel.yaml":       "ruamel-yaml",
		"typing_extensions": "typing-extensions",
		"Foo-_.Bar":         "foo-bar",
		"a__b..c--d":        "a-b-c-d",
		"PyYAML":            "pyyaml",
		"x":                 "x",
	} {
		if got, ok := normalizePythonName(in); !ok || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "-foo", "foo.", "foo bar", "foo/bar", "fö", strings.Repeat("a", 215), "a\x00b"} {
		if got, ok := normalizePythonName(in); ok {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestParsePythonMetadataHostile(t *testing.T) {
	for name, in := range map[string]string{
		"empty":         "",
		"no version":    "Name: requests\n",
		"no name":       "Version: 1.0\n",
		"version space": "Name: a\nVersion: 1.0 beta\n",
		"control":       "Name: a\nVersion: 1.0\x1b[31m\n",
		"long version":  "Name: a\nVersion: " + strings.Repeat("1", 129) + "\n",
		"after header":  "Metadata-Version: 2.1\n\nName: a\nVersion: 1.0\n",
		"huge header":   "Name: a\nVersion: 1.0\n" + strings.Repeat("X-Junk: y\n", maxPythonHeader/10+1),
		"garbage":       "\x00\xff\xfe\x01binary",
		"invalid utf8":  "Name: a\nVersion: 1.\xff\n",
	} {
		if p, ok := ParsePythonMetadata([]byte(in)); ok {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

func TestParseComposerInstalled(t *testing.T) {
	v2 := `{"packages":[
	  {"name":"Symfony/Console","version":"v6.4.3","version_normalized":"6.4.3.0"},
	  {"name":"monolog/monolog","version":"3.5.0"},
	  {"name":"acme/tool","version":"dev-main"},
	  {"name":"acme/next","version":"2.x-dev"},
	  {"name":"no-vendor","version":"1.0.0"},
	  {"name":"bad/na me","version":"1.0.0"},
	  {"name":"ok/empty","version":""},
	  {"name":"guzzlehttp/guzzle","version":"7.8.1"},
	  {"name":"guzzlehttp/guzzle","version":"7.8.1"}],
	  "dev":true,"dev-package-names":[]}`
	wantPkgs(t, pkgMap(t, "composer", ParseComposerInstalled([]byte(v2))), map[string]string{
		"symfony/console": "6.4.3", "monolog/monolog": "3.5.0", "guzzlehttp/guzzle": "7.8.1",
	})
	v1 := `[{"name":"psr/log","version":"1.1.4"},{"name":"twig/twig","version":"v3.8.0"}]`
	wantPkgs(t, pkgMap(t, "composer", ParseComposerInstalled([]byte(v1))), map[string]string{
		"psr/log": "1.1.4", "twig/twig": "3.8.0",
	})
	for name, in := range map[string]string{
		"garbage":   "not json",
		"truncated": v2[:len(v2)/2],
		"wrong":     `{"packages":"x"}`,
		"oversized": `[` + strings.Repeat(" ", maxLangJSON) + `]`,
	} {
		if got := ParseComposerInstalled([]byte(in)); got != nil {
			t.Errorf("%s: %v", name, got)
		}
	}
	var sb strings.Builder
	sb.WriteString(`[`)
	for i := range 6000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"name":"v/p%d","version":"1.0.%d"}`, i, i)
	}
	sb.WriteString(`]`)
	if got := ParseComposerInstalled([]byte(sb.String())); len(got) != maxLangPackages {
		t.Fatalf("cap: %d", len(got))
	}
}

func TestParseGemspecName(t *testing.T) {
	for in, want := range map[string][2]string{
		"net-http-0.4.1.gemspec":                          {"net-http", "0.4.1"},
		"nokogiri-1.16.2-x86_64-linux.gemspec":            {"nokogiri", "1.16.2"},
		"google-protobuf-3.25.1-x86_64-linux-gnu.gemspec": {"google-protobuf", "3.25.1"},
		"rack-3.0.9.1.gemspec":                            {"rack", "3.0.9.1"},
		"racc-1.7.3.gemspec":                              {"racc", "1.7.3"},
		"rails-7.1.0.rc1.gemspec":                         {"rails", "7.1.0.rc1"},
		"ffi-1.16.3-arm64-darwin.gemspec":                 {"ffi", "1.16.3"},
		"specifications/aws-sdk-s3-1.142.0.gemspec":       {"aws-sdk-s3", "1.142.0"},
		"sqlite3-1.7.2-x64-mingw-ucrt.gemspec":            {"sqlite3", "1.7.2"},
	} {
		p, ok := ParseGemspecName(in)
		if !ok || p != (inventory.Package{Manager: "gem", Name: want[0], Version: want[1]}) {
			t.Errorf("%q: got %+v %v", in, p, ok)
		}
	}
	for _, in := range []string{
		"", ".gemspec", "rack.gemspec", "rack-.gemspec", "rack-3.0.gemspec.bak",
		"-1.0.gemspec", "ra ck-1.0.gemspec", "rack-1.0_beta.gemspec", "rack-\x001.0.gemspec",
		strings.Repeat("a", 215) + "-1.0.gemspec", "rack-" + strings.Repeat("1", 129) + ".gemspec",
	} {
		if p, ok := ParseGemspecName(in); ok {
			t.Errorf("%q accepted as %+v", in, p)
		}
	}
}

func TestParseDepsJSON(t *testing.T) {
	deps := `{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},
	  "targets":{".NETCoreApp,Version=v8.0":{}},
	  "libraries":{
	    "MyApp/1.0.0":{"type":"project","serviceable":false,"sha512":""},
	    "Newtonsoft.Json/13.0.3":{"type":"package","serviceable":true,"sha512":"sha512-x","path":"newtonsoft.json/13.0.3"},
	    "System.Text.Json/8.0.0":{"type":"package"},
	    "Microsoft.NETCore.App.Ref/8.0.0":{"type":"referenceassembly"},
	    "Bad/Name/1.0":{"type":"package"},
	    "NoVersion":{"type":"package"},
	    "Spaced Name/1.0":{"type":"package"}}}`
	wantPkgs(t, pkgMap(t, "nuget", ParseDepsJSON([]byte(deps))), map[string]string{
		"Newtonsoft.Json": "13.0.3", "System.Text.Json": "8.0.0",
	})
	for name, in := range map[string]string{
		"garbage":   "\x00\x01",
		"truncated": deps[:100],
		"wrong":     `{"libraries":[]}`,
		"oversized": `{"libraries":{}` + strings.Repeat(" ", maxLangJSON) + `}`,
	} {
		if got := ParseDepsJSON([]byte(in)); got != nil {
			t.Errorf("%s: %v", name, got)
		}
	}
}

type zipEntry struct {
	name string
	data []byte
	// store writes the entry uncompressed, as Spring Boot does for nested
	// jars.
	store bool
}

func buildZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		method := zip.Deflate
		if e.store {
			method = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pom(group, artifact, version string) []byte {
	return []byte("#Generated by Maven\n#Mon Jan 01 00:00:00 UTC 2024\n! another comment\nartifactId=" + artifact + "\r\ngroupId: " + group + "\nversion " + version + "\n")
}

func parseJARBytes(b []byte) []inventory.Package {
	return ParseJAR(bytes.NewReader(b), int64(len(b)))
}

func TestParseJAR(t *testing.T) {
	inner := buildZip(t,
		zipEntry{name: "META-INF/MANIFEST.MF", data: []byte("Manifest-Version: 1.0\n")},
		zipEntry{name: "META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties", data: pom("com.fasterxml.jackson.core", "jackson-databind", "2.15.2")},
	)
	// A jar nested two levels deep is not read.
	deep := buildZip(t, zipEntry{name: "META-INF/maven/deep/deep/pom.properties", data: pom("deep", "deep", "1.0")})
	middle := buildZip(t,
		zipEntry{name: "META-INF/maven/org.yaml/snakeyaml/pom.properties", data: pom("org.yaml", "snakeyaml", "2.2")},
		zipEntry{name: "WEB-INF/lib/deep.jar", data: deep},
		zipEntry{name: "BOOT-INF/lib/deep.jar", data: deep},
	)
	war := buildZip(t,
		zipEntry{name: "META-INF/maven/com.example/app/pom.properties", data: pom("com.example", "app", "1.0.0")},
		zipEntry{name: "META-INF/maven/com.example/app/pom.xml", data: []byte("<project/>")},
		zipEntry{name: "META-INF/maven/a/b/c/pom.properties", data: pom("x", "y", "1")},
		zipEntry{name: "META-INF/maven/unresolved/unresolved/pom.properties", data: pom("unresolved", "unresolved", "${project.version}")},
		zipEntry{name: "META-INF/maven/missing/missing/pom.properties", data: []byte("groupId=missing\n")},
		zipEntry{name: "../../META-INF/maven/evil/evil/pom.properties", data: pom("evil", "evil", "6.6.6")},
		zipEntry{name: "WEB-INF/lib/jackson-databind-2.15.2.jar", data: inner},
		zipEntry{name: "BOOT-INF/lib/snakeyaml-2.2.JAR", data: middle, store: true},
		zipEntry{name: "lib/ignored.jar", data: deep},
		zipEntry{name: "WEB-INF/lib/broken.jar", data: []byte("not a zip")},
	)
	wantPkgs(t, pkgMap(t, "maven", parseJARBytes(war)), map[string]string{
		"com.example:app": "1.0.0",
		"com.fasterxml.jackson.core:jackson-databind": "2.15.2",
		"org.yaml:snakeyaml":                          "2.2",
	})
}

func TestParseJARHostile(t *testing.T) {
	valid := buildZip(t, zipEntry{name: "META-INF/maven/g/a/pom.properties", data: pom("g", "a", "1.0")})
	if len(parseJARBytes(valid)) != 1 {
		t.Fatal("valid jar not read")
	}
	// Every truncation and a flipped byte anywhere must not panic.
	for i := range len(valid) {
		_ = parseJARBytes(valid[:i])
		b := bytes.Clone(valid)
		b[i] ^= 0xff
		_ = parseJARBytes(b)
	}
	if parseJARBytes([]byte("garbage that is not a zip at all")) != nil {
		t.Error("garbage accepted")
	}
	// An oversized pom.properties is skipped by its declared size.
	big := buildZip(t, zipEntry{name: "META-INF/maven/g/a/pom.properties", data: append(pom("g", "a", "1.0"), make([]byte, maxPomProperties)...)})
	if got := parseJARBytes(big); got != nil {
		t.Errorf("oversized pom.properties: %v", got)
	}
	// A bomb that declares a small size but inflates to more is cut off.
	if got := parseJARBytes(lyingZip(t, "META-INF/maven/g/a/pom.properties", append(pom("g", "a", "1.0"), make([]byte, 4<<20)...))); got != nil {
		t.Errorf("lying size: %v", got)
	}
	// A nested jar over its cap is skipped.
	nestedBomb := buildZip(t, zipEntry{name: "WEB-INF/lib/bomb.jar", data: make([]byte, maxNestedJar+1)})
	if got := parseJARBytes(nestedBomb); got != nil {
		t.Errorf("nested bomb: %v", got)
	}
}

// lyingZip writes one deflated entry whose header understates its size.
func lyingZip(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var comp bytes.Buffer
	fw, err := flate.NewWriter(&comp, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name: name, Method: zip.Deflate, CRC32: crc32.ChecksumIEEE(data),
		CompressedSize64: uint64(comp.Len()), UncompressedSize64: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(comp.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseJAREntryCap(t *testing.T) {
	for _, n := range []int{maxZipEntries + 1, 70000} {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		if _, err := zw.Create("META-INF/maven/g/a/pom.properties"); err != nil {
			t.Fatal(err)
		}
		for i := range n - 1 {
			if _, err := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("f%d", i), Method: zip.Store}); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		// 70000 entries need the zip64 end record.
		if got := parseJARBytes(buf.Bytes()); got != nil {
			t.Errorf("%d entries: %v", n, got)
		}
	}
}

// buildELF writes a minimal little-endian ELF64 file with one section
// named name holding data, and the section name table.
func buildELF(name string, data []byte) []byte {
	shstr := "\x00" + name + "\x00.shstrtab\x00"
	const ehdr, shdr = 64, 64
	dataOff := uint64(ehdr)
	strOff := dataOff + uint64(len(data))
	shOff := strOff + uint64(len(shstr))
	var b bytes.Buffer
	le := binary.LittleEndian
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	b.Write(make([]byte, 8))
	_ = binary.Write(&b, le, uint16(2))  // ET_EXEC
	_ = binary.Write(&b, le, uint16(62)) // EM_X86_64
	_ = binary.Write(&b, le, uint32(1))
	_ = binary.Write(&b, le, uint64(0)) // entry
	_ = binary.Write(&b, le, uint64(0)) // phoff
	_ = binary.Write(&b, le, shOff)
	_ = binary.Write(&b, le, uint32(0))
	_ = binary.Write(&b, le, uint16(ehdr))
	_ = binary.Write(&b, le, uint16(56))
	_ = binary.Write(&b, le, uint16(0))
	_ = binary.Write(&b, le, uint16(shdr))
	_ = binary.Write(&b, le, uint16(3)) // shnum
	_ = binary.Write(&b, le, uint16(2)) // shstrndx
	b.Write(data)
	b.WriteString(shstr)
	section := func(nameOff, typ uint32, off, size uint64) {
		_ = binary.Write(&b, le, nameOff)
		_ = binary.Write(&b, le, typ)
		_ = binary.Write(&b, le, uint64(0)) // flags
		_ = binary.Write(&b, le, uint64(0)) // addr
		_ = binary.Write(&b, le, off)
		_ = binary.Write(&b, le, size)
		_ = binary.Write(&b, le, uint32(0))
		_ = binary.Write(&b, le, uint32(0))
		_ = binary.Write(&b, le, uint64(1))
		_ = binary.Write(&b, le, uint64(0))
	}
	section(0, 0, 0, 0)
	section(1, 1, dataOff, uint64(len(data)))                   // PROGBITS
	section(uint32(len(name))+2, 3, strOff, uint64(len(shstr))) // STRTAB
	return b.Bytes()
}

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseCargoAuditable(t *testing.T) {
	deps := `{"packages":[
	  {"name":"myapp","version":"0.1.0","source":"local","kind":"runtime","dependencies":[1,2],"root":true},
	  {"name":"serde","version":"1.0.197","source":"crates.io","kind":"runtime"},
	  {"name":"cc","version":"1.0.90","source":"crates.io","kind":"build"},
	  {"name":"forked","version":"0.2.0","source":"git"},
	  {"name":"bad name","version":"1.0.0","source":"crates.io"},
	  {"name":"tokio","version":"1.36.0","source":"crates.io"}]}`
	bin := buildELF(".dep-v0", zlibBytes(t, []byte(deps)))
	wantPkgs(t, pkgMap(t, "cargo", ParseCargoAuditable(bytes.NewReader(bin))), map[string]string{
		"serde": "1.0.197", "cc": "1.0.90", "tokio": "1.36.0",
	})
	root := `{"packages":[{"name":"ripgrep","version":"14.1.0","source":"crates.io","root":true}]}`
	wantPkgs(t, pkgMap(t, "cargo", ParseCargoAuditable(bytes.NewReader(buildELF(".dep-v0", zlibBytes(t, []byte(root)))))), map[string]string{
		"ripgrep": "14.1.0",
	})
	// Every truncation and a flipped byte anywhere must not panic.
	for i := range len(bin) {
		_ = ParseCargoAuditable(bytes.NewReader(bin[:i]))
		b := bytes.Clone(bin)
		b[i] ^= 0xff
		_ = ParseCargoAuditable(bytes.NewReader(b))
	}
}

func TestParseCargoAuditableHostile(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":         nil,
		"not elf":       []byte("#!/bin/sh\necho hi\n"),
		"other section": buildELF(".data", zlibBytes(t, []byte(`{"packages":[{"name":"a","version":"1.0.0","source":"crates.io"}]}`))),
		"not zlib":      buildELF(".dep-v0", []byte(`{"packages":[]}`)),
		"not json":      buildELF(".dep-v0", zlibBytes(t, []byte("garbage"))),
		"truncated":     buildELF(".dep-v0", zlibBytes(t, []byte(`{"packages":[{"name":"a","version":"1.0.0","source":"crates.io"}]}`))[:20]),
		// A bomb: valid JSON padded past the decompression cap.
		"bomb": buildELF(".dep-v0", zlibBytes(t, append([]byte(`{"packages":[{"name":"a","version":"1.0.0","source":"crates.io"}]}`), bytes.Repeat([]byte(" "), maxCargoAuditable)...))),
	} {
		if got := ParseCargoAuditable(bytes.NewReader(in)); got != nil {
			t.Errorf("%s: %v", name, got)
		}
	}
}
