// SPDX-License-Identifier: Apache-2.0

package pkgdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestParseNPMLock(t *testing.T) {
	v3 := `{"lockfileVersion":3,"packages":{
	  "": {"name":"app","version":"1.0.0"},
	  "node_modules/express": {"version":"4.18.2"},
	  "node_modules/express/node_modules/qs": {"version":"6.11.0"},
	  "node_modules/@scope/x": {"version":"2.0.0-beta.1"},
	  "node_modules/jest": {"version":"29.0.0","dev":true},
	  "node_modules/local": {"version":"file:../local"},
	  "node_modules/linked": {"link":true},
	  "node_modules/alias": {"name":"lodash","version":"4.17.20"}}}`
	got := map[string]string{}
	for _, p := range ParseNPMLock([]byte(v3)) {
		if p.Manager != "npm" {
			t.Fatalf("manager %q", p.Manager)
		}
		got[p.Name] = p.Version
	}
	want := map[string]string{"express": "4.18.2", "qs": "6.11.0", "@scope/x": "2.0.0-beta.1", "lodash": "4.17.20"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	v1 := `{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}},"c":{"version":"1.0.0","dev":true}}}`
	if got := ParseNPMLock([]byte(v1)); len(got) != 2 {
		t.Fatalf("v1: %+v", got)
	}
	if got := ParseNPMLock([]byte("not json")); got != nil {
		t.Fatalf("garbage: %+v", got)
	}
}

// The test binary itself is a Go executable.
func TestScanGoBinarySelf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	f, err := os.Open(exe) //nolint:gosec // the running test binary
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = f.Close() }()
	bi, err := ScanGoBinary(f)
	if err != nil {
		t.Fatal(err)
	}
	if bi.GoVersion != runtime.Version() {
		t.Fatalf("go version %q, want %q", bi.GoVersion, runtime.Version())
	}
	if want, ok := goRelease(runtime.Version()); ok && (len(bi.Packages) == 0 || bi.Packages[0].Name != "stdlib" || bi.Packages[0].Version != want) {
		t.Fatalf("stdlib: %+v", bi.Packages)
	}
}

// buildInfo builds an inline build information block.
func buildInfo(goVersion, mod string) []byte {
	b := append([]byte(nil), buildInfoMagic...)
	b = append(b, 8, 0x2)
	b = append(b, make([]byte, 16)...)
	b = binary.AppendUvarint(b, uint64(len(goVersion)))
	b = append(b, goVersion...)
	framed := strings.Repeat("x", 16) + mod + strings.Repeat("y", 16)
	b = binary.AppendUvarint(b, uint64(len(framed)))
	return append(b, framed...)
}

func TestScanGoBinary(t *testing.T) {
	mod := "path\tgithub.com/traefik/traefik/v3/cmd/traefik\n" +
		"mod\tgithub.com/traefik/traefik/v3\tv3.1.2\th1:x=\n" +
		"dep\tgolang.org/x/net\tv0.25.0\th1:y=\n" +
		"dep\tgithub.com/old/thing\tv1.0.0\th1:z=\n=>\tgithub.com/new/thing\tv1.2.0\th1:w=\n" +
		"dep\texample.com/local\tv0.0.0\n=>\t../local\t\t\n"
	// A decoy (the magic inside a program that reads build information)
	// first, the real block across the 1 MiB chunk boundary.
	var stream bytes.Buffer
	stream.Write(buildInfoMagic)
	stream.WriteString("garbage that is no header at all....")
	stream.Write(make([]byte, 1<<20-stream.Len()-5))
	stream.Write(buildInfo("go1.22.5", mod))
	stream.Write(make([]byte, 4096))
	bi, err := ScanGoBinary(&stream)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range bi.Packages {
		got[p.Name] = p.Version
	}
	want := map[string]string{"stdlib": "1.22.5", "github.com/traefik/traefik/v3": "v3.1.2", "golang.org/x/net": "v0.25.0", "github.com/new/thing": "v1.2.0"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	if _, err := ScanGoBinary(strings.NewReader("#!/bin/sh\nexec traefik\n")); !errors.Is(err, ErrNotGo) {
		t.Fatalf("script: %v", err)
	}
}

func TestGoRelease(t *testing.T) {
	for in, want := range map[string]string{"go1.22.5": "1.22.5", "go1.22.5 X:boringcrypto": "1.22.5", "go1.23rc1": "", "devel go1.24-abc": ""} {
		if got, _ := goRelease(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func FuzzScanGoBinary(f *testing.F) {
	f.Add(buildInfo("go1.22.5", "path\tx\nmod\tx\tv1.0.0\t\n"))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = ScanGoBinary(bytes.NewReader(b))
	})
}
