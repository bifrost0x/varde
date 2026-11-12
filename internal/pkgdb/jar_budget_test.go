// SPDX-License-Identifier: Apache-2.0

package pkgdb

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"hash/crc32"
	"testing"
)

// Both rejected CRCs and understated sizes must spend the shared budget.
// Starting near the cap exercises the real limits with small fixtures.
func TestJARFailedEntriesConsumeSharedBudgets(t *testing.T) {
	for _, kind := range []string{"pom", "nested"} {
		for _, invalid := range []string{"crc", "size"} {
			t.Run(kind+"/"+invalid, func(t *testing.T) {
				name := "META-INF/maven/g/bad/pom.properties"
				payload := bytes.Repeat([]byte("x"), 512)
				if kind == "nested" {
					name = "BOOT-INF/lib/bad.jar"
				}
				bad := invalidJAREntry(t, name, payload, invalid)
				zr, err := zip.NewReader(bytes.NewReader(bad), int64(len(bad)))
				if err != nil {
					t.Fatal(err)
				}
				var s jarScan
				if kind == "pom" {
					s.pom = maxPomTotal - 512
					s.pomProperties(zr.File[0])
					if s.pom < maxPomTotal {
						t.Errorf("failed POM read did not exhaust remaining budget: %d", s.pom)
					}
				} else {
					s.nested = maxNestedTotal - 512
					s.nestedJar(zr.File[0], 0)
					if s.nested < maxNestedTotal {
						t.Errorf("failed nested read did not exhaust remaining budget: %d", s.nested)
					}
				}
				// A second bad entry and then valid metadata must not be read
				// after the first attempt exhausts the shared budget.
				if kind == "pom" {
					s.pomProperties(zr.File[0])
				} else {
					s.nestedJar(zr.File[0], 0)
				}
				good := buildZip(t, zipEntry{name: "META-INF/maven/g/good/pom.properties", data: pom("g", "good", "1.0")})
				if kind == "nested" {
					good = buildZip(t, zipEntry{name: "WEB-INF/lib/good.jar", data: good})
				}
				s.walk(bytes.NewReader(good), int64(len(good)), 0)
				if len(s.set.out) != 0 {
					t.Fatalf("read after budget exhaustion: %+v", s.set.out)
				}
			})
		}
	}
}

func TestJARValidEntriesStillUseActualSize(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "pom", true: "nested"}[nested], func(t *testing.T) {
			data := buildZip(t, zipEntry{name: "META-INF/maven/g/good/pom.properties", data: pom("g", "good", "1.0")})
			var s jarScan
			if nested {
				s.nested = maxNestedTotal - int64(len(data))
				data = buildZip(t, zipEntry{name: "BOOT-INF/lib/good.jar", data: data})
			} else {
				s.pom = maxPomTotal - int64(len(pom("g", "good", "1.0")))
			}
			s.walk(bytes.NewReader(data), int64(len(data)), 0)
			wantPkgs(t, pkgMap(t, "maven", s.set.out), map[string]string{"g:good": "1.0"})
		})
	}
}

func invalidJAREntry(t *testing.T, name string, payload []byte, invalid string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	fw, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	h := &zip.FileHeader{Name: name, Method: zip.Deflate, CRC32: crc32.ChecksumIEEE(payload),
		CompressedSize64: uint64(compressed.Len()), UncompressedSize64: uint64(len(payload))}
	if invalid == "crc" {
		h.CRC32 ^= 1
	} else {
		h.UncompressedSize64 = 1
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	w, err := zw.CreateRaw(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(compressed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
