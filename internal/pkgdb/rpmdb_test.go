// SPDX-License-Identifier: Apache-2.0

package pkgdb

import (
	"os"
	"strings"
	"testing"
)

// seed is testdata/rpmdb.sqlite: a database with rpm's schema, written by
// SQLite itself (go test -tags rpmdbgen -run TestWriteSeed).
func seed(t testing.TB) []byte {
	t.Helper()
	db, err := os.ReadFile("testdata/rpmdb.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestRPMDB(t *testing.T) {
	var p Parser
	if err := p.RPM(seed(t)); err != nil {
		t.Fatal(err)
	}
	pkgs := p.Packages("almalinux-9.4")
	if len(pkgs) != 42 {
		t.Fatalf("%d packages", len(pkgs))
	}
	got := map[string]string{}
	for _, pk := range pkgs {
		got[pk.Name] = pk.Manager + " " + pk.Version + " " + pk.Source + " " + pk.Distro
	}
	if got["openssl-libs"] != "rpm 1:3.0.7-27.el9 openssl almalinux-9.4" {
		t.Fatalf("openssl-libs: %q", got["openssl-libs"])
	}
	// The source package equals the name: not repeated.
	if got["bash"] != "rpm 0:5.1.8-9.el9  almalinux-9.4" {
		t.Fatalf("bash: %q", got["bash"])
	}
	if _, ok := got["gpg-pubkey"]; ok {
		t.Fatal("gpg-pubkey is not a package")
	}
}

func TestRPMDBRejectsGarbage(t *testing.T) {
	var p Parser
	for _, b := range [][]byte{nil, []byte("not a database"), append([]byte("SQLite format 3\x00"), make([]byte, 200)...)} {
		if err := p.RPM(b); err == nil {
			t.Errorf("accepted %q", b[:min(len(b), 20)])
		}
	}
	// A truncated database fails cleanly.
	db := seed(t)
	if err := p.RPM(db[:len(db)/2]); err != nil && !strings.Contains(err.Error(), "rpmdb") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRPMSource(t *testing.T) {
	for in, want := range map[string]string{"openssl-3.0.7-27.el9.src.rpm": "openssl", "python3.11-3.11.7-1.el9.src.rpm": "python3.11", "x": "", "": ""} {
		if got := rpmSource(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// The reader never panics or loops on a corrupted database. The test
// binary does not link the SQLite driver: its coverage counters would slow
// fuzzing down to nothing.
func FuzzRPMDB(f *testing.F) {
	db := seed(f)
	f.Add(db)
	f.Add(db[:4096])
	f.Fuzz(func(_ *testing.T, b []byte) {
		var p Parser
		_ = p.RPM(b)
	})
}
