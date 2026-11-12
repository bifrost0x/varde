// SPDX-License-Identifier: Apache-2.0

//go:build rpmdbgen

package pkgdb

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// header builds an rpm header blob as rpmdb stores it.
func header(name, version, release string, epoch int, srpm string, padding int) []byte {
	type entry struct {
		tag, typ uint32
		data     []byte
	}
	str := func(s string) []byte { return append([]byte(s), 0) }
	es := []entry{{tagName, typeString, str(name)}, {tagVersion, typeString, str(version)}, {tagRelease, typeString, str(release)}}
	if srpm != "" {
		es = append(es, entry{tagSourceRPM, typeString, str(srpm)})
	}
	if epoch > 0 {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(epoch))
		es = append(es, entry{tagEpoch, typeInt32, b})
	}
	// A large tag forces the row onto overflow pages.
	es = append(es, entry{1027, 8, make([]byte, padding)})
	var index, data []byte
	for _, e := range es {
		for len(data)%4 != 0 {
			data = append(data, 0)
		}
		ent := make([]byte, 16)
		binary.BigEndian.PutUint32(ent, e.tag)
		binary.BigEndian.PutUint32(ent[4:], e.typ)
		binary.BigEndian.PutUint32(ent[8:], uint32(len(data)))
		binary.BigEndian.PutUint32(ent[12:], 1)
		index = append(index, ent...)
		data = append(data, e.data...)
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out, uint32(len(es)))
	binary.BigEndian.PutUint32(out[4:], uint32(len(data)))
	return append(append(out, index...), data...)
}

// rpmdb writes an rpmdb.sqlite with the schema rpm uses.
func rpmdb(t testing.TB, n int) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rpmdb.sqlite")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, q := range []string{
		`CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)`,
		`CREATE TABLE Name (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL, FOREIGN KEY (hnum) REFERENCES Packages(hnum))`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	ins := func(b []byte) {
		if _, err := db.Exec(`INSERT INTO Packages (blob) VALUES (?)`, b); err != nil {
			t.Fatal(err)
		}
	}
	ins(header("gpg-pubkey", "fd431d51", "4ae0493b", 0, "", 0))
	ins(header("openssl-libs", "3.0.7", "27.el9", 1, "openssl-3.0.7-27.el9.src.rpm", 9000))
	ins(header("bash", "5.1.8", "9.el9", 0, "bash-5.1.8-9.el9.src.rpm", 100))
	for i := range n {
		ins(header(fmt.Sprintf("pkg%d", i), "1.0", "1.el9", 0, fmt.Sprintf("pkg%d-1.0-1.el9.src.rpm", i), 300))
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path) //nolint:gosec // test file in a temporary directory
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWriteSeed writes testdata/rpmdb.sqlite.
func TestWriteSeed(t *testing.T) {
	if err := os.WriteFile("testdata/rpmdb.sqlite", rpmdb(t, 40), 0o600); err != nil {
		t.Fatal(err)
	}
}
