// SPDX-License-Identifier: Apache-2.0

package pkgdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// RPMDBFiles are the paths of the SQLite package database rpm uses since
// version 4.16 (RHEL 9 and its rebuilds, Fedora, openSUSE). The older
// Berkeley DB and NDB formats are not read.
var RPMDBFiles = []string{"/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite"}

// ErrRPMDB is returned for a database Varde cannot read.
var ErrRPMDB = errors.New("rpmdb: unreadable")

// Bounds of the reader. The database comes from an image, so it is
// untrusted: every page number, length and count is checked, and the walk
// is bounded in pages and depth.
const (
	maxRPMPages    = 1 << 16
	maxRPMDepth    = 16
	maxRPMPackages = 20000
	// maxPayload bounds one row; a package header is rarely above 1 MB.
	maxPayload = 64 << 20
)

// RPM parses an rpmdb.sqlite file and adds its packages. It reads the SQLite
// file format directly, only the table Packages, and never runs SQL on it.
func (p *Parser) RPM(db []byte) error {
	blobs, err := sqliteTable(db, "Packages")
	if err != nil {
		return err
	}
	for _, b := range blobs {
		h, ok := rpmHeader(b)
		if !ok || h.name == "gpg-pubkey" || h.version == "" {
			continue
		}
		p.add("rpm", h.name, h.epoch+":"+h.version+"-"+h.release, rpmSource(h.sourceRPM))
		if len(p.packages) >= maxRPMPackages {
			break
		}
	}
	return nil
}

// rpmSource is the source package name of a SOURCERPM value
// ("openssl-3.0.7-27.el9.src.rpm" → "openssl").
func rpmSource(s string) string {
	s = strings.TrimSuffix(s, ".src.rpm")
	for range 2 {
		i := strings.LastIndexByte(s, '-')
		if i <= 0 {
			return ""
		}
		s = s[:i]
	}
	return s
}

type rpmPkg struct{ name, version, release, epoch, sourceRPM string }

// RPM header tags and types (rpm's lib/rpmtag.h).
const (
	tagName      = 1000
	tagVersion   = 1001
	tagRelease   = 1002
	tagEpoch     = 1003
	tagSourceRPM = 1044
	typeInt32    = 4
	typeString   = 6
)

// rpmHeader reads an rpm header blob as rpmdb stores it: the index count
// and data length, the index entries, then the data.
func rpmHeader(b []byte) (rpmPkg, bool) {
	if len(b) < 8 {
		return rpmPkg{}, false
	}
	il, dl := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
	if il == 0 || il > 1<<16 || uint64(dl) > uint64(len(b)) || 8+uint64(il)*16+uint64(dl) > uint64(len(b)) {
		return rpmPkg{}, false
	}
	data := b[8+il*16 : 8+il*16+dl]
	pkg := rpmPkg{epoch: "0"}
	for i := uint32(0); i < il; i++ {
		e := b[8+i*16:]
		tag, typ, off := binary.BigEndian.Uint32(e), binary.BigEndian.Uint32(e[4:]), binary.BigEndian.Uint32(e[8:])
		if int64(off) >= int64(len(data)) {
			continue
		}
		switch {
		case typ == typeString && (tag == tagName || tag == tagVersion || tag == tagRelease || tag == tagSourceRPM):
			end := bytes.IndexByte(data[off:], 0)
			if end < 0 || end > 512 {
				continue
			}
			v := string(data[off : off+uint32(end)])
			switch tag {
			case tagName:
				pkg.name = v
			case tagVersion:
				pkg.version = v
			case tagRelease:
				pkg.release = v
			case tagSourceRPM:
				pkg.sourceRPM = v
			}
		case typ == typeInt32 && tag == tagEpoch && int64(off)+4 <= int64(len(data)):
			pkg.epoch = strconv.FormatUint(uint64(binary.BigEndian.Uint32(data[off:])), 10)
		}
	}
	return pkg, pkg.name != "" && pkg.release != ""
}

// sqliteTable returns the last column of every row of a table, read from
// the bytes of an SQLite database (https://sqlite.org/fileformat.html).
func sqliteTable(db []byte, table string) ([][]byte, error) {
	if len(db) < 100 || string(db[:16]) != "SQLite format 3\x00" {
		return nil, fmt.Errorf("%w: not an SQLite database", ErrRPMDB)
	}
	size := int(binary.BigEndian.Uint16(db[16:]))
	if size == 1 {
		size = 65536
	}
	if size < 512 || size&(size-1) != 0 {
		return nil, fmt.Errorf("%w: page size %d", ErrRPMDB, size)
	}
	usable := size - int(db[20])
	if usable < 480 {
		return nil, fmt.Errorf("%w: usable size %d", ErrRPMDB, usable)
	}
	r := &sqliteReader{db: db, size: size, usable: usable, seen: map[uint32]bool{}}
	// rpm stores every package once; a valid file never reads more than
	// itself.
	// The schema is the table on page 1: type, name, tbl_name, rootpage, sql.
	var root uint32
	err := r.walk(1, 0, func(rec []byte) bool {
		cols := record(rec)
		if len(cols) >= 4 && string(cols[0].text) == "table" && string(cols[1].text) == table && cols[3].isInt {
			if cols[3].i > 0 && cols[3].i <= int64(len(db)/size) {
				root = uint32(cols[3].i) //nolint:gosec // G115: at most the page count of the file
			}
			return false
		}
		return true
	})
	if err != nil && !errors.Is(err, errStop) {
		return nil, err
	}
	if root == 0 {
		return nil, fmt.Errorf("%w: no table %s", ErrRPMDB, table)
	}
	var out [][]byte
	r.seen = map[uint32]bool{}
	err = r.walk(root, 0, func(rec []byte) bool {
		cols := record(rec)
		if len(cols) > 0 && cols[len(cols)-1].blob != nil {
			out = append(out, cols[len(cols)-1].blob)
		}
		return len(out) < maxRPMPackages
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	return out, err
}

type sqliteReader struct {
	db           []byte
	size, usable int
	seen         map[uint32]bool
	// cells and read count what the walk decoded: cells may point at the
	// same bytes many times, so the work is bounded, not only the pages.
	cells, read int
}

func (r *sqliteReader) page(n uint32) ([]byte, error) {
	if n == 0 || int64(n)*int64(r.size) > int64(len(r.db)) {
		return nil, fmt.Errorf("%w: page %d out of range", ErrRPMDB, n)
	}
	if r.seen[n] || len(r.seen) >= maxRPMPages {
		return nil, fmt.Errorf("%w: page %d revisited or too many pages", ErrRPMDB, n)
	}
	r.seen[n] = true
	return r.db[int(n-1)*r.size : int(n)*r.size], nil
}

// walk visits the rows of a table b-tree in order; visit returns false to
// stop.
func (r *sqliteReader) walk(n uint32, depth int, visit func([]byte) bool) error {
	if depth > maxRPMDepth {
		return fmt.Errorf("%w: b-tree too deep", ErrRPMDB)
	}
	pg, err := r.page(n)
	if err != nil {
		return err
	}
	hdr := 0
	if n == 1 {
		hdr = 100
	}
	if len(pg) < hdr+12 {
		return fmt.Errorf("%w: short page", ErrRPMDB)
	}
	kind, cells := pg[hdr], int(binary.BigEndian.Uint16(pg[hdr+3:]))
	ptrs := hdr + 8
	if kind == 0x05 {
		ptrs = hdr + 12
	}
	if ptrs+2*cells > len(pg) {
		return fmt.Errorf("%w: cell pointers out of range", ErrRPMDB)
	}
	for i := 0; i < cells; i++ {
		if r.cells++; r.cells > 4*maxRPMPackages {
			return fmt.Errorf("%w: too many cells", ErrRPMDB)
		}
		off := int(binary.BigEndian.Uint16(pg[ptrs+2*i:]))
		if off < ptrs || off >= r.usable {
			return fmt.Errorf("%w: cell out of range", ErrRPMDB)
		}
		switch kind {
		case 0x05: // interior: left child, rowid
			if off+4 > len(pg) {
				return fmt.Errorf("%w: cell out of range", ErrRPMDB)
			}
			if err := r.walk(binary.BigEndian.Uint32(pg[off:]), depth+1, visit); err != nil {
				return err
			}
		case 0x0d: // leaf: payload size, rowid, payload
			rec, err := r.payload(pg, off)
			if err != nil {
				return err
			}
			if !visit(rec) {
				return errStop
			}
		default:
			return fmt.Errorf("%w: page type %#x", ErrRPMDB, kind)
		}
	}
	if kind == 0x05 {
		return r.walk(binary.BigEndian.Uint32(pg[hdr+8:]), depth+1, visit)
	}
	return nil
}

// errStop ends a walk early; callers treat it as success.
var errStop = errors.New("stop")

// payload returns the record of a leaf cell, following overflow pages.
func (r *sqliteReader) payload(pg []byte, off int) ([]byte, error) {
	size, n := varint(pg[off:])
	if n == 0 {
		return nil, fmt.Errorf("%w: bad payload size", ErrRPMDB)
	}
	off += n
	_, n = varint(pg[off:])
	if n == 0 {
		return nil, fmt.Errorf("%w: bad rowid", ErrRPMDB)
	}
	off += n
	if size > maxPayload {
		return nil, fmt.Errorf("%w: payload too large", ErrRPMDB)
	}
	total := int(size) //nolint:gosec // G115: at most maxPayload
	if total > len(r.db) || r.read+total > 2*len(r.db) {
		return nil, fmt.Errorf("%w: payload too large", ErrRPMDB)
	}
	r.read += total
	u := r.usable
	x := u - 35
	local := total
	if total > x {
		m := (u-12)*32/255 - 23
		local = m + (total-m)%(u-4)
		if local > x {
			local = m
		}
	}
	if off+local > len(pg) || (local < total && off+local+4 > len(pg)) {
		return nil, fmt.Errorf("%w: payload out of page", ErrRPMDB)
	}
	out := make([]byte, 0, total)
	out = append(out, pg[off:off+local]...)
	if local == total {
		return out, nil
	}
	next := binary.BigEndian.Uint32(pg[off+local:])
	for len(out) < total {
		ov, err := r.page(next)
		if err != nil {
			return nil, err
		}
		take := min(total-len(out), u-4)
		out = append(out, ov[4:4+take]...)
		next = binary.BigEndian.Uint32(ov)
	}
	return out, nil
}

type column struct {
	isInt bool
	i     int64
	text  []byte
	blob  []byte
}

// record decodes an SQLite record; it returns nil for a malformed one.
func record(rec []byte) []column {
	h, n := varint(rec)
	if n == 0 || h > maxPayload {
		return nil
	}
	hlen := int(h) //nolint:gosec // G115: at most maxPayload
	if hlen > len(rec) || hlen < n {
		return nil
	}
	var types []uint64
	for p := n; p < hlen; {
		t, m := varint(rec[p:hlen])
		if m == 0 || len(types) > 64 {
			return nil
		}
		types = append(types, t)
		p += m
	}
	body := rec[hlen:]
	var cols []column
	for _, t := range types {
		var c column
		var w int
		switch {
		case t == 0:
			// NULL, as the rowid alias column is stored.
		case t == 8 || t == 9:
			c.isInt, c.i = true, int64(t-8)
		case t >= 1 && t <= 6:
			w = intWidth(t)
			if w > len(body) {
				return nil
			}
			var v int64
			for _, b := range body[:w] {
				v = v<<8 | int64(b)
			}
			if body[0]&0x80 != 0 && w < 8 {
				v -= 1 << (8 * w)
			}
			c.isInt, c.i = true, v
		case t == 7:
			w = 8
		case t >= 12 && t <= maxPayload:
			w = int((t - 12) / 2) //nolint:gosec // G115: t is at most maxPayload
			if w > len(body) {
				return nil
			}
			if t%2 == 0 {
				c.blob = body[:w]
			} else {
				c.text = body[:w]
			}
		default:
			return nil
		}
		if w > len(body) {
			return nil
		}
		body = body[w:]
		cols = append(cols, c)
	}
	return cols
}

// varint reads an SQLite variable-length integer; n is 0 when b is short.
func varint(b []byte) (v uint64, n int) {
	for i := 0; i < 9; i++ {
		if i >= len(b) {
			return 0, 0
		}
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return v, 9
}

// intWidth is the byte width of the integer serial types 1 to 6.
func intWidth(t uint64) int {
	switch t {
	case 5:
		return 6
	case 6:
		return 8
	}
	return int(t) //nolint:gosec // G115: t is 1 to 4
}
