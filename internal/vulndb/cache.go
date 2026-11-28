// SPDX-License-Identifier: Apache-2.0

package vulndb

import (
	"archive/zip"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/distro"
)

// line is one line of a cache file: the keys of the packages a record
// names, so that Select decodes only the records it keeps.
type line struct {
	Keys   []string        `json:"k"`
	Record json.RawMessage `json:"r"`
}

// maxLine bounds one line of a cache file.
const maxLine = 16 << 20

// maxUnpacked bounds a decompressed OVAL file.
const maxUnpacked = 1 << 30

// Stats describes a normalised dataset.
type Stats struct {
	Records  int
	Packages int
}

// Normalize reads the downloaded file of d at raw and writes its records
// to out as a compressed cache file, atomically. modified stamps records
// of formats that carry no dates.
func Normalize(d Dataset, raw, out string, modified time.Time) (Stats, error) {
	tmp, err := os.CreateTemp(filepath.Dir(out), ".tmp-*")
	if err != nil {
		return Stats{}, fmt.Errorf("vulndb %s: %w", d.Key, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	zw := gzip.NewWriter(tmp)
	bw := bufio.NewWriterSize(zw, 1<<20)
	enc := json.NewEncoder(bw)
	var st Stats
	pkgs := map[string]bool{}
	emit := func(r Record) error {
		keys := make([]string, 0, len(r.Vuln.Affected))
		if d.Format == FormatUbuntuCVE {
			keys = append(keys, cveKey(r.Vuln.ID))
		}
		seen := map[string]bool{}
		for _, a := range r.Vuln.Affected {
			if a.Package.Ecosystem == "" || a.Package.Name == "" {
				continue
			}
			k := Key(a.Package.Ecosystem, a.Package.Name)
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
				pkgs[k] = true
			}
		}
		if len(keys) == 0 {
			return nil
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		st.Records++
		return enc.Encode(line{Keys: keys, Record: raw})
	}
	if err := parseFile(d, raw, modified, emit); err != nil {
		_ = tmp.Close()
		return Stats{}, err
	}
	st.Packages = len(pkgs)
	if err := bw.Flush(); err != nil {
		_ = tmp.Close()
		return Stats{}, fmt.Errorf("vulndb %s: %w", d.Key, err)
	}
	if err := zw.Close(); err != nil {
		_ = tmp.Close()
		return Stats{}, fmt.Errorf("vulndb %s: %w", d.Key, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return Stats{}, fmt.Errorf("vulndb %s: %w", d.Key, err)
	}
	if err := tmp.Close(); err != nil {
		return Stats{}, fmt.Errorf("vulndb %s: %w", d.Key, err)
	}
	if st.Records == 0 {
		return Stats{}, fmt.Errorf("vulndb %s: no records in the file", d.Key)
	}
	if err := os.Rename(tmp.Name(), out); err != nil {
		return Stats{}, fmt.Errorf("vulndb %s: %w", d.Key, err)
	}
	return st, nil
}

func parseFile(d Dataset, raw string, modified time.Time, emit func(Record) error) error {
	if d.Format == FormatOSVZip {
		zr, err := zip.OpenReader(raw)
		if err != nil {
			return fmt.Errorf("vulndb %s: %w", d.Key, err)
		}
		defer func() { _ = zr.Close() }()
		return parseOSVZip(&zr.Reader, emit)
	}
	f, err := os.Open(raw) //nolint:gosec // path built by the caller inside the data directory
	if err != nil {
		return fmt.Errorf("vulndb %s: %w", d.Key, err)
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReaderSize(f, 1<<20)
	switch d.Format {
	case FormatDebian:
		return parseDebian(r, modified, emit)
	case FormatUbuntuOVAL:
		return parseUbuntuOVAL(io.LimitReader(bzip2.NewReader(r), maxUnpacked), d.Ecosystem, modified, emit)
	case FormatSecDB:
		return parseSecDB(r, d.Ecosystem, d.Prefix, modified, emit)
	case FormatUbuntuCVE:
		return parseUbuntuCVE(io.LimitReader(bzip2.NewReader(r), maxUnpacked), modified, emit)
	}
	return fmt.Errorf("vulndb %s: unknown format", d.Key)
}

// Selected is a record kept for one package: only the entries of that
// package are left in it, named as the package is installed.
type Selected struct {
	Vuln     advisory.Vulnerability
	CVSS     float64
	Severity string
}

// Select reads a cache file and adds the records of the wanted packages to
// into, keyed by the package's app ID (distro.SystemAppID).
func Select(path string, w *Wanted, into map[string][]Selected) error {
	f, err := os.Open(path) //nolint:gosec // path built by the caller inside the data directory
	if err != nil {
		return fmt.Errorf("vulndb: %w", err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return fmt.Errorf("vulndb %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = zr.Close() }()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		var l line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return fmt.Errorf("vulndb %s: %w", filepath.Base(path), err)
		}
		var hits []wantedPkg
		for _, k := range l.Keys {
			hits = append(hits, w.byKey[k]...)
		}
		if len(hits) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(l.Record, &rec); err != nil {
			return fmt.Errorf("vulndb %s: %w", filepath.Base(path), err)
		}
		// One record per app: an app with packages in two releases keeps
		// the entries of both in one record.
		byApp := map[string]*Selected{}
		var order []string
		for _, h := range hits {
			s, ok := selectFor(rec, h)
			if !ok {
				continue
			}
			if prev := byApp[h.appID]; prev != nil {
				for _, a := range s.Vuln.Affected {
					if !containsEntry(prev.Vuln.Affected, a) {
						prev.Vuln.Affected = append(prev.Vuln.Affected, a)
					}
				}
				continue
			}
			byApp[h.appID] = &s
			order = append(order, h.appID)
		}
		for _, app := range order {
			into[app] = append(into[app], *byApp[app])
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("vulndb %s: %w", filepath.Base(path), err)
	}
	return nil
}

// selectFor trims rec to the entries of the wanted package.
func selectFor(rec Record, h wantedPkg) (Selected, bool) {
	eco := h.ecosystem
	v := rec.Vuln
	v.Affected = nil
	system := strings.HasPrefix(h.appID, distro.SystemPrefix)
	for _, a := range rec.Vuln.Affected {
		if CanonicalName(a.Package.Ecosystem, a.Package.Name) != CanonicalName(eco, h.name) {
			continue
		}
		if !distro.SameRelease(a.Package.Ecosystem, eco, time.Now()) {
			continue
		}
		if u, _ := a.EcosystemSpecific["urgency"].(string); system && strings.EqualFold(u, "unimportant") {
			// Debian does not count it as a security issue of this
			// package; the system packages leave it out, as the osv.dev
			// source does (sources.SystemPackages).
			continue
		}
		// The matcher compares names exactly: the entry takes the name
		// the package is installed under.
		a.Package.Name = h.name
		v.Affected = append(v.Affected, a)
	}
	if len(v.Affected) == 0 {
		return Selected{}, false
	}
	s := Selected{Vuln: v, CVSS: rec.CVSS, Severity: rec.Severity}
	if s.Severity == "" && strings.HasPrefix(v.ID, "DEBIAN-") {
		s.Severity = debianSeverity(v.Affected)
	}
	return s, true
}

// Tidy orders the selected records of each package by ID, so that equal
// data compares equal, and merges records of one ID: osv.dev exports a
// record that names packages of several ecosystems in each of them, and a
// catalog app installed on two releases gets the record of each release's
// dataset. The merged record keeps the entries of every release.
func Tidy(sel map[string][]Selected) {
	for app, rs := range sel {
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Vuln.ID < rs[j].Vuln.ID })
		out := rs[:0]
		for _, r := range rs {
			n := len(out)
			if n == 0 || out[n-1].Vuln.ID != r.Vuln.ID {
				out = append(out, r)
				continue
			}
			m := &out[n-1]
			for _, a := range r.Vuln.Affected {
				if !containsEntry(m.Vuln.Affected, a) {
					m.Vuln.Affected = append(m.Vuln.Affected, a)
				}
			}
			if r.CVSS > m.CVSS {
				m.CVSS = r.CVSS
			}
			if rank(r.Severity) > rank(m.Severity) {
				m.Severity = r.Severity
			}
		}
		sel[app] = out
	}
}

// ErrNoData reports that a dataset has no cache file yet.
var ErrNoData = errors.New("vulndb: dataset not downloaded yet")

// CachePath is where the cache file of a dataset lives under dir.
func CachePath(dir string, d Dataset) string {
	name := strings.NewReplacer(":", "_", "/", "_", " ", "_", ".", "_").Replace(d.Key)
	return filepath.Join(dir, name+".jsonl.gz")
}

func cveKey(id string) string { return "cve/" + id }

// Ratings are CVE ratings by CVE ID.
type Ratings map[string]Record

// Unrated lists the CVEs of the selected records that carry no score of
// their own: the ratings LoadRatings needs to read.
func Unrated(sel map[string][]Selected) map[string]bool {
	out := map[string]bool{}
	for _, rs := range sel {
		for _, r := range rs {
			if r.CVSS > 0 {
				continue
			}
			for _, id := range append(append([]string{r.Vuln.ID}, r.Vuln.Upstream...), r.Vuln.Aliases...) {
				if strings.HasPrefix(id, "CVE-") {
					out[id] = true
				}
			}
		}
	}
	return out
}

// LoadRatings reads the ratings of the CVEs in only from the cache file of
// the CVE dataset; a nil only reads all of them.
func LoadRatings(path string, only map[string]bool) (Ratings, error) {
	f, err := os.Open(path) //nolint:gosec // path built by the caller inside the data directory
	if err != nil {
		return nil, fmt.Errorf("vulndb: %w", err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("vulndb %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = zr.Close() }()
	out := Ratings{}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		var l line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("vulndb %s: %w", filepath.Base(path), err)
		}
		if only != nil && (len(l.Keys) == 0 || !only[strings.TrimPrefix(l.Keys[0], "cve/")]) {
			continue
		}
		var rec Record
		if err := json.Unmarshal(l.Record, &rec); err != nil {
			return nil, fmt.Errorf("vulndb %s: %w", filepath.Base(path), err)
		}
		out[rec.Vuln.ID] = rec
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("vulndb %s: %w", filepath.Base(path), err)
	}
	return out, nil
}

// Rate gives a selected record without a score of its own the rating of its
// CVE: the CVSS score and vector, a label from the score where the record
// has none, and the description where it has none.
func (r Ratings) Rate(s *Selected) {
	if len(r) == 0 || s.CVSS > 0 {
		return
	}
	var c Record
	found := false
	for _, id := range append(append([]string{s.Vuln.ID}, s.Vuln.Upstream...), s.Vuln.Aliases...) {
		if c, found = r[id]; found {
			break
		}
	}
	if !found {
		return
	}
	if c.CVSS > 0 {
		s.CVSS = c.CVSS
		if len(s.Vuln.Severity) == 0 {
			s.Vuln.Severity = c.Vuln.Severity
		}
		if s.Severity == "" {
			s.Severity = CVSSLabel(c.CVSS)
		}
		spec := make(map[string]any, len(s.Vuln.DatabaseSpecific)+1)
		for k, v := range s.Vuln.DatabaseSpecific {
			spec[k] = v
		}
		spec[advisory.RatedByKey] = "NVD score as the Ubuntu CVE tracker states it"
		s.Vuln.DatabaseSpecific = spec
	}
	if s.Vuln.Summary == "" && c.Vuln.Summary != "" {
		s.Vuln.Summary, s.Vuln.Details = c.Vuln.Summary, c.Vuln.Details
	}
	if s.Vuln.Published.IsZero() {
		s.Vuln.Published = c.Vuln.Published
	}
}

// CVSSLabel is the qualitative rating of a CVSS base score.
func CVSSLabel(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}

func containsEntry(entries []advisory.Affected, a advisory.Affected) bool {
	for _, e := range entries {
		if strings.EqualFold(e.Package.Ecosystem, a.Package.Ecosystem) && e.Package.Name == a.Package.Name {
			return true
		}
	}
	return false
}
