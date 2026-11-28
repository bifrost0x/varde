// SPDX-License-Identifier: Apache-2.0

package vulndb

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/bifrost0x/varde/internal/advisory"
)

// Limits of a bulk export: osv.dev's largest exports Varde reads hold
// some tens of thousands of records of a few kilobytes each.
const (
	maxZipEntries     = 600000
	maxZipEntryBytes  = 8 << 20
	maxZipUnpackTotal = 4 << 30
)

// parseOSVZip reads osv.dev's bulk export of one ecosystem: one OSV record
// per JSON file. Withdrawn records are left out.
func parseOSVZip(zr *zip.Reader, emit func(Record) error) error {
	if len(zr.File) > maxZipEntries {
		return fmt.Errorf("osv export: %d files, more than allowed", len(zr.File))
	}
	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || path.Ext(f.Name) != ".json" {
			continue
		}
		if f.UncompressedSize64 > maxZipEntryBytes {
			continue
		}
		rec, n, err := readZipRecord(f)
		if err != nil {
			return err
		}
		if total += n; total > maxZipUnpackTotal {
			return fmt.Errorf("osv export: more than %d bytes unpacked", int64(maxZipUnpackTotal))
		}
		if rec == nil {
			continue
		}
		if err := emit(*rec); err != nil {
			return err
		}
	}
	return nil
}

func readZipRecord(f *zip.File) (*Record, int64, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, 0, fmt.Errorf("osv export: %s: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	// The size in the directory is not trusted: the read is cut too.
	data, err := io.ReadAll(io.LimitReader(rc, maxZipEntryBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("osv export: %s: %w", f.Name, err)
	}
	if len(data) > maxZipEntryBytes {
		return nil, int64(len(data)), nil
	}
	var v advisory.Vulnerability
	if err := json.Unmarshal(data, &v); err != nil {
		// One malformed record must not cost the ecosystem.
		return nil, int64(len(data)), nil
	}
	if v.Withdrawn != nil || !validID(v.ID) || len(v.Affected) == 0 {
		return nil, int64(len(data)), nil
	}
	rec := osvRecord(v)
	return &rec, int64(len(data)), nil
}

// osvRecord bounds an OSV record's text and reads its severity.
func osvRecord(v advisory.Vulnerability) Record {
	v.Summary = truncate(v.Summary, 512)
	v.Details = truncate(v.Details, 16<<10)
	if len(v.References) > 20 {
		v.References = v.References[:20]
	}
	rec := Record{}
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			if c, err := advisory.CVSS3BaseScore(s.Score); err == nil && c > rec.CVSS {
				rec.CVSS = c
			}
		}
	}
	if sev, ok := v.DatabaseSpecific["severity"].(string); ok {
		rec.Severity = strings.ToLower(truncate(sev, 16))
	}
	rec.Vuln = v
	return rec
}
