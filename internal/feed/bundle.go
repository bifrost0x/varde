// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

// checkHash verifies a downloaded blob before anything else touches it.
func checkHash(b Blob, data []byte) error {
	if int64(len(data)) != b.Size {
		return fmt.Errorf("blob %s: %d bytes, manifest says %d: %w", b.Name, len(data), b.Size, ErrMismatch)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != b.SHA256 {
		return fmt.Errorf("blob %s: sha256: %w", b.Name, ErrMismatch)
	}
	return nil
}

// unpack decompresses a verified blob with a hard limit of the declared
// uncompressed size, so a decompression bomb stops at the limit.
func unpack(b Blob, data []byte) ([]byte, error) {
	if b.Compression == "none" {
		return data, nil
	}
	dec, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1),
		// Memory is capped near the declared size (with a floor for the
		// decoder's minimum window); the output itself is cut below.
		zstd.WithDecoderMaxMemory(uint64(max(b.UncompressedSize, 1<<20))*2), zstd.WithDecoderMaxWindow(64<<20))
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", b.Name, err)
	}
	defer dec.Close()
	out, err := io.ReadAll(io.LimitReader(dec, b.UncompressedSize+1))
	if err != nil {
		return nil, fmt.Errorf("blob %s: decompress: %w", b.Name, err)
	}
	if int64(len(out)) != b.UncompressedSize {
		return nil, fmt.Errorf("blob %s: %d bytes unpacked, manifest says %d: %w", b.Name, len(out), b.UncompressedSize, ErrMismatch)
	}
	return out, nil
}

// Content is the parsed, validated content of a manifest.
type Content struct {
	Catalog []catalog.Entry
	// Generated are the generated catalog entries, which rank below the
	// reviewed ones (catalog.BuildLayered).
	Generated  []catalog.Entry
	Advisories []store.AdvisoryRecord
	KEV        []store.KEVEntry
	EPSS       []store.EPSSEntry
	// Index is the first-party index of the package (image to source
	// repository), nil when the package has none.
	Index *applists.Table
	// Releases are the package lists of the newest releases, nil when the
	// package has none.
	Releases []ReleaseLine
	// Tags are the release tags of the images of catalog apps, nil when
	// the package has none.
	Tags []TagLine
}

// maxIndexBytes bounds the unpacked index blob.
const maxIndexBytes = 8 << 20

type catalogDoc struct {
	SchemaVersion int             `json:"schema_version"`
	Entries       []catalog.Entry `json:"entries"`
}

// AdvisoryLine is one line of an advisory shard.
type AdvisoryLine struct {
	AppID    string                 `json:"app_id"`
	CVSS     float64                `json:"cvss,omitempty"`
	Severity string                 `json:"severity,omitempty"`
	OSV      advisory.Vulnerability `json:"osv"`
}

// KEVLine and EPSSLine are the enrichment records.
type KEVLine struct {
	CVE        string `json:"cve"`
	DateAdded  string `json:"date_added"`
	Ransomware string `json:"ransomware,omitempty"`
}

// EPSSLine is one EPSS score.
type EPSSLine struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

var (
	appIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	cveRe   = regexp.MustCompile(`^CVE-\d{4}-\d{4,9}$`)
)

const maxAdvisoryLine = 4 << 20

// parse adds one unpacked blob to c.
func (c *Content) parse(b Blob, data []byte) error {
	switch {
	case b.Name == "catalog":
		var doc catalogDoc
		if err := decodeStrict(data, &doc); err != nil {
			return fmt.Errorf("catalog: %w", err)
		}
		if doc.SchemaVersion != SpecVersion {
			return fmt.Errorf("catalog: schema version %d", doc.SchemaVersion)
		}
		c.Catalog = doc.Entries
	case b.Name == "generated":
		var doc catalogDoc
		if err := decodeStrict(data, &doc); err != nil {
			return fmt.Errorf("generated: %w", err)
		}
		if doc.SchemaVersion != SpecVersion {
			return fmt.Errorf("generated: schema version %d", doc.SchemaVersion)
		}
		c.Generated = doc.Entries
	case b.Name == "releases":
		lines, err := parseReleases(data)
		if err != nil {
			return err
		}
		c.Releases = lines
	case b.Name == "tags":
		lines, err := parseTags(data)
		if err != nil {
			return err
		}
		c.Tags = lines
	case b.Name == "index":
		if len(data) > maxIndexBytes {
			return errors.New("index: larger than allowed")
		}
		t, err := applists.Unmarshal(data)
		if err != nil {
			return fmt.Errorf("index: %w", err)
		}
		c.Index = t
	case b.Name == "enrichment/kev":
		var lines []KEVLine
		if err := decodeStrict(data, &lines); err != nil {
			return fmt.Errorf("kev: %w", err)
		}
		for _, l := range lines {
			if !cveRe.MatchString(l.CVE) || len(l.DateAdded) > 32 || len(l.Ransomware) > 32 {
				return fmt.Errorf("kev: invalid entry %q", l.CVE)
			}
			c.KEV = append(c.KEV, store.KEVEntry{CVE: l.CVE, DateAdded: l.DateAdded, Ransomware: l.Ransomware})
		}
	case b.Name == "enrichment/epss":
		var lines []EPSSLine
		if err := decodeStrict(data, &lines); err != nil {
			return fmt.Errorf("epss: %w", err)
		}
		for _, l := range lines {
			if !cveRe.MatchString(l.CVE) || l.Score < 0 || l.Score > 1 || l.Percentile < 0 || l.Percentile > 1 || len(l.Date) > 32 {
				return fmt.Errorf("epss: invalid entry %q", l.CVE)
			}
			c.EPSS = append(c.EPSS, store.EPSSEntry{CVE: l.CVE, Score: l.Score, Percentile: l.Percentile, Date: l.Date})
		}
	case strings.HasPrefix(b.Name, "advisories/"):
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64<<10), maxAdvisoryLine)
		n := 0
		for sc.Scan() {
			n++
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var a AdvisoryLine
			if err := decodeStrict(line, &a); err != nil {
				return fmt.Errorf("%s line %d: %w", b.Name, n, err)
			}
			if !appIDRe.MatchString(a.AppID) || a.OSV.ID == "" || len(a.OSV.ID) > 128 || a.CVSS < 0 || a.CVSS > 10 || len(a.Severity) > 16 {
				return fmt.Errorf("%s line %d: invalid record", b.Name, n)
			}
			c.Advisories = append(c.Advisories, store.AdvisoryRecord{
				AppID: a.AppID, Source: store.FeedSource, Vuln: a.OSV, CVSS: a.CVSS, SeverityLabel: strings.ToLower(a.Severity),
			})
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("%s: %w", b.Name, err)
		}
	default:
		return errors.New("unknown blob " + b.Name)
	}
	return nil
}

// marshalLines encodes advisory lines as JSONL (used by the feed builder and
// tests).
func marshalLines(lines []AdvisoryLine) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, l := range lines {
		if err := enc.Encode(l); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
