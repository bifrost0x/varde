// SPDX-License-Identifier: Apache-2.0

package vulndb

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
)

// secdb is the format Alpine, Wolfi and Chainguard publish: per package
// the versions that fixed issues. Fixes listed under version "0" never
// affected the release. The format knows no unfixed issues.
type secdb struct {
	Packages []struct {
		Pkg struct {
			Name     string              `json:"name"`
			SecFixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

// secdbID finds the identifiers in a secfixes entry, which may hold
// several or a note ("CVE-2021-1 CVE-2021-2", "CVE-2020-3 (patched)").
var secdbID = regexp.MustCompile(`\b(CVE-\d{4}-\d{4,9}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b`)

// maxSecDBPackages bounds a file.
const maxSecDBPackages = 100000

// parseSecDB emits one record per issue and package. prefix starts the
// record IDs ("ALPINE-"), ecosystem is the release the file covers.
func parseSecDB(r io.Reader, ecosystem, prefix string, modified time.Time, emit func(Record) error) error {
	var db secdb
	if err := json.NewDecoder(r).Decode(&db); err != nil {
		return fmt.Errorf("secdb: %w", err)
	}
	if len(db.Packages) > maxSecDBPackages {
		return fmt.Errorf("secdb: %d packages, more than allowed", len(db.Packages))
	}
	for _, p := range db.Packages {
		name := p.Pkg.Name
		if !validPackageName(name) {
			continue
		}
		// Every fixed version of an issue; "0" removes it.
		fixed := map[string][]string{}
		never := map[string]bool{}
		for ver, entries := range p.Pkg.SecFixes {
			for _, e := range entries {
				for _, id := range secdbID.FindAllString(e, -1) {
					if ver == "0" {
						never[id] = true
						continue
					}
					if len(ver) <= 128 {
						fixed[id] = append(fixed[id], ver)
					}
				}
			}
		}
		ids := make([]string, 0, len(fixed))
		for id := range fixed {
			if !never[id] {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			vers := fixed[id]
			sort.Strings(vers)
			events := []advisory.Event{{Introduced: "0"}}
			seen := map[string]bool{}
			for _, v := range vers {
				if !seen[v] {
					seen[v] = true
					events = append(events, advisory.Event{Fixed: v})
				}
			}
			v := advisory.Vulnerability{
				ID: prefix + id, Modified: modified, Upstream: []string{id},
				Affected: []advisory.Affected{{
					Package: advisory.Package{Ecosystem: ecosystem, Name: name},
					Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: events}},
				}},
				References: []advisory.Reference{{Type: "ADVISORY", URL: secdbURL(id)}},
			}
			if err := emit(Record{Vuln: v}); err != nil {
				return err
			}
		}
	}
	return nil
}

// secdbURL is a page about an issue: the CVE record, or GitHub's advisory.
func secdbURL(id string) string {
	if len(id) > 5 && id[:5] == "GHSA-" {
		return "https://github.com/advisories/" + id
	}
	return "https://www.cve.org/CVERecord?id=" + id
}
