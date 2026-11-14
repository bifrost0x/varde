// SPDX-License-Identifier: Apache-2.0

// Package advisory holds the OSV-based advisory model (ADR 0004), the
// conversion of upstream formats into it, and the advisory sources.
package advisory

import "time"

// Vulnerability is an OSV record (https://ossf.github.io/osv-schema/),
// limited to the fields Varde uses. Unknown fields are dropped on import.
type Vulnerability struct {
	SchemaVersion string     `json:"schema_version,omitempty"`
	ID            string     `json:"id"`
	Modified      time.Time  `json:"modified"`
	Published     time.Time  `json:"published,omitzero"`
	Withdrawn     *time.Time `json:"withdrawn,omitempty"`
	Aliases       []string   `json:"aliases,omitempty"`
	// Upstream names the records this one is derived from: a distribution
	// record ("DEBIAN-CVE-2026-1642") names its CVE here, not in aliases.
	Upstream         []string       `json:"upstream,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	Severity         []Severity     `json:"severity,omitempty"`
	Affected         []Affected     `json:"affected,omitempty"`
	References       []Reference    `json:"references,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// Severity is an OSV severity entry (type CVSS_V3, CVSS_V4, ...).
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected is one affected package with its ranges.
type Affected struct {
	Package          Package        `json:"package"`
	Ranges           []Range        `json:"ranges,omitempty"`
	Versions         []string       `json:"versions,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
	// EcosystemSpecific carries distribution data such as Debian's urgency.
	EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
}

// Package identifies the affected software.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// Range types.
const (
	RangeSemver    = "SEMVER"
	RangeEcosystem = "ECOSYSTEM"
	RangeGit       = "GIT"
)

// Range is an OSV range with ordered events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
	// DatabaseSpecific carries Varde annotations, see RangeInferred.
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// Event is one OSV range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference is a link with a type (WEB, ADVISORY, FIX, ...).
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// RangeInferred marks a range Varde reconstructed from ambiguous upstream
// data. Only versions listed exactly may be reported as affected; others
// inside the range are unverified (ADR 0008).
const RangeInferred = "varde_inferred"

// Inferred reports whether the range carries the RangeInferred marker.
func (r Range) Inferred() bool {
	v, _ := r.DatabaseSpecific[RangeInferred].(bool)
	return v
}

// CVEs returns the CVE identifiers among the record's ID and aliases.
func (v Vulnerability) CVEs() []string {
	var out []string
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if len(id) > 4 && id[:4] == "CVE-" {
			out = append(out, id)
		}
	}
	return out
}

// URL returns the most useful human-readable link: an advisory reference,
// else the first web reference.
func (v Vulnerability) URL() string {
	for _, r := range v.References {
		if r.Type == "ADVISORY" {
			return r.URL
		}
	}
	for _, r := range v.References {
		if r.Type == "WEB" {
			return r.URL
		}
	}
	return ""
}

// OriginKey is the database_specific key under which a record of the data
// package names the source the package builder read it from, when that is
// not the project's own repository: "osv", or "nvd:" and the CPE asked
// for. Installations released before it ignore the key.
const OriginKey = "varde_origin"

// Origin returns the origin of a record of the data package, "" for one a
// project published in its repository.
func (v Vulnerability) Origin() string {
	s, _ := v.DatabaseSpecific[OriginKey].(string)
	return s
}

// WithOrigin returns v with its origin set, leaving v's map as it is.
func WithOrigin(v Vulnerability, origin string) Vulnerability {
	m := make(map[string]any, len(v.DatabaseSpecific)+1)
	for k, val := range v.DatabaseSpecific {
		m[k] = val
	}
	m[OriginKey] = origin
	v.DatabaseSpecific = m
	return v
}

// NamesEnd reports whether the record says where the affected versions
// end: a fixed or last affected version, or an explicit list of versions.
// A record that does not ("from 2.8 on", or a range no program could read)
// cannot clear a patched version or name an update by itself.
func (v Vulnerability) NamesEnd() bool {
	for _, a := range v.Affected {
		if len(a.Versions) > 0 {
			return true
		}
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" || ev.LastAffected != "" || ev.Limit != "" {
					return true
				}
			}
		}
	}
	return false
}
