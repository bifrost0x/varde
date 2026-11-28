// SPDX-License-Identifier: Apache-2.0

package vulndb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
)

// debianIssue is one entry of the security tracker: a CVE (or a TEMP-
// issue without one yet) of one source package.
type debianIssue struct {
	Description string                   `json:"description"`
	Releases    map[string]debianRelease `json:"releases"`
}

type debianRelease struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
	NoDSA        string `json:"nodsa"`
	NoDSAReason  string `json:"nodsa_reason"`
}

// Debian's urgencies as Varde's severity labels. "unimportant" is kept as
// Debian's own word: the matcher treats it as not worth an alert.
var debianUrgency = map[string]string{
	"high":        "high",
	"medium":      "medium",
	"low":         "low",
	"unimportant": "unimportant",
}

// parseDebian reads the tracker's JSON ({package: {issue: {...}}}) one
// package at a time and emits one record per issue and package, with an
// entry per supported release the issue affects. modified stamps the
// records: the tracker states no dates.
func parseDebian(r io.Reader, modified time.Time, emit func(Record) error) error {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("debian: %w", err)
		}
		pkg, ok := tok.(string)
		if !ok {
			return errors.New("debian: package name expected")
		}
		issues, err := decodeIssues(dec)
		if err != nil {
			return fmt.Errorf("debian: package %q: %w", truncate(pkg, 64), err)
		}
		if !validPackageName(pkg) {
			continue
		}
		ids := make([]string, 0, len(issues))
		for id := range issues {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			rec, ok := debianRecord(pkg, id, issues[id], modified)
			if !ok {
				continue
			}
			if err := emit(rec); err != nil {
				return err
			}
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return err
	}
	return nil
}

// decodeIssues reads one package's issues an issue at a time. Decoding the
// package as one value would make the decoder buffer all of it, and the
// kernel's entry alone holds tens of megabytes.
func decodeIssues(dec *json.Decoder) (map[string]debianIssue, error) {
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	issues := map[string]debianIssue{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		id, ok := tok.(string)
		if !ok {
			return nil, errors.New("issue name expected")
		}
		var is debianIssue
		if err := dec.Decode(&is); err != nil {
			return nil, fmt.Errorf("issue %q: %w", truncate(id, 64), err)
		}
		issues[id] = is
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, err
	}
	return issues, nil
}

func debianRecord(pkg, id string, is debianIssue, modified time.Time) (Record, bool) {
	if !validID(id) || (!strings.HasPrefix(id, "CVE-") && !strings.HasPrefix(id, "TEMP-")) {
		return Record{}, false
	}
	codes := make([]string, 0, len(is.Releases))
	for code := range is.Releases {
		if _, ok := debianReleases[code]; ok {
			codes = append(codes, code)
		}
	}
	sort.Slice(codes, func(i, j int) bool { return debianReleases[codes[i]] < debianReleases[codes[j]] })
	v := advisory.Vulnerability{ID: "DEBIAN-" + id, Modified: modified}
	for _, code := range codes {
		rel := is.Releases[code]
		events := []advisory.Event{{Introduced: "0"}}
		switch {
		case rel.Status == "resolved" && rel.FixedVersion == "0":
			// Never affected in this release.
			continue
		case rel.Status == "resolved" && rel.FixedVersion != "":
			events = append(events, advisory.Event{Fixed: truncate(rel.FixedVersion, 128)})
		case rel.Status == "resolved":
			// Resolved without a version: nothing to compare.
			continue
		}
		spec := map[string]any{}
		if u := strings.TrimSpace(rel.Urgency); u != "" && u != "not yet assigned" {
			spec["urgency"] = truncate(u, 32)
		}
		if rel.Status != "resolved" {
			spec["status"] = truncate(rel.Status, 32)
		}
		if rel.NoDSA != "" {
			// Debian decided not to issue an advisory: "ignored" (minor
			// issue) or "postponed" (fixed with a point release).
			spec["nodsa"] = truncate(firstNonEmpty(rel.NoDSAReason, "yes"), 32)
		}
		aff := advisory.Affected{
			Package: advisory.Package{Ecosystem: "Debian:" + debianReleases[code], Name: pkg},
			Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: events}},
		}
		if len(spec) > 0 {
			aff.EcosystemSpecific = spec
		}
		v.Affected = append(v.Affected, aff)
	}
	if len(v.Affected) == 0 {
		return Record{}, false
	}
	if strings.HasPrefix(id, "CVE-") {
		v.Upstream = []string{id}
	}
	if d := strings.TrimSpace(is.Description); d != "" {
		v.Summary = summary(d)
		v.Details = truncate(d, 4<<10)
	}
	v.References = []advisory.Reference{{Type: "ADVISORY", URL: "https://" + debianHost + "/tracker/" + id}}
	return Record{Vuln: v}, true
}

// debianSeverity is the label of a record trimmed to the entries of one
// package: Debian's urgency for it, if Debian rated it.
func debianSeverity(entries []advisory.Affected) string {
	best := ""
	rank := map[string]int{"unimportant": 1, "low": 2, "medium": 3, "high": 4}
	for _, e := range entries {
		u, _ := e.EcosystemSpecific["urgency"].(string)
		if l, ok := debianUrgency[u]; ok && rank[l] > rank[best] {
			best = l
		}
	}
	return best
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("debian: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("debian: %q expected", want)
	}
	return nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// validPackageName accepts the names distributions give packages.
func validPackageName(name string) bool {
	if name == "" || len(name) > 214 {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == '/' || r == '\\' || r == 0x7f {
			return false
		}
	}
	return true
}
