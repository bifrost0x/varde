// SPDX-License-Identifier: Apache-2.0

package vulndb

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
)

// Canonical's package OVAL has one definition per source package. Its
// metadata lists the CVEs fixed in the release, each pointing at a test
// whose state names the version that fixed it ("evr less than
// 1.2-3ubuntu0.1"). Kernel definitions compare the running kernel instead
// and are left out: containers do not bring a kernel.

type ovalDefinition struct {
	Class    string       `xml:"class,attr"`
	Title    string       `xml:"metadata>title"`
	CVEs     []ovalCVE    `xml:"metadata>advisory>cve"`
	Criteria ovalCriteria `xml:"criteria"`
}

type ovalCVE struct {
	ID         string `xml:",chardata"`
	Href       string `xml:"href,attr"`
	Priority   string `xml:"priority,attr"`
	Public     string `xml:"public,attr"`
	CVSSScore  string `xml:"cvss_score,attr"`
	CVSSVector string `xml:"cvss_vector,attr"`
	USNs       string `xml:"usns,attr"`
	TestRef    string `xml:"test_ref,attr"`
}

type ovalCriteria struct {
	Criteria  []ovalCriteria  `xml:"criteria"`
	Criterion []ovalCriterion `xml:"criterion"`
}

type ovalCriterion struct {
	Comment string `xml:"comment,attr"`
}

// kernel reports whether a definition checks the running kernel.
func (c ovalCriteria) kernel() bool {
	for _, x := range c.Criterion {
		if strings.HasPrefix(x.Comment, "Is kernel ") || strings.Contains(x.Comment, "kernel '") {
			return true
		}
	}
	for _, sub := range c.Criteria {
		if sub.kernel() {
			return true
		}
	}
	return false
}

type ovalTest struct {
	ID    string `xml:"id,attr"`
	State struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

type ovalState struct {
	ID  string `xml:"id,attr"`
	EVR struct {
		Value     string `xml:",chardata"`
		Operation string `xml:"operation,attr"`
	} `xml:"evr"`
}

// ubuntuFix is one fixed CVE of one source package.
type ubuntuFix struct {
	pkg   string
	cve   ovalCVE
	fixed string
}

// maxOVALDefinitions bounds what one file may hold.
const maxOVALDefinitions = 200000

// parseUbuntuOVAL reads a package OVAL file of one release and emits one
// record per CVE, with an entry per source package that fixed it.
func parseUbuntuOVAL(r io.Reader, ecosystem string, modified time.Time, emit func(Record) error) error {
	dec := xml.NewDecoder(r)
	var fixes []ubuntuFix
	tests := map[string]string{}  // test ID -> state ID
	states := map[string]string{} // state ID -> fixed version
	defs := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("ubuntu oval: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "definition":
			var d ovalDefinition
			if err := dec.DecodeElement(&d, &se); err != nil {
				return fmt.Errorf("ubuntu oval: definition: %w", err)
			}
			if defs++; defs > maxOVALDefinitions {
				return errors.New("ubuntu oval: too many definitions")
			}
			pkg := strings.TrimSpace(d.Title)
			if d.Class != "vulnerability" || !validPackageName(pkg) || d.Criteria.kernel() {
				continue
			}
			for _, c := range d.CVEs {
				c.ID = strings.TrimSpace(c.ID)
				if strings.HasPrefix(c.ID, "CVE-") && validID(c.ID) && c.TestRef != "" {
					fixes = append(fixes, ubuntuFix{pkg: pkg, cve: c})
				}
			}
		case "dpkginfo_test":
			var t ovalTest
			if err := dec.DecodeElement(&t, &se); err != nil {
				return fmt.Errorf("ubuntu oval: test: %w", err)
			}
			if t.State.Ref != "" {
				tests[t.ID] = t.State.Ref
			}
		case "dpkginfo_state":
			var s ovalState
			if err := dec.DecodeElement(&s, &se); err != nil {
				return fmt.Errorf("ubuntu oval: state: %w", err)
			}
			if s.EVR.Operation == "less than" && strings.TrimSpace(s.EVR.Value) != "" {
				states[s.ID] = strings.TrimSpace(s.EVR.Value)
			}
		}
	}
	// One record per CVE: the packages that fixed it, in file order.
	byCVE := map[string][]ubuntuFix{}
	var order []string
	for _, f := range fixes {
		fixed := states[tests[f.cve.TestRef]]
		if fixed == "" {
			continue
		}
		if _, seen := byCVE[f.cve.ID]; !seen {
			order = append(order, f.cve.ID)
		}
		f.fixed = fixed
		byCVE[f.cve.ID] = append(byCVE[f.cve.ID], f)
	}
	sort.Strings(order)
	for _, id := range order {
		rec := ubuntuRecord(id, byCVE[id], ecosystem, modified)
		if err := emit(rec); err != nil {
			return err
		}
	}
	return nil
}

func ubuntuRecord(id string, fs []ubuntuFix, ecosystem string, modified time.Time) Record {
	v := advisory.Vulnerability{ID: "UBUNTU-" + id, Modified: modified, Upstream: []string{id}}
	rec := Record{}
	seenPkg := map[string]bool{}
	usns := map[string]bool{}
	for _, f := range fs {
		if seenPkg[f.pkg] {
			continue
		}
		seenPkg[f.pkg] = true
		spec := map[string]any{}
		if p := strings.ToLower(strings.TrimSpace(f.cve.Priority)); p != "" {
			spec["priority"] = truncate(p, 16)
		}
		fixed := truncate(f.fixed, 128)
		if strings.Contains(fixed, "esm") {
			// The fix is published for Ubuntu Pro (Expanded Security
			// Maintenance) only.
			spec["pro"] = true
		}
		aff := advisory.Affected{
			Package: advisory.Package{Ecosystem: ecosystem, Name: f.pkg},
			Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}},
		}
		if len(spec) > 0 {
			aff.EcosystemSpecific = spec
		}
		v.Affected = append(v.Affected, aff)
		if s, err := strconv.ParseFloat(f.cve.CVSSScore, 64); err == nil && s > rec.CVSS && s <= 10 {
			rec.CVSS = s
		}
		if vec := strings.TrimSpace(f.cve.CVSSVector); vec != "" && len(v.Severity) == 0 && len(vec) < 200 {
			typ := "CVSS_V3"
			if strings.HasPrefix(vec, "CVSS:4") {
				typ = "CVSS_V4"
			}
			if strings.HasPrefix(vec, "CVSS:3") || strings.HasPrefix(vec, "CVSS:4") {
				v.Severity = []advisory.Severity{{Type: typ, Score: vec}}
			}
		}
		if p := ubuntuPriority(f.cve.Priority); rank(p) > rank(rec.Severity) {
			rec.Severity = p
		}
		if t, err := time.Parse("20060102", f.cve.Public); err == nil && v.Published.IsZero() {
			v.Published = t
		}
		for _, u := range strings.Split(f.cve.USNs, ",") {
			if u = strings.TrimSpace(u); u != "" && validID(u) {
				usns[u] = true
			}
		}
	}
	v.References = []advisory.Reference{{Type: "ADVISORY", URL: "https://ubuntu.com/security/" + id}}
	ids := make([]string, 0, len(usns))
	for u := range usns {
		ids = append(ids, u)
	}
	sort.Strings(ids)
	for _, u := range ids {
		v.References = append(v.References, advisory.Reference{Type: "ADVISORY", URL: "https://ubuntu.com/security/notices/USN-" + u})
	}
	rec.Vuln = v
	return rec
}

// ubuntuPriority maps Canonical's priority to a severity label.
func ubuntuPriority(p string) string {
	switch p = strings.ToLower(strings.TrimSpace(p)); p {
	case "critical", "high", "medium", "low", "negligible":
		return p
	}
	return ""
}

// rank orders severity labels.
func rank(label string) int {
	switch label {
	case "critical":
		return 6
	case "high":
		return 5
	case "medium", "moderate":
		return 4
	case "low":
		return 3
	case "negligible", "unimportant":
		return 2
	}
	return 0
}

// ovalCVEDefinition is a definition of Canonical's CVE OVAL: one CVE, with
// its description and Canonical's rating.
type ovalCVEDefinition struct {
	Class       string    `xml:"class,attr"`
	Description string    `xml:"metadata>description"`
	CVEs        []ovalCVE `xml:"metadata>advisory>cve"`
}

// parseUbuntuCVE reads Canonical's CVE OVAL and emits one rating record
// per CVE: its NVD CVSS score and vector as Canonical states them,
// Canonical's priority and the description. The records name no package.
func parseUbuntuCVE(r io.Reader, modified time.Time, emit func(Record) error) error {
	dec := xml.NewDecoder(r)
	defs := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ubuntu cve oval: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "definition" {
			continue
		}
		var d ovalCVEDefinition
		if err := dec.DecodeElement(&d, &se); err != nil {
			return fmt.Errorf("ubuntu cve oval: definition: %w", err)
		}
		if defs++; defs > maxOVALDefinitions {
			return errors.New("ubuntu cve oval: too many definitions")
		}
		if d.Class != "vulnerability" || len(d.CVEs) == 0 {
			continue
		}
		c := d.CVEs[0]
		id := strings.TrimSpace(c.ID)
		if !strings.HasPrefix(id, "CVE-") || !validID(id) {
			continue
		}
		v := advisory.Vulnerability{ID: id, Modified: modified}
		if desc := strings.TrimSpace(d.Description); desc != "" {
			// The summary only: the ratings of every CVE are read at
			// once, and the record's own source has the description.
			v.Summary = summary(desc)
		}
		rec := Record{Severity: ubuntuPriority(c.Priority)}
		if s, err := strconv.ParseFloat(c.CVSSScore, 64); err == nil && s > 0 && s <= 10 {
			rec.CVSS = s
		}
		if vec := strings.TrimSpace(c.CVSSVector); len(vec) < 200 && (strings.HasPrefix(vec, "CVSS:3") || strings.HasPrefix(vec, "CVSS:4")) {
			typ := "CVSS_V3"
			if strings.HasPrefix(vec, "CVSS:4") {
				typ = "CVSS_V4"
			}
			v.Severity = []advisory.Severity{{Type: typ, Score: vec}}
		}
		if t, err := time.Parse("20060102", c.Public); err == nil {
			v.Published = t
		}
		if rec.CVSS == 0 && v.Summary == "" {
			continue
		}
		rec.Vuln = v
		if err := emit(rec); err != nil {
			return err
		}
	}
}
