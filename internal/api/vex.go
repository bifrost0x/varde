// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/store"
)

// OpenVEX 0.2.0 (https://github.com/openvex/spec): what Varde knows about
// each open finding, for scanners and SBOM tools that read VEX. Varde
// states only what it has established (ADR 0028):
//   - affected: the running version is in an affected range;
//   - under_investigation: an unverified finding (version unknown, not
//     comparable, or not confirmed);
//   - not_affected: the user suppressed it, with the reason as impact
//     statement.

const vexContext = "https://openvex.dev/ns/v0.2.0"

type vexDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  time.Time      `json:"timestamp"`
	Version    int            `json:"version"`
	Tooling    string         `json:"tooling"`
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability   vexVulnerability `json:"vulnerability"`
	Products        []vexProduct     `json:"products"`
	Status          string           `json:"status"`
	StatusNotes     string           `json:"status_notes,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
	Timestamp       time.Time        `json:"timestamp"`
}

type vexVulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type vexProduct struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
}

func (a *api) vex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fs, err := a.store.Findings(ctx, store.FindingFilter{})
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	ids, err := a.store.Identifications(ctx)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	sups, err := a.store.Suppressions(ctx)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	reasons := map[string]string{}
	for _, s := range sups {
		reasons[s.ID] = s.Reason
	}
	doc := vexDocument{Context: vexContext, Author: "Varde", Timestamp: a.now().UTC(), Version: 1, Tooling: "Varde " + buildinfo.Version}
	for _, f := range fs {
		st := vexStatement{Products: []vexProduct{product(f.WorkloadID, ids[f.WorkloadID].PURL)}, Timestamp: f.LastChanged.UTC()}
		st.Vulnerability = vulnerability(f)
		switch {
		case f.State == store.StateSuppressed:
			st.Status = "not_affected"
			st.ImpactStatement = "Suppressed by the operator: " + reasons[f.SuppressionID]
		case f.MatchState == "affected":
			st.Status = "affected"
			if f.FixedIn != "" {
				st.ActionStatement = "Update to " + f.FixedIn + " or later."
			} else {
				st.ActionStatement = "No fixed version is known yet."
			}
		default:
			st.Status = "under_investigation"
			st.StatusNotes = "The finding is unverified: " + unverifiedReason(f)
		}
		doc.Statements = append(doc.Statements, st)
	}
	sort.Slice(doc.Statements, func(i, j int) bool {
		a, b := doc.Statements[i], doc.Statements[j]
		if a.Vulnerability.Name != b.Vulnerability.Name {
			return a.Vulnerability.Name < b.Vulnerability.Name
		}
		return a.Products[0].ID < b.Products[0].ID
	})
	if doc.Statements == nil {
		doc.Statements = []vexStatement{}
	}
	// The ID names the content, so the same state gives the same ID.
	body, err := json.Marshal(doc.Statements)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	sum := sha256.Sum256(body)
	doc.ID = "urn:varde:vex:" + hex.EncodeToString(sum[:16])
	w.Header().Set("Content-Disposition", `attachment; filename="varde.openvex.json"`)
	writeJSON(w, http.StatusOK, doc)
}

// product names the workload by its package URL when Varde knows one.
func product(workloadID, purl string) vexProduct {
	if purl == "" {
		return vexProduct{ID: "urn:varde:workload:" + workloadID}
	}
	return vexProduct{ID: purl, Identifiers: map[string]string{"purl": purl}}
}

// vulnerability prefers the CVE, which VEX consumers match on.
func vulnerability(f store.Finding) vexVulnerability {
	var d struct {
		Aliases []string `json:"aliases"`
	}
	_ = json.Unmarshal(f.Detail, &d)
	v := vexVulnerability{Name: f.AdvisoryID}
	all := append([]string{f.AdvisoryID}, d.Aliases...)
	for _, id := range all {
		if strings.HasPrefix(id, "CVE-") {
			v.Name = id
			break
		}
	}
	for _, id := range all {
		if id != v.Name {
			v.Aliases = append(v.Aliases, id)
		}
	}
	return v
}

func unverifiedReason(f store.Finding) string {
	var d struct {
		Evidence struct {
			Reason string `json:"reason"`
		} `json:"evidence"`
	}
	_ = json.Unmarshal(f.Detail, &d)
	if d.Evidence.Reason == "" {
		return "the running version could not be compared"
	}
	return d.Evidence.Reason
}
