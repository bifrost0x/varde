// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/catgen"
	"github.com/bifrost0x/varde/internal/fsutil"
	"github.com/bifrost0x/varde/internal/pkgbuild"
	"github.com/bifrost0x/varde/internal/store"
)

// The readable list of generated entries (ADR 0040) lies in catalog/
// beside feed/ and cache/ and is published with them on the branch data.
// Nothing reads it but people: what installations use is the signed
// package. generated.json is the state after this build, generated.md the
// change against the list published before.
const (
	generatedDir  = "catalog"
	generatedJSON = "generated.json"
	generatedMD   = "generated.md"
)

// Image states in generated.json.
const (
	genShipped = "shipped"
	// genWithheld: the image passed, but its project's entry waits for
	// the check of an image the project gained.
	genWithheld = "withheld"
	genFailed   = "failed"
	// genPending: not checked yet; it waits for the budget of a build.
	genPending = "pending"
)

// Check results in generated.json.
const (
	checkPass   = "pass"
	checkFail   = "fail"
	checkNotRun = "not run"
)

// checkOrder is the order in which the generator runs the checks; the
// first that fails ends a candidate's check.
var checkOrder = []string{catgen.CheckSchema, catgen.CheckEvidence, catgen.CheckTags, catgen.CheckVersion, catgen.CheckCPE, catgen.CheckNoRegression}

type genState struct {
	Build    time.Time `json:"build"`
	Sequence int64     `json:"sequence"`
	// Stopped names the sources the build stopped asking (a rate limit)
	// and "deadline" when its time ran out.
	Stopped []string   `json:"stopped,omitempty"`
	Entries []genEntry `json:"entries"`
	Images  []genImage `json:"images"`
}

// genEntry is one shipped entry, as the package carries it.
type genEntry struct {
	ID   string `json:"id"`
	YAML string `json:"yaml"`
}

type genImage struct {
	Image  string `json:"image"`
	Repo   string `json:"repo"`
	Weight int64  `json:"weight"`
	Status string `json:"status"`
	// Entry is the ID of the entry the image is in; Hash identifies its
	// text without the verified date, so a passing re-check is no change.
	Entry       string     `json:"entry,omitempty"`
	Hash        string     `json:"hash,omitempty"`
	Checks      []genCheck `json:"checks,omitempty"`
	FailedCheck string     `json:"failed_check,omitempty"`
	// Reason says what failed; known for failures of this build.
	Reason string `json:"reason,omitempty"`
	// Skipped says why the image could not be checked this build; it
	// keeps its earlier state.
	Skipped   string    `json:"skipped,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
	ShippedAt time.Time `json:"shipped_at,omitzero"`
}

type genCheck struct {
	Check  string `json:"check"`
	Result string `json:"result"`
}

// checksOf spells out the check results of a candidate from its state:
// every check passed for a shipped one; for a failed one those before the
// failed check passed and those after it did not run.
func checksOf(status, failed string) []genCheck {
	var out []genCheck
	switch status {
	case genShipped, genWithheld:
		for _, c := range checkOrder {
			out = append(out, genCheck{c, checkPass})
		}
	case genFailed:
		i := slices.Index(checkOrder, failed)
		if i < 0 {
			// stale: no check could confirm the entry for too long.
			return []genCheck{{failed, checkFail}}
		}
		for j, c := range checkOrder {
			r := checkNotRun
			switch {
			case j < i:
				r = checkPass
			case j == i:
				r = checkFail
			}
			out = append(out, genCheck{c, r})
		}
	}
	return out
}

// entryHash identifies an entry's text without its verified date.
func entryHash(entry string) string {
	var b strings.Builder
	for l := range strings.SplitSeq(entry, "\n") {
		if !strings.HasPrefix(l, "verified:") {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:12])
}

// generatedState is the state of every candidate in the index after a
// build: rows are the builder store's candidates, rep the build's report.
func generatedState(rows []store.Candidate, rep catgen.Report, build time.Time, sequence int64) genState {
	s := genState{Build: build.UTC(), Sequence: sequence, Stopped: rep.Stopped, Entries: []genEntry{}, Images: []genImage{}}
	inPackage := map[string]bool{}
	for _, e := range rep.Shipped {
		id := strings.TrimSuffix(e.Name, ".yaml")
		inPackage[id] = true
		s.Entries = append(s.Entries, genEntry{ID: id, YAML: e.Data})
	}
	for _, c := range rows {
		if c.Status == catgen.StatusRetired {
			continue
		}
		owner, name, _ := strings.Cut(c.Repo, "/")
		img := genImage{Image: c.Image, Repo: c.Repo, Weight: c.Weight, Skipped: rep.Skipped[c.Image],
			CheckedAt: c.CheckedAt.UTC(), ShippedAt: c.ShippedAt.UTC()}
		switch c.Status {
		case store.CandidateShipped:
			img.Entry, img.Hash = catalog.DerivedID(owner, name), entryHash(c.EntryYAML)
			img.Status = genWithheld
			if inPackage[img.Entry] {
				img.Status = genShipped
			}
		case catgen.StatusFailed:
			img.Status, img.FailedCheck, img.Reason = genFailed, c.FailedCheck, rep.Reasons[c.Image]
		default:
			img.Status = genPending
		}
		img.Checks = checksOf(img.Status, img.FailedCheck)
		s.Images = append(s.Images, img)
	}
	sort.Slice(s.Images, func(i, j int) bool { return s.Images[i].Image < s.Images[j].Image })
	return s
}

// genDiff is the change of a build against the list published before.
type genDiff struct {
	// Against says what the change was measured against.
	Against               string
	New, Changed, Dropped []string
}

// diffGenerated compares cur with the list published before. Without one
// (the first build, or a list that does not read) the changes are the
// ones the generator recorded in the builder store this build.
func diffGenerated(prev *genState, cur genState, rep catgen.Report) genDiff {
	if prev == nil {
		d := genDiff{Against: "no list published before; changes as the builder's store recorded them this build",
			New: slices.Clone(rep.New), Changed: slices.Clone(rep.Changed), Dropped: slices.Clone(rep.Dropped)}
		sort.Strings(d.New)
		sort.Strings(d.Changed)
		sort.Strings(d.Dropped)
		return d
	}
	d := genDiff{Against: fmt.Sprintf("the list of the build of %s (package %d)", prev.Build.UTC().Format("2006-01-02 15:04 UTC"), prev.Sequence)}
	was := map[string]string{}
	for _, img := range prev.Images {
		if img.Status == genShipped {
			was[img.Image] = img.Hash
		}
	}
	now := map[string]bool{}
	for _, img := range cur.Images {
		if img.Status != genShipped {
			continue
		}
		now[img.Image] = true
		h, ok := was[img.Image]
		switch {
		case !ok:
			d.New = append(d.New, img.Image)
		case h != img.Hash:
			d.Changed = append(d.Changed, img.Image)
		}
	}
	for img := range was {
		if !now[img] {
			d.Dropped = append(d.Dropped, img)
		}
	}
	sort.Strings(d.New)
	sort.Strings(d.Changed)
	sort.Strings(d.Dropped)
	return d
}

// readPreviousGenerated reads the list published before from the branch
// the build fetched. It is unsigned and only feeds the summary: a list
// that does not read is reported and left out.
func readPreviousGenerated(previous string) (*genState, error) {
	if previous == "" {
		return nil, nil
	}
	data, err := pkgbuild.ReadRegular(filepath.Join(filepath.Dir(filepath.Clean(previous)), generatedDir, generatedJSON))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s genState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", generatedJSON, err)
	}
	return &s, nil
}

// renderGenerated writes the summary: counts, then the images that are
// new, changed and dropped, then this build's failures with their check.
func renderGenerated(cur genState, d genDiff, rep catgen.Report) string {
	var b strings.Builder
	shippedImages := 0
	for _, img := range cur.Images {
		if img.Status == genShipped {
			shippedImages++
		}
	}
	byCheck := map[string]int{}
	for _, c := range rep.Failed {
		byCheck[c]++
	}
	checks := make([]string, 0, len(byCheck))
	for c := range byCheck {
		checks = append(checks, c)
	}
	sort.Strings(checks)

	fmt.Fprintf(&b, "# Generated catalog entries\n\n")
	fmt.Fprintf(&b, "Build of %s, package %d. Entries made and checked by machine (checks C1 to C6), not reviewed by a person. Compared with %s.\n\n",
		cur.Build.Format("2006-01-02 15:04 UTC"), cur.Sequence, d.Against)
	fmt.Fprintf(&b, "| | |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Entries shipped | %d |\n| Images shipped | %d |\n", len(cur.Entries), shippedImages)
	fmt.Fprintf(&b, "| New | %d |\n| Changed | %d |\n| Dropped | %d |\n", len(d.New), len(d.Changed), len(d.Dropped))
	fmt.Fprintf(&b, "| Failed this build | %d |\n", len(rep.Failed))
	for _, c := range checks {
		fmt.Fprintf(&b, "| Failed %s | %d |\n", c, byCheck[c])
	}
	fmt.Fprintf(&b, "| Not checked (a source did not answer) | %d |\n", len(rep.Skipped))
	if len(cur.Stopped) > 0 {
		fmt.Fprintf(&b, "\nStopped early: %s.\n", strings.Join(cur.Stopped, ", "))
	}
	for _, l := range []struct {
		title  string
		images []string
	}{{"New", d.New}, {"Changed", d.Changed}, {"Dropped", d.Dropped}} {
		if len(l.images) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n\n", l.title)
		for _, img := range l.images {
			fmt.Fprintf(&b, "- %s\n", img)
		}
	}
	if len(rep.Failed) > 0 {
		failed := make([]string, 0, len(rep.Failed))
		for img := range rep.Failed {
			failed = append(failed, img)
		}
		sort.Strings(failed)
		fmt.Fprintf(&b, "\n## Failures\n\n")
		for _, img := range failed {
			line := fmt.Sprintf("- %s: %s", img, rep.Failed[img])
			if r := oneLine(rep.Reasons[img]); r != "" {
				line += ": " + r
			}
			fmt.Fprintln(&b, line)
		}
	}
	return b.String()
}

// oneLine keeps a reason from breaking the list it is in.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// writeGenerated writes generated.json and generated.md into
// <dir>/catalog.
func writeGenerated(dir string, cur genState, md string) error {
	out := filepath.Join(dir, generatedDir)
	if err := os.MkdirAll(out, 0o755); err != nil { //nolint:gosec // published layout
		return err
	}
	data, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(out, generatedJSON), append(data, '\n'), 0o644); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(out, generatedMD), []byte(md), 0o644)
}
