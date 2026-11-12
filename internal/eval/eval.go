// SPDX-License-Identifier: Apache-2.0

// Package eval measures how well Varde recognises what runs: which app,
// which version, which machine, and which advisories apply. It runs the
// production code (identify, coverage, match) against a corpus with ground
// truth and reports precision, recall and version accuracy. The corpus is
// recorded data, so the numbers are reproducible offline and in CI.
package eval

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// Truth is the expected identification of one case.
type Truth struct {
	App     string `yaml:"app"`
	Version string `yaml:"version"`
	// Basis says where the truth comes from (tag, label, label+rel, user,
	// none); with none, any reported version is an error.
	Basis string `yaml:"basis"`
	Note  string `yaml:"note"`
	// Trust, if set, is the expected trust level (conflict cases).
	Trust string `yaml:"trust"`
	// Weak marks a probable match that must not be notifiable.
	Weak bool `yaml:"weak"`
}

// ContainerCase is one container.
type ContainerCase struct {
	Name          string            `yaml:"name"`
	Why           string            `yaml:"why"`
	Image         string            `yaml:"image"`
	Digest        string            `yaml:"digest"`
	ImageLabels   map[string]string `yaml:"image_labels"`
	Labels        map[string]string `yaml:"labels"`
	ContainerName string            `yaml:"container_name"`
	// RegistryTag is the recorded registry answer for the digest; the
	// evaluation replays it as the resolver would.
	RegistryTag string `yaml:"registry_tag"`
	// Packages are package database entries read from the image, as the
	// package reader stores them.
	Packages []inventory.Package `yaml:"packages"`
	Truth    Truth               `yaml:"truth"`
}

// TopologyHost is a stored host record of a topology case.
type TopologyHost struct {
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	Kind          string   `yaml:"kind"`
	Source        string   `yaml:"source"`
	OS            string   `yaml:"os"`
	Addresses     []string `yaml:"addresses"`
	IntegrationID string   `yaml:"integration_id"`
	MACs          []string `yaml:"macs"`
	MachineID     string   `yaml:"machine_id"`
	ParentID      string   `yaml:"parent_id"`
}

// TopologyCase checks that records become the right machines.
type TopologyCase struct {
	Name    string         `yaml:"name"`
	Scope   string         `yaml:"scope"`
	Hosts   []TopologyHost `yaml:"hosts"`
	Devices []string       `yaml:"devices"`
	Groups  [][]string     `yaml:"groups"`
	// Parents maps a record to the record of the machine it runs on.
	Parents map[string]string `yaml:"parents"`
}

// PackageTruth is an expected app among packages.
type PackageTruth struct {
	App     string `yaml:"app"`
	Version string `yaml:"version"`
}

// PackageCase is a package list.
type PackageCase struct {
	Name    string              `yaml:"name"`
	Why     string              `yaml:"why"`
	Fixture string              `yaml:"fixture"`
	List    []inventory.Package `yaml:"list"`
	Truth   []PackageTruth      `yaml:"truth"`
}

// MatchCase is one running version and the advisories that must apply.
type MatchCase struct {
	Name    string   `yaml:"name"`
	Why     string   `yaml:"why"`
	App     string   `yaml:"app"`
	Version string   `yaml:"version"`
	Trust   string   `yaml:"trust"`
	Expect  []string `yaml:"expect"`
}

// MatchAdvisory is an advisory reduced to its fixed version.
type MatchAdvisory struct {
	ID    string `yaml:"id"`
	Fixed string `yaml:"fixed"`
}

// DistroCase is a distribution package and the advisories that must be
// affected; all others must not be.
type DistroCase struct {
	Name    string            `yaml:"name"`
	Why     string            `yaml:"why"`
	Package inventory.Package `yaml:"package"`
	Expect  []string          `yaml:"expect"`
}

// DistroUpstream is an upstream advisory of the same CVE, with an upstream
// range, which must not decide for a distribution package.
type DistroUpstream struct {
	ID      string   `yaml:"id"`
	App     string   `yaml:"app"`
	Aliases []string `yaml:"aliases"`
	Fixed   string   `yaml:"fixed"`
}

// Corpus is the whole test corpus.
type Corpus struct {
	Containers []ContainerCase `yaml:"containers"`
	Topologies []TopologyCase  `yaml:"topologies"`
	Packages   []PackageCase   `yaml:"packages"`
	Matching   struct {
		Advisories map[string][]MatchAdvisory `yaml:"advisories"`
		Cases      []MatchCase                `yaml:"cases"`
	} `yaml:"matching"`
	// Distro holds distribution security records (real OSV records in a
	// JSON file) and package cases matched against them (ADR 0028).
	Distro struct {
		Records  string           `yaml:"records"`
		Upstream []DistroUpstream `yaml:"upstream"`
		Cases    []DistroCase     `yaml:"cases"`
	} `yaml:"distro"`
	dir string
}

// Load reads every *.yaml file of dir. containers.yaml holds the real
// container cases under "cases"; the other files use the Corpus layout.
func Load(dir string) (*Corpus, error) {
	c := &Corpus{dir: dir}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // corpus path from the test
		if err != nil {
			return nil, err
		}
		if err := c.add(filepath.Base(f), raw); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// corpusFiles is the corpus as built into the binary, for the package
// builder: its catalog generator compares every entry it makes with the
// derived one on the container cases of its images (check C6), and it
// runs from a binary, not from a checkout.
//
//go:embed testdata/corpus/*.yaml
var corpusFiles embed.FS

// ContainerCases returns the container cases of the corpus built into the
// binary.
func ContainerCases() ([]ContainerCase, error) {
	names, err := fs.Glob(corpusFiles, "testdata/corpus/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	c := &Corpus{}
	for _, n := range names {
		raw, err := corpusFiles.ReadFile(n)
		if err != nil {
			return nil, err
		}
		if err := c.add(path.Base(n), raw); err != nil {
			return nil, err
		}
	}
	return c.Containers, nil
}

// add merges one corpus file into c.
func (c *Corpus) add(name string, raw []byte) error {
	var part struct {
		Corpus `yaml:",inline"`
		Cases  []ContainerCase `yaml:"cases"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&part); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	c.Containers = append(c.Containers, part.Containers...)
	c.Containers = append(c.Containers, part.Cases...)
	c.Topologies = append(c.Topologies, part.Topologies...)
	c.Packages = append(c.Packages, part.Packages...)
	if part.Distro.Records != "" {
		c.Distro.Records = part.Distro.Records
	}
	c.Distro.Upstream = append(c.Distro.Upstream, part.Distro.Upstream...)
	c.Distro.Cases = append(c.Distro.Cases, part.Distro.Cases...)
	for app, advs := range part.Matching.Advisories {
		if c.Matching.Advisories == nil {
			c.Matching.Advisories = map[string][]MatchAdvisory{}
		}
		c.Matching.Advisories[app] = append(c.Matching.Advisories[app], advs...)
	}
	c.Matching.Cases = append(c.Matching.Cases, part.Matching.Cases...)
	return nil
}

// Counts are the outcomes of one measurement.
type Counts struct {
	// App identification: true and false positives, false negatives.
	AppTP, AppFP, AppFN int
	// Versions: correct, wrong (a version that is not the truth, or any
	// version where the truth is unknown), and missed (none reported where
	// the truth is known).
	VersionCorrect, VersionWrong, VersionMissed int
	// AppCases counts the cases whose truth names an app; Unresolved those
	// of them where nothing states the version (a floating tag without a
	// version label): the app runs some version that Varde cannot know yet.
	AppCases, Unresolved int
	// TrustWrong counts cases whose expected trust level differs.
	TrustWrong int
	// Machines: topology cases whose grouping is exactly the truth, and
	// the number of duplicates (a true machine split) and false merges.
	TopologyCorrect, TopologyTotal, Duplicates, FalseMerges int
	// Relations: expected parent links and the wrong ones among them.
	RelationsTotal, RelationsWrong int
	// Advisories: affected results that must be there, that must not, and
	// expected ones that are missing.
	MatchTP, MatchFP, MatchFN int
}

// Precision of app identification.
func (c Counts) Precision() float64 { return ratio(c.AppTP, c.AppTP+c.AppFP) }

// Recall of app identification.
func (c Counts) Recall() float64 { return ratio(c.AppTP, c.AppTP+c.AppFN) }

// VersionAccuracy is the share of known versions reported correctly.
func (c Counts) VersionAccuracy() float64 {
	return ratio(c.VersionCorrect, c.VersionCorrect+c.VersionMissed+c.VersionWrong)
}

// VersionCoverage is the share of app cases with a correct version, the
// unresolved ones included: the number the roadmap target refers to.
func (c Counts) VersionCoverage() float64 { return ratio(c.VersionCorrect, c.AppCases) }

// MatchPrecision of affected findings.
func (c Counts) MatchPrecision() float64 { return ratio(c.MatchTP, c.MatchTP+c.MatchFP) }

// MatchRecall of affected findings.
func (c Counts) MatchRecall() float64 { return ratio(c.MatchTP, c.MatchTP+c.MatchFN) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

// Failure describes one case that differs from the truth.
type Failure struct {
	Case, Kind, Got, Want string
}

// Report is the result of a run.
type Report struct {
	Counts   Counts
	Failures []Failure
}

// Run evaluates the corpus against the catalog.
func Run(c *Corpus, cat *catalog.Catalog) (Report, error) {
	var r Report
	fail := func(cs, kind, got, want string) {
		r.Failures = append(r.Failures, Failure{cs, kind, got, want})
	}
	// Derive provisional entries the way the analysis does.
	var ws []inventory.Workload
	for _, cs := range c.Containers {
		ws = append(ws, inventory.Workload{ID: cs.Name, Kind: inventory.KindContainer,
			Container: &inventory.Container{ImageRef: cs.Image, ImageLabels: cs.ImageLabels, Labels: cs.Labels}})
	}
	if derived, err := cat.WithDerived(coverage.DeriveApps(cat, nil, ws)); err == nil {
		cat = derived
	}
	for _, cs := range c.Containers {
		w := inventory.Workload{
			ID: cs.Name, Kind: inventory.KindContainer, Name: cs.ContainerName,
			Container: &inventory.Container{ImageRef: cs.Image, ImageLabels: cs.ImageLabels, Labels: cs.Labels, ResolvedTag: cs.RegistryTag, Packages: cs.Packages},
		}
		if cs.Digest != "" {
			if repo, _, ok := strings.Cut(cs.Image, ":"); ok && !strings.Contains(cs.Image, "@") {
				w.Container.RepoDigests = []string{repo + "@" + cs.Digest}
			}
		}
		got := identify.Identify(cat, w)
		scoreApp(&r, cs.Name, got, cs.Truth, fail)
	}
	for _, tc := range c.Topologies {
		if err := scoreTopology(&r, tc, fail); err != nil {
			return r, err
		}
	}
	for _, pc := range c.Packages {
		if err := scorePackages(&r, c.dir, pc, cat, fail); err != nil {
			return r, err
		}
	}
	for _, mc := range c.Matching.Cases {
		scoreMatch(&r, mc, c.Matching.Advisories[mc.App], cat, fail)
	}
	if len(c.Distro.Cases) > 0 {
		if err := scoreDistro(&r, c, cat, fail); err != nil {
			return r, err
		}
	}
	return r, nil
}

// scoreDistro identifies each package as the analysis does and matches it
// against the stored distribution records and the upstream advisories.
func scoreDistro(r *Report, c *Corpus, cat *catalog.Catalog, fail func(string, string, string, string)) error {
	raw, err := os.ReadFile(filepath.Join(c.dir, c.Distro.Records)) //nolint:gosec // corpus path from the test
	if err != nil {
		return err
	}
	var vulns []advisory.Vulnerability
	if err := json.Unmarshal(raw, &vulns); err != nil {
		return fmt.Errorf("%s: %w", c.Distro.Records, err)
	}
	for _, dc := range c.Distro.Cases {
		pkg := dc.Package
		got := identify.Identify(cat, inventory.Workload{ID: dc.Name, Kind: inventory.KindPackage, Package: &pkg})
		app, ok := cat.App(got.AppID)
		if !ok {
			fail(dc.Name, "distro", "no app", pkg.Name)
			continue
		}
		stored := make([]match.Advisory, 0, len(vulns))
		for _, v := range vulns {
			stored = append(stored, match.Advisory{Source: match.SourceDistro, Vuln: v})
		}
		for _, u := range c.Distro.Upstream {
			if u.App != app.ID {
				continue
			}
			stored = append(stored, match.Advisory{Source: "nvd", Vuln: advisory.Vulnerability{
				ID: u.ID, Aliases: u.Aliases,
				Affected: []advisory.Affected{{Ranges: []advisory.Range{{Type: advisory.RangeSemver, Events: []advisory.Event{{Introduced: "0"}, {Fixed: u.Fixed}}}}}},
			}})
		}
		findings := match.Match(match.Input{App: app, Version: got.Version, VersionSource: got.VersionSource, Doubt: got.Doubt(), Distro: got.DistroPackage}, stored, match.Enrichment{})
		scoreExpected(r, dc.Name, findings, dc.Expect, fail)
	}
	return nil
}

// scoreExpected counts affected findings against the expected IDs.
func scoreExpected(r *Report, name string, findings []match.Finding, expect []string, fail func(string, string, string, string)) {
	want := map[string]bool{}
	for _, id := range expect {
		want[id] = true
	}
	got := map[string]bool{}
	for _, f := range findings {
		if f.State == match.Affected {
			got[f.AdvisoryID] = true
		}
	}
	for id := range got {
		if want[id] {
			r.Counts.MatchTP++
		} else {
			r.Counts.MatchFP++
			fail(name, "advisory", id, "not affected")
		}
	}
	for id := range want {
		if !got[id] {
			r.Counts.MatchFN++
			fail(name, "advisory", "not affected", id)
		}
	}
}

func scoreApp(r *Report, name string, got identify.Result, t Truth, fail func(string, string, string, string)) {
	if t.App != "" && !t.Weak {
		r.Counts.AppCases++
		if t.Version == "" && t.Basis == "none" {
			r.Counts.Unresolved++
		}
	}
	gotApp := got.AppID
	if t.Weak {
		if got.Confidence.Notifiable() {
			fail(name, "weak match notifiable", string(got.Confidence), "weak")
			r.Counts.AppFP++
		} else {
			r.Counts.AppTP++
		}
		return
	}
	if !got.Confidence.Notifiable() {
		gotApp = ""
	}
	switch {
	case gotApp != "" && gotApp == t.App:
		r.Counts.AppTP++
	case gotApp != "" && gotApp != t.App:
		r.Counts.AppFP++
		fail(name, "app", gotApp, t.App)
		if t.App != "" {
			r.Counts.AppFN++
		}
		return
	case gotApp == "" && t.App != "":
		r.Counts.AppFN++
		fail(name, "app", "", t.App)
		return
	default:
		return // correctly nothing
	}
	if t.Trust != "" && string(got.Trust) != t.Trust {
		r.Counts.TrustWrong++
		fail(name, "trust", string(got.Trust), t.Trust)
	}
	// A conflict is not a usable version: the user must settle it.
	v := got.Version
	if got.Trust == identify.Conflict {
		v = ""
	}
	switch {
	case t.Version == "" && v == "":
	case t.Version == "":
		r.Counts.VersionWrong++
		fail(name, "version", v, "unknown ("+t.Note+")")
	case v == "":
		r.Counts.VersionMissed++
		fail(name, "version", "", t.Version)
	case sameVersion(v, t.Version):
		r.Counts.VersionCorrect++
	default:
		r.Counts.VersionWrong++
		fail(name, "version", v, t.Version)
	}
}

// sameVersion accepts a shorter form of the truth ("4.0.15" for
// "4.0.15.2941"); a different release is wrong.
func sameVersion(got, want string) bool {
	got, want = strings.TrimPrefix(got, "v"), strings.TrimPrefix(want, "v")
	if got == want {
		return true
	}
	g, w := strings.Split(got, "."), strings.Split(want, ".")
	if len(g) > len(w) {
		return false
	}
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

func scoreTopology(r *Report, tc TopologyCase, fail func(string, string, string, string)) error {
	scope, err := discovery.ParseScope(tc.Scope)
	if err != nil {
		return fmt.Errorf("%s: %w", tc.Name, err)
	}
	var in coverage.MachineInput
	in.Scope = scope
	for _, h := range tc.Hosts {
		in.Hosts = append(in.Hosts, inventory.Host{
			ID: h.ID, Name: h.Name, Kind: inventory.HostKind(h.Kind), Source: inventory.HostSource(h.Source), OS: h.OS,
			Addresses: h.Addresses, IntegrationID: h.IntegrationID, MACs: h.MACs, MachineID: h.MachineID, ParentID: h.ParentID,
		})
	}
	for _, d := range tc.Devices {
		in.Devices = append(in.Devices, storedDevice(d))
	}
	ms := coverage.Machines(in)
	got := map[string]int{}
	for i, m := range ms {
		for _, id := range m.HostIDs {
			got[id] = i
		}
		for _, e := range m.Evidence {
			if e.Source == coverage.EvidenceScan {
				got["device:"+e.Addresses[0]] = i
			}
		}
	}
	r.Counts.TopologyTotal++
	ok := len(ms) == len(tc.Groups)
	for _, g := range tc.Groups {
		seen := map[int]bool{}
		for _, id := range g {
			seen[got[id]] = true
		}
		if len(seen) > 1 {
			ok = false
			r.Counts.Duplicates += len(seen) - 1
			fail(tc.Name, "machine split", strings.Join(g, "+"), "one machine")
		}
	}
	owner := map[int]int{}
	for gi, g := range tc.Groups {
		for _, id := range g {
			if prev, dup := owner[got[id]]; dup && prev != gi {
				ok = false
				r.Counts.FalseMerges++
				fail(tc.Name, "false merge", id, "separate machine")
			}
			owner[got[id]] = gi
		}
	}
	for child, parent := range tc.Parents {
		r.Counts.RelationsTotal++
		c, p := got[child], got[parent]
		if ms[c].ParentID != ms[p].ID {
			ok = false
			r.Counts.RelationsWrong++
			fail(tc.Name, "parent", ms[c].ParentName, ms[p].Name)
		}
	}
	if ok {
		r.Counts.TopologyCorrect++
	}
	return nil
}

func scorePackages(r *Report, dir string, pc PackageCase, cat *catalog.Catalog, fail func(string, string, string, string)) error {
	inv := integrations.HostInventory{Packages: pc.List}
	if pc.Fixture != "" {
		raw, err := os.ReadFile(filepath.Join(dir, pc.Fixture)) //nolint:gosec // corpus path from the test
		if err != nil {
			return err
		}
		if inv, err = integrations.ParseInventory(raw); err != nil {
			return fmt.Errorf("%s: %w", pc.Name, err)
		}
	}
	pkgs, svcs, _ := integrations.InventoryWorkloads(cat, inv)
	want := map[string]PackageTruth{}
	for _, t := range pc.Truth {
		want[t.App] = t
	}
	seen := map[string]bool{}
	for _, w := range append(pkgs, svcs...) {
		got := identify.Identify(cat, w)
		seen[got.AppID] = true
		t, ok := want[got.AppID]
		if !ok {
			r.Counts.AppFP++
			fail(pc.Name, "app", got.AppID, "")
			continue
		}
		scoreApp(r, pc.Name+" "+got.AppID, got, Truth{App: t.App, Version: t.Version, Basis: "package"}, fail)
	}
	for app := range want {
		if !seen[app] {
			r.Counts.AppFN++
			fail(pc.Name, "app", "", app)
		}
	}
	return nil
}

func scoreMatch(r *Report, mc MatchCase, advs []MatchAdvisory, cat *catalog.Catalog, fail func(string, string, string, string)) {
	app, ok := cat.App(mc.App)
	if !ok {
		fail(mc.Name, "matching", "app not in catalog", mc.App)
		return
	}
	var stored []match.Advisory
	for _, a := range advs {
		stored = append(stored, match.Advisory{Source: "github", Vuln: advisory.Vulnerability{
			ID: a.ID,
			Affected: []advisory.Affected{{
				// As GitHub publishes vaultwarden's repository advisories.
				Package: advisory.Package{Ecosystem: "rust", Name: app.ID},
				Ranges:  []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: a.Fixed}}}},
			}},
		}})
	}
	res := identify.Result{AppID: app.ID, Version: mc.Version, VersionSource: "corpus", Trust: identify.Trust(mc.Trust)}
	if mc.Trust == string(identify.Conflict) {
		res.Evidence = []identify.Evidence{{Method: "a", Version: mc.Version}, {Method: "b", Version: "0.0.1"}}
	}
	findings := match.Match(match.Input{App: app, Version: mc.Version, VersionSource: "corpus", Doubt: res.Doubt()}, stored, match.Enrichment{})
	want := map[string]bool{}
	for _, id := range mc.Expect {
		want[id] = true
	}
	got := map[string]bool{}
	for _, f := range findings {
		if f.State == match.Affected {
			got[f.AdvisoryID] = true
		}
	}
	for id := range got {
		if want[id] {
			r.Counts.MatchTP++
		} else {
			r.Counts.MatchFP++
			fail(mc.Name, "advisory", id, "not affected")
		}
	}
	for id := range want {
		if !got[id] {
			r.Counts.MatchFN++
			fail(mc.Name, "advisory", "", id)
		}
	}
}

func storedDevice(addr string) store.StoredDevice {
	return store.StoredDevice{Device: discovery.Device{Address: addr, Kind: discovery.KindOther, Label: "device"}}
}
