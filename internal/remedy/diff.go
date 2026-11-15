// SPDX-License-Identifier: Apache-2.0

package remedy

import (
	"errors"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
)

// Candidate is the package list of an image a container could run instead
// of its own: the newest release the data package read, or an image Varde
// read from the registry itself.
type Candidate struct {
	// Distro is "<ID>-<VERSION_ID>" from os-release ("debian-12").
	Distro   string
	Packages []inventory.Package
	// Partial marks a read that stopped at a bound: a package missing from
	// the list may still be in the image.
	Partial bool
}

// Errors of a candidate read.
var (
	// ErrImageTooLarge marks a candidate image whose layers exceed the
	// bound of one read.
	ErrImageTooLarge = errors.New("the image is larger than Varde reads")
	// ErrNoPlatform marks a candidate image without a build for the host's
	// platform.
	ErrNoPlatform = errors.New("the image has no build for the host's platform")
)

// Diff is what a candidate image does to a container's image findings.
type Diff struct {
	// Fixed are the findings the candidate no longer has, Open those it
	// still has, Unknown those Varde cannot tell about.
	Fixed, Open, Unknown []Flaw
	// Introduced are flaws only the candidate has; set only when asked
	// for, since it needs the advisories of every package of the candidate.
	Introduced []Flaw
}

// DiffImage compares a container's image findings with a candidate image,
// by the same matcher and records the analysis used. ok is false when the
// candidate is built on another distribution release than the findings
// were read from: its packages are judged by other records, and nothing
// is claimed. With introduced, advs must know the advisories of every
// checked package of the candidate.
func DiffImage(findings []match.Finding, cand Candidate, advs func(distro.Package) []match.Advisory, introduced bool) (Diff, bool) {
	candEco, _, _ := distro.Ecosystem(cand.Distro)
	for _, f := range findings {
		if eco, _, ok := strings.Cut(f.Evidence.Package, "/"); f.Image && ok && !distro.Language(eco) && eco != candEco {
			return Diff{}, false
		}
	}
	img := &inventory.Container{Distro: cand.Distro, Packages: cand.Packages}
	system, langs := identify.ImageSystemPackages(img), identify.ImageLanguagePackages(img)
	// An image can carry several copies of a language package; each one
	// counts.
	byKey := make(map[string][]distro.Package, len(system)+len(langs))
	for _, p := range append(system, langs...) {
		k := p.Ecosystem + "/" + p.Name
		byKey[k] = append(byKey[k], p)
	}
	// Presence is read from the whole list: a package the checked lists
	// leave out (a build from outside the distribution, a version that does
	// not compare) is still in the image.
	listed := identify.ImagePackageNames(img)
	// A package missing from the candidate counts as gone only when the
	// list is complete: the read did not stop at a bound, and neither did
	// the checked list.
	complete := !cand.Partial && len(system) < identify.MaxImagePackages && len(langs) < identify.MaxImagePackages

	var d Diff
	running := map[string][]match.Finding{}
	for _, f := range findings {
		if !f.Image {
			continue
		}
		running[f.Evidence.Package] = append(running[f.Evidence.Package], f)
		flaw := Flaw{AdvisoryID: f.AdvisoryID, Package: f.Evidence.Package}
		switch inRelease(f, byKey, listed, complete, advs) {
		case gone:
			d.Fixed = append(d.Fixed, flaw)
		case still:
			d.Open = append(d.Open, flaw)
		default:
			d.Unknown = append(d.Unknown, flaw)
		}
	}
	if introduced {
		d.Introduced = introducedFlaws(byKey, running, advs)
	}
	return d, true
}

// introducedFlaws are the affected advisories of the candidate's packages
// that no running finding of the same package names.
func introducedFlaws(byKey map[string][]distro.Package, running map[string][]match.Finding, advs func(distro.Package) []match.Advisory) []Flaw {
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Flaw
	seen := map[string]bool{}
	for _, k := range keys {
		eco, name, _ := strings.Cut(k, "/")
		for _, p := range byKey[k] {
			pkg := p
			recs := advs(pkg)
			if len(recs) == 0 {
				continue
			}
			in := match.Input{App: &catalog.App{ID: distro.SystemAppID(eco, name), Name: name}, Distro: &pkg}
			for _, r := range match.Match(in, recs, match.Enrichment{}) {
				if r.State != match.Affected || seen[k+"|"+r.AdvisoryID] {
					continue
				}
				known := false
				for _, f := range running[k] {
					if sameAdvisory(r, f) {
						known = true
						break
					}
				}
				if !known {
					seen[k+"|"+r.AdvisoryID] = true
					out = append(out, Flaw{AdvisoryID: r.AdvisoryID, Package: k})
				}
			}
		}
	}
	return out
}
