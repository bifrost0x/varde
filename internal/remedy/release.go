// SPDX-License-Identifier: Apache-2.0

package remedy

import (
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/version"
)

// ReleaseFix says which of a container's image findings the newest release
// of its app fixes, by the package list the data package read of that
// release's image.
type ReleaseFix struct {
	// Tag and Version name the newest release.
	Tag, Version string
	// Fixed are the findings the release no longer has; Open those it
	// still has: no release fixes them yet. Unknown are those Varde cannot
	// tell about: the package is missing from a list that was not read
	// completely, or the release's package is not comparable.
	Fixed, Open, Unknown []Flaw
	// Newest is set when the container already runs that release or a
	// later one: no release fixes anything yet.
	Newest bool
	// Read is when the release's packages were read.
	Read time.Time
}

// Flaw is one image finding: an advisory in a package.
type Flaw struct {
	AdvisoryID string
	// Package is "Ecosystem/name" as the finding's evidence names it.
	Package string
}

// Total is the number of findings compared.
func (f ReleaseFix) Total() int { return len(f.Fixed) + len(f.Open) + len(f.Unknown) }

// Running is the image a container runs.
type Running struct {
	// Repository is the normalised image repository; Tag the version tag
	// the container runs (for a floating tag the one the registry gives
	// its image), empty when unknown or not trusted.
	Repository, Tag string
}

// ReleaseFixFor compares a container's image findings with the newest
// release of app (as identify.AppForImage reads the container's image),
// read for the container's host platform (the zero Platform when unknown:
// amd64). advs returns the advisories a package was matched against, so a
// package of the release is judged by the same records.
//
// ok is set when the release is newer than the running one, of the same
// image variant and distribution, and there are image findings to compare:
// only then does the result say what the release fixes. Otherwise Tag,
// Version and Read still name the release when a line for the platform
// exists, and Newest says that the container runs it already (or a later
// version); nothing else is claimed.
func ReleaseFixFor(app *catalog.App, run Running, platform registry.Platform, findings []match.Finding, lines []feed.ReleaseLine, advs func(pkg distro.Package) []match.Advisory) (ReleaseFix, bool) {
	if app == nil {
		return ReleaseFix{}, false
	}
	rel, ok := releaseLine(lines, platform)
	if !ok {
		return ReleaseFix{}, false
	}
	fix := ReleaseFix{Tag: rel.Tag, Version: rel.Version, Read: rel.Read}
	// Both tags are read the same way, without their variant suffix
	// ("1.2.0-alpine" is release 1.2.0), as update suggestions read them.
	have, haveSuffix, ok := tagRelease(app, run.Repository, run.Tag)
	if !ok {
		return fix, false
	}
	newest, newestSuffix, ok := tagRelease(app, run.Repository, rel.Tag)
	if !ok {
		return fix, false
	}
	c, ok := newest.Compare(have)
	if !ok {
		return fix, false
	}
	if c <= 0 {
		// The same release, or a tag stream that went back: the release
		// fixes nothing the container could get by updating.
		fix.Newest = true
		return fix, false
	}
	// Another variant of the image ("-alpine", "-slim", "-bookworm") has
	// other packages: its list says nothing about the container's.
	if suffixClass(haveSuffix) != suffixClass(newestSuffix) {
		return fix, false
	}
	// Nor does an image on another distribution release: its packages are
	// judged by other records than the container's findings were.
	releaseEco, _, _ := distro.Ecosystem(rel.Distro)
	for _, f := range findings {
		if eco, _, ok := strings.Cut(f.Evidence.Package, "/"); f.Image && ok && !distro.Language(eco) && eco != releaseEco {
			return fix, false
		}
	}

	img := &inventory.Container{Distro: rel.Distro, Packages: rel.Packages}
	system, langs := identify.ImageSystemPackages(img), identify.ImageLanguagePackages(img)
	// An image can carry several copies of a language package; each one
	// counts.
	byKey := make(map[string][]distro.Package, len(system)+len(langs))
	for _, p := range append(system, langs...) {
		k := p.Ecosystem + "/" + p.Name
		byKey[k] = append(byKey[k], p)
	}
	// A package missing from the release counts as gone only when the
	// list is complete: the read did not stop at a bound, and neither did
	// the checked list.
	complete := !rel.Partial && len(system) < identify.MaxImagePackages && len(langs) < identify.MaxImagePackages

	for _, f := range findings {
		if !f.Image {
			continue
		}
		flaw := Flaw{AdvisoryID: f.AdvisoryID, Package: f.Evidence.Package}
		switch inRelease(f, byKey, complete, advs) {
		case gone:
			fix.Fixed = append(fix.Fixed, flaw)
		case still:
			fix.Open = append(fix.Open, flaw)
		default:
			fix.Unknown = append(fix.Unknown, flaw)
		}
	}
	return fix, fix.Total() > 0
}

// tagRelease is the release a tag names for app, and the variant suffix
// around it ("-alpine"); ok is false for floating and unrelated tags.
func tagRelease(app *catalog.App, repository, tag string) (version.Version, string, bool) {
	if tag == "" {
		return version.Version{}, "", false
	}
	canon, ok := identify.TagRelease(app, repository, tag)
	if !ok {
		return version.Version{}, "", false
	}
	_, suffix, ok := template(tag, canon)
	if !ok {
		return version.Version{}, "", false
	}
	v, err := version.Parse(app.Version.Scheme, canon)
	if err != nil {
		return version.Version{}, "", false
	}
	return v, suffix, true
}

// presence is what a release says about a finding.
type presence int

const (
	unknown presence = iota
	gone             // the release does not have it
	still            // the release has it too
)

// inRelease tells whether the release still has finding f.
func inRelease(f match.Finding, byKey map[string][]distro.Package, complete bool, advs func(distro.Package) []match.Advisory) presence {
	eco, name, ok := strings.Cut(f.Evidence.Package, "/")
	if !ok || eco == "" || name == "" {
		return unknown
	}
	copies := byKey[eco+"/"+name]
	if len(copies) == 0 {
		// Not in the release; on the same distribution release (checked
		// by the caller), or a language package.
		if complete {
			return gone
		}
		return unknown
	}
	// The same matcher and records as the analysis, so the answer agrees
	// with the findings page. One affected copy keeps the finding; an
	// unverified result is no answer either way.
	recs := advs(distro.Package{Ecosystem: eco, Name: name, Version: f.Evidence.Version})
	out := gone
	for _, p := range copies {
		pkg := p
		in := match.Input{App: &catalog.App{ID: distro.SystemAppID(eco, name), Name: name}, Distro: &pkg}
		for _, r := range match.Match(in, recs, match.Enrichment{}) {
			if !sameAdvisory(r, f) {
				continue
			}
			if r.State == match.Affected {
				return still
			}
			out = unknown
		}
	}
	return out
}

// sameAdvisory reports whether two findings name the same advisory.
func sameAdvisory(a, b match.Finding) bool {
	ids := map[string]bool{a.AdvisoryID: true}
	for _, id := range a.Aliases {
		ids[id] = true
	}
	if ids[b.AdvisoryID] {
		return true
	}
	for _, id := range b.Aliases {
		if ids[id] {
			return true
		}
	}
	return false
}

// releaseLine picks the line of the host's platform. A line of another
// platform never stands in: amd64 and arm64 images of one release can
// carry different packages. The exception is a single-platform image, which
// is what the tag pulls on every host.
func releaseLine(lines []feed.ReleaseLine, host registry.Platform) (feed.ReleaseLine, bool) {
	if host.Arch == "" {
		host = registry.Platform{OS: "linux", Arch: "amd64"}
	}
	if host.OS == "" {
		host.OS = "linux"
	}
	want := variant(host.Arch, host.Variant)
	var same, exact []feed.ReleaseLine
	for _, l := range lines {
		if l.Platform.OS != host.OS || l.Platform.Arch != host.Arch {
			continue
		}
		same = append(same, l)
		if variant(l.Platform.Arch, l.Platform.Variant) == want {
			exact = append(exact, l)
		}
	}
	switch {
	case len(exact) == 1:
		return exact[0], true
	case len(same) == 1 && (want == "" || same[0].Platform.Variant == ""):
		// One image of the architecture, and the host's or the line's
		// variant is not known.
		return same[0], true
	case len(same) == 0 && len(lines) == 1 && lines[0].IndexDigest == "":
		return lines[0], true
	}
	return feed.ReleaseLine{}, false
}

// variant is a platform variant with the default of its architecture
// dropped: arm64 images are "v8" or name none.
func variant(arch, v string) string {
	if arch == "arm64" && v == "v8" {
		return ""
	}
	return v
}

// HostPlatform is the OCI platform of a host from the architecture its
// agent (Go's GOARCH) or Docker (uname: "x86_64", "aarch64") reports; the
// zero Platform when it is unknown. Containers run Linux images.
func HostPlatform(arch string) registry.Platform {
	p := registry.Platform{OS: "linux"}
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "amd64", "x86_64", "x86-64":
		p.Arch = "amd64"
	case "arm64", "aarch64", "armv8", "arm64v8":
		p.Arch = "arm64"
	case "armv7l", "armv7", "armhf", "arm32v7":
		p.Arch, p.Variant = "arm", "v7"
	case "armv6l", "armv6", "armel", "arm32v6":
		p.Arch, p.Variant = "arm", "v6"
	case "arm":
		p.Arch = "arm"
	case "386", "i386", "i686":
		p.Arch = "386"
	case "ppc64le", "s390x", "riscv64":
		p.Arch = strings.ToLower(strings.TrimSpace(arch))
	default:
		return registry.Platform{}
	}
	return p
}
