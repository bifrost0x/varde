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
	// Fixed are the findings the release no longer has, Open those it
	// still has or cannot be shown to be rid of.
	Fixed, Open []Flaw
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
func (f ReleaseFix) Total() int { return len(f.Fixed) + len(f.Open) }

// ReleaseFixFor compares a container's image findings with the newest
// release of app, read for the container's host platform (the zero
// Platform when unknown: amd64). running is the canonical version the
// container runs; advs returns the advisories a package was matched
// against, so a package of the release is judged by the same records.
//
// ok is set when the release is newer than running and there are image
// findings to compare: only then does the result say what the release
// fixes. Otherwise Tag, Version and Read still name the release when a
// line for the platform exists, and Newest says that the container runs
// it already (or a later version); with an unknown running version nothing
// is claimed.
func ReleaseFixFor(app *catalog.App, running string, platform registry.Platform, findings []match.Finding, lines []feed.ReleaseLine, advs func(pkg distro.Package) []match.Advisory) (ReleaseFix, bool) {
	if app == nil {
		return ReleaseFix{}, false
	}
	rel, ok := releaseLine(lines, platform)
	if !ok {
		return ReleaseFix{}, false
	}
	fix := ReleaseFix{Tag: rel.Tag, Version: rel.Version, Read: rel.Read}
	if running == "" {
		return fix, false
	}
	have, err := version.Parse(app.Version.Scheme, running)
	if err != nil {
		return fix, false
	}
	newest, err := version.Parse(app.Version.Scheme, rel.Version)
	if err != nil {
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

	img := &inventory.Container{Distro: rel.Distro, Packages: rel.Packages}
	system, langs := identify.ImageSystemPackages(img), identify.ImageLanguagePackages(img)
	byKey := make(map[string]distro.Package, len(system)+len(langs))
	for _, p := range append(system, langs...) {
		byKey[p.Ecosystem+"/"+p.Name] = p
	}
	// A package missing from the release counts as gone only when the
	// list is complete: the read did not stop at a bound, and neither did
	// the checked list.
	complete := !rel.Partial && len(system) < identify.MaxImagePackages && len(langs) < identify.MaxImagePackages
	releaseEco, _, _ := distro.Ecosystem(rel.Distro)

	for _, f := range findings {
		if !f.Image {
			continue
		}
		flaw := Flaw{AdvisoryID: f.AdvisoryID, Package: f.Evidence.Package}
		if fixedIn(f, byKey, complete, releaseEco, advs) {
			fix.Fixed = append(fix.Fixed, flaw)
		} else {
			fix.Open = append(fix.Open, flaw)
		}
	}
	return fix, fix.Total() > 0
}

// fixedIn reports whether the release no longer has finding f.
func fixedIn(f match.Finding, byKey map[string]distro.Package, complete bool, releaseEco string, advs func(distro.Package) []match.Advisory) bool {
	eco, name, ok := strings.Cut(f.Evidence.Package, "/")
	if !ok || eco == "" || name == "" {
		return false
	}
	p, ok := byKey[eco+"/"+name]
	if !ok {
		// Not in the release. A language package is gone; a
		// distribution's package only when the release is on the same
		// distribution release: on another, its packages are judged by
		// other records, which this finding was not matched with.
		return complete && (distro.Language(eco) || eco == releaseEco)
	}
	// The same matcher and records as the analysis, so the answer agrees
	// with the findings page; an unverified result is no fix either.
	pkg := p
	in := match.Input{App: &catalog.App{ID: distro.SystemAppID(eco, name), Name: name}, Distro: &pkg}
	for _, r := range match.Match(in, advs(distro.Package{Ecosystem: eco, Name: name, Version: f.Evidence.Version}), match.Enrichment{}) {
		if sameAdvisory(r, f) {
			return false
		}
	}
	return true
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
