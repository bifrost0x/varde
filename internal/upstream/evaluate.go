// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/store"
)

// Input is what Evaluate decides one container's status from.
type Input struct {
	Container *inventory.Container
	// Platform is the platform of the container's host; the zero Platform
	// when unknown.
	Platform registry.Platform
	// Findings are the container's active, affected image findings.
	Findings []match.Finding
	// Check is the registry's answer for the running image, nil when
	// there is none.
	Check *store.UpstreamCheck
	// App, Running and Lines are the data package's read of the newest
	// release of the container's app; App is nil when there is none.
	App     *catalog.App
	Running remedy.Running
	Lines   []feed.ReleaseLine
	// RegistryOn is the setting that lets Varde ask registries.
	RegistryOn bool
	// Advisories returns the advisories of a package, as the analysis
	// matched them; it must know every package of a candidate for the
	// introduced flaws to be complete.
	Advisories func(distro.Package) []match.Advisory
}

// Evaluate decides what Varde knows about a newer image of one container.
// It claims an update only for an image whose package list it compared
// and that fixes at least one finding; whatever it cannot establish is
// Unknown with the reason.
func Evaluate(in Input) Status {
	c := in.Container
	if c == nil {
		return Status{Kind: Unknown, Reason: ReasonLocal}
	}
	ref, err := imageref.Parse(c.ImageRef)
	if err != nil {
		return Status{Kind: Unknown, Reason: ReasonLocal}
	}
	if ref.Tag == "" && ref.Digest != "" {
		return Status{Kind: Unknown, Reason: ReasonDigest}
	}
	running := registry.RepoDigest(c, ref.Repository)
	if running == "" {
		return Status{Kind: Unknown, Reason: ReasonLocal}
	}
	if ck := in.Check; ck != nil && ck.Error == "" {
		return fromCheck(in, *ck)
	}
	if st, ok := fromDataPackage(in, running); ok {
		return st
	}
	switch {
	case in.Check != nil:
		return Status{Kind: Unknown, Reason: in.Check.Error, Source: SourceRegistry, Checked: in.Check.Checked}
	case !in.RegistryOn:
		return Status{Kind: Unknown, Reason: ReasonOff}
	}
	return Status{Kind: Unknown, Reason: ReasonNotChecked}
}

// fromCheck is the status the registry's answer gives.
func fromCheck(in Input, ck store.UpstreamCheck) Status {
	base := Status{Source: SourceRegistry, Checked: ck.Checked}
	if ck.CandidateDigest == "" {
		base.Kind = NoUpstreamFix
		return base
	}
	base.TargetTag, base.TargetDigest = ck.CandidateTag, ck.CandidateDigest
	base.Rebuilt = ck.CandidateTag == ck.Tag
	if ck.Candidate != nil {
		cand, err := DecodeCandidate(ck.Candidate)
		if err == nil {
			return classify(base, in, cand)
		}
		base.Kind, base.Reason = Unknown, ReasonCandidate
		return base
	}
	// The data package may have read the same image.
	if line, ok := remedy.ReleaseLineFor(in.Lines, in.Platform); ok && (line.IndexDigest == ck.CandidateDigest || line.ManifestDigest == ck.CandidateDigest) {
		base.Source = SourceDataPackage
		return classify(base, in, remedy.Candidate{Distro: line.Distro, Packages: line.Packages, Partial: line.Partial})
	}
	base.Kind, base.Reason = Unknown, ReasonCandidate
	if ck.CandidateError != "" {
		base.Reason = ReasonCandidate + " (" + ck.CandidateError + ")"
	}
	return base
}

// fromDataPackage is the status the data package's read of the newest
// release gives; ok is false when it says nothing about this container.
func fromDataPackage(in Input, running string) (Status, bool) {
	if in.App == nil || len(in.Lines) == 0 {
		return Status{}, false
	}
	line, ok := remedy.ReleaseLineFor(in.Lines, in.Platform)
	if !ok {
		return Status{}, false
	}
	base := Status{Source: SourceDataPackage, Checked: line.Read}
	if running == line.IndexDigest || running == line.ManifestDigest {
		// The container runs the newest release as the data package read
		// it: nothing newer exists.
		base.Kind = NoUpstreamFix
		return base, true
	}
	fix, newer := remedy.ReleaseFixFor(in.App, in.Running, in.Platform, in.Findings, in.Lines, in.Advisories)
	cand := remedy.Candidate{Distro: line.Distro, Packages: line.Packages, Partial: line.Partial}
	switch {
	case newer:
		base.TargetTag, base.TargetDigest = fix.Tag, lineDigest(line)
		return classify(base, in, cand), true
	case fix.Newest && fix.Tag != "" && fix.Tag == in.Running.Tag:
		// The very release tag the container runs, under another digest:
		// the release was rebuilt and the running tag pulls the rebuild.
		// A data package that read an older release says nothing about
		// what the running tag points to.
		ref, err := imageref.Parse(in.Container.ImageRef)
		if err != nil {
			return Status{}, false
		}
		base.TargetTag, base.TargetDigest, base.Rebuilt = tagOrLatest(ref.Tag), lineDigest(line), true
		return classify(base, in, cand), true
	}
	return Status{}, false
}

func lineDigest(l feed.ReleaseLine) string {
	if l.IndexDigest != "" {
		return l.IndexDigest
	}
	return l.ManifestDigest
}

func tagOrLatest(tag string) string {
	if tag == "" {
		return "latest"
	}
	return tag
}

// classify compares the findings with a candidate and names the status.
func classify(base Status, in Input, cand remedy.Candidate) Status {
	adv := in.Advisories
	if adv == nil {
		adv = func(distro.Package) []match.Advisory { return nil }
	}
	d, ok := remedy.DiffImage(in.Findings, cand, adv, true)
	if !ok {
		base.Kind, base.Reason = Unknown, ReasonOtherDistro
		return base
	}
	base.Fixed, base.Remaining, base.Unclear, base.Introduced = d.Fixed, d.Open, d.Unknown, d.Introduced
	switch {
	case len(d.Fixed) > 0:
		base.Kind = UpdateAvailable
	case len(d.Unknown) == 0:
		base.Kind = UpdateNoEffect
	default:
		base.Kind, base.Reason = Unknown, ReasonUnclear
	}
	return base
}

// maxCandidateJSON bounds a decoded candidate package list.
const maxCandidateJSON = 64 << 20

// EncodeCandidate is the stored form of a candidate package list.
func EncodeCandidate(c remedy.Candidate) ([]byte, error) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if err := json.NewEncoder(zw).Encode(c); err != nil {
		return nil, fmt.Errorf("encode candidate: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("encode candidate: %w", err)
	}
	return b.Bytes(), nil
}

// DecodeCandidate reads a stored candidate package list.
func DecodeCandidate(b []byte) (remedy.Candidate, error) {
	var c remedy.Candidate
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return c, fmt.Errorf("decode candidate: %w", err)
	}
	defer func() { _ = zr.Close() }()
	raw, err := io.ReadAll(io.LimitReader(zr, maxCandidateJSON+1))
	if err != nil {
		return c, fmt.Errorf("decode candidate: %w", err)
	}
	if len(raw) > maxCandidateJSON {
		return c, fmt.Errorf("decode candidate: larger than %d bytes", maxCandidateJSON)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("decode candidate: %w", err)
	}
	return c, nil
}

// PlatformKey is the platform of a check: "linux/amd64", "linux/arm/v7";
// empty when unknown.
func PlatformKey(p registry.Platform) string {
	if p.Arch == "" {
		return ""
	}
	os := p.OS
	if os == "" {
		os = "linux"
	}
	k := os + "/" + p.Arch
	if p.Variant != "" {
		k += "/" + p.Variant
	}
	return k
}

// KeyOf is the check key of a container on a host platform; ok is false
// for an image without a registry digest or tag.
func KeyOf(c *inventory.Container, p registry.Platform) (store.UpstreamKey, bool) {
	if c == nil {
		return store.UpstreamKey{}, false
	}
	ref, err := imageref.Parse(c.ImageRef)
	if err != nil || (ref.Tag == "" && ref.Digest != "") {
		return store.UpstreamKey{}, false
	}
	d := registry.RepoDigest(c, ref.Repository)
	if d == "" {
		return store.UpstreamKey{}, false
	}
	return store.UpstreamKey{Repository: ref.Repository, Tag: tagOrLatest(ref.Tag), RunningDigest: d, Platform: PlatformKey(p)}, true
}
