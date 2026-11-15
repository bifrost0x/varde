// SPDX-License-Identifier: Apache-2.0

// Package upstream decides whether a newer image of a running container
// exists upstream and what it would fix, before Varde suggests pulling one.
// It compares the running image's registry digest with what its tag points
// to now and with newer tags on the same track, and judges a candidate by
// its package list: the data package's read of the newest release, or a
// read Varde made of the candidate in the registry (never a pull into the
// Docker daemon). An update is only ever suggested for an image that is
// known to fix at least one open finding.
package upstream

import (
	"time"

	"github.com/bifrost0x/varde/internal/remedy"
)

// Kind is what Varde knows about a container's upstream image.
type Kind string

const (
	// UpdateAvailable means a newer image exists and fixes at least one of the
	// open findings.
	UpdateAvailable Kind = "update_available"
	// UpdateNoEffect means a newer image exists but fixes none of them.
	UpdateNoEffect Kind = "update_no_effect"
	// NoUpstreamFix means the container runs the newest image of its track.
	NoUpstreamFix Kind = "no_upstream_fix"
	// Unknown means Varde could not tell; Reason says why.
	Unknown Kind = "unknown"
)

// Sources of a status.
const (
	SourceRegistry    = "registry"
	SourceDataPackage = "data package"
)

// Reasons of an Unknown status that are not a registry's answer.
const (
	ReasonLocal       = "the image was built locally or never pulled from a registry, so there is no registry digest to compare"
	ReasonDigest      = "the image is pinned by digest; its tag track is not known"
	ReasonOff         = "registry checks are off; switch them on under Settings to compare with the registry"
	ReasonNotChecked  = "the registry has not been asked yet"
	ReasonCandidate   = "a newer image exists, but Varde has not read what it fixes"
	ReasonUnclear     = "a newer image exists, but Varde cannot tell for every finding whether it fixes it"
	ReasonOtherDistro = "the newer image is built on another distribution release; its packages cannot be compared"
)

// Status is what Varde knows about the upstream image of one container,
// for its image findings. It is stored as JSON (table upstream_status);
// new fields must be optional.
type Status struct {
	Kind Kind `json:"kind"`
	// Reason says why the status is Unknown, in the words of the pages.
	Reason string `json:"reason,omitempty"`
	// TargetTag and TargetDigest name the newer image, when one exists.
	// For a rebuilt floating tag the tag is the running one.
	TargetTag    string `json:"target_tag,omitempty"`
	TargetDigest string `json:"target_digest,omitempty"`
	// Rebuilt is set when the target is the running tag pointing to a
	// rebuilt image.
	Rebuilt bool `json:"rebuilt,omitempty"`
	// Fixed, Remaining and Introduced compare the target with the running
	// image: findings it no longer has, findings it still has, flaws only
	// the target has. Unclear are findings Varde cannot tell about.
	Fixed      []remedy.Flaw `json:"fixed,omitempty"`
	Remaining  []remedy.Flaw `json:"remaining,omitempty"`
	Unclear    []remedy.Flaw `json:"unclear,omitempty"`
	Introduced []remedy.Flaw `json:"introduced,omitempty"`
	// Source names where the answer comes from, Checked when it was
	// established.
	Source  string    `json:"source,omitempty"`
	Checked time.Time `json:"checked,omitzero"`
}

// Fixes reports whether the status names an update that fixes advisoryID
// in package pkg ("Debian:12/openssl").
func (s Status) Fixes(advisoryID, pkg string) bool {
	if s.Kind != UpdateAvailable {
		return false
	}
	for _, f := range s.Fixed {
		if f.AdvisoryID == advisoryID && f.Package == pkg {
			return true
		}
	}
	return false
}

// Total is the number of findings the status compared.
func (s Status) Total() int { return len(s.Fixed) + len(s.Remaining) + len(s.Unclear) }

// Actionable reports whether the status names an update to make.
func (s Status) Actionable() bool { return s.Kind == UpdateAvailable && len(s.Fixed) > 0 }
