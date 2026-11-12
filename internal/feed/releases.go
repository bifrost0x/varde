// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/registry"
)

// ReleaseLine is one line of the releases blob: the package list of the
// newest release of a catalog app's image, for one platform, as the
// package builder read it from the registry. An installation compares it
// with what its containers run to tell which findings that release fixes.
type ReleaseLine struct {
	AppID string `json:"app_id"`
	// Image is the normalised image repository ("docker.io/grafana/grafana").
	Image   string `json:"image"`
	Tag     string `json:"tag"`
	Version string `json:"version"`
	// IndexDigest is the digest of the image index the tag points to;
	// empty for a single-platform image.
	IndexDigest    string          `json:"index_digest,omitempty"`
	Platform       ReleasePlatform `json:"platform"`
	ManifestDigest string          `json:"manifest_digest"`
	Read           time.Time       `json:"read"`
	// Distro is "<ID>-<VERSION_ID>" from os-release ("debian-12"), OS
	// the readable name.
	Distro string `json:"distro,omitempty"`
	OS     string `json:"os_name,omitempty"`
	// Partial marks a read that stopped at a bound: a package missing from
	// the list may still be in the release.
	Partial  bool                `json:"partial,omitempty"`
	Packages []inventory.Package `json:"packages"`
}

// ReleasePlatform is the platform of a release line, with the keys of an
// OCI image index (registry.Platform has no JSON form of its own).
type ReleasePlatform struct {
	OS      string `json:"os"`
	Arch    string `json:"architecture"`
	Variant string `json:"variant,omitempty"`
}

// PlatformOf is the release platform of a registry platform.
func PlatformOf(p registry.Platform) ReleasePlatform {
	return ReleasePlatform{OS: p.OS, Arch: p.Arch, Variant: p.Variant}
}

// Registry is the registry platform of p.
func (p ReleasePlatform) Registry() registry.Platform {
	return registry.Platform{OS: p.OS, Arch: p.Arch, Variant: p.Variant}
}

var (
	versionRe  = regexp.MustCompile(`^[A-Za-z0-9._+~:-]{1,128}$`)
	digestRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tagRe      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	platformRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// maxReleaseLine bounds one line: 20000 packages with long names fit.
const maxReleaseLine = 16 << 20

// Validate checks a line with the bounds of every other record that comes
// from outside the installation; the packages get the checks of an agent's
// image record (inventory.CheckImagePackages).
func (l ReleaseLine) Validate() error {
	if !appIDRe.MatchString(l.AppID) {
		return fmt.Errorf("invalid app id %q", l.AppID)
	}
	if repo, err := imageref.NormaliseRepository(l.Image); err != nil || repo != l.Image || len(l.Image) > 256 {
		return fmt.Errorf("%s: image is not a normalised repository", l.AppID)
	}
	if !tagRe.MatchString(l.Tag) {
		return fmt.Errorf("%s: invalid tag", l.AppID)
	}
	if !versionRe.MatchString(l.Version) {
		return fmt.Errorf("%s: invalid version", l.AppID)
	}
	if (l.IndexDigest != "" && !digestRe.MatchString(l.IndexDigest)) || !digestRe.MatchString(l.ManifestDigest) {
		return fmt.Errorf("%s: invalid digest", l.AppID)
	}
	p := l.Platform
	if !platformRe.MatchString(p.OS) || !platformRe.MatchString(p.Arch) || (p.Variant != "" && !platformRe.MatchString(p.Variant)) {
		return fmt.Errorf("%s: invalid platform", l.AppID)
	}
	if l.Read.IsZero() {
		return fmt.Errorf("%s: no read time", l.AppID)
	}
	if err := inventory.CheckImagePackages(l.Distro, l.OS, l.Packages); err != nil {
		return fmt.Errorf("%s: %w", l.AppID, err)
	}
	return nil
}

// key identifies a line: one package list per app, image and platform.
func (l ReleaseLine) key() [5]string {
	return [...]string{l.AppID, l.Image, l.Platform.OS, l.Platform.Arch, l.Platform.Variant}
}

func (l ReleaseLine) String() string {
	k := l.key()
	return fmt.Sprintf("%s %s %s/%s/%s", k[0], k[1], k[2], k[3], k[4])
}

// releaseLess orders lines by app, image and platform, so the same reads
// give the same blob.
func releaseLess(a, b ReleaseLine) bool {
	ka, kb := a.key(), b.key()
	for i := range ka {
		if ka[i] != kb[i] {
			return ka[i] < kb[i]
		}
	}
	return false
}

// marshalReleases encodes lines as sorted JSONL. The builder refuses a line
// installations would refuse.
func marshalReleases(lines []ReleaseLine) ([]byte, error) {
	sorted := append([]ReleaseLine(nil), lines...)
	sort.SliceStable(sorted, func(i, j int) bool { return releaseLess(sorted[i], sorted[j]) })
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i, l := range sorted {
		if err := l.Validate(); err != nil {
			return nil, fmt.Errorf("releases: %w", err)
		}
		if i > 0 && sorted[i-1].key() == l.key() {
			return nil, fmt.Errorf("releases: %s listed twice", l)
		}
		if err := enc.Encode(l); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// parseReleases decodes and validates the releases blob.
func parseReleases(data []byte) ([]ReleaseLine, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), maxReleaseLine)
	var out []ReleaseLine
	seen := map[[5]string]bool{}
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var l ReleaseLine
		if err := decodeStrict(line, &l); err != nil {
			return nil, fmt.Errorf("releases line %d: %w", n, err)
		}
		if err := l.Validate(); err != nil {
			return nil, fmt.Errorf("releases line %d: %w", n, err)
		}
		if seen[l.key()] {
			return nil, fmt.Errorf("releases line %d: %s listed twice", n, l)
		}
		seen[l.key()] = true
		out = append(out, l)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("releases line %d: longer than allowed", n+1)
		}
		return nil, fmt.Errorf("releases: %w", err)
	}
	return out, nil
}
