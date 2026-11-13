// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// Key is the platform as "os/architecture" or "os/architecture/variant",
// the form an installation keeps a release package list under.
func (p ReleasePlatform) Key() string {
	if p.Variant == "" {
		return p.OS + "/" + p.Arch
	}
	return p.OS + "/" + p.Arch + "/" + p.Variant
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

// The releases blob is JSONL of two kinds of records. A package list,
// {"list":{"id":"sha256:…","packages":[…]}}, holds one list of packages
// under the SHA-256 of its JSON encoding; a release,
// {"release":{…,"packages":"sha256:…"}}, is a ReleaseLine that names its
// package list instead of carrying it. Identical lists (the amd64 and
// arm64 images of a release, releases on the same base) are stored once.
// A list comes before the first release that names it, so the blob reads
// in one pass.
type releaseRecord struct {
	List    *releaseList `json:"list,omitempty"`
	Release *releaseRef  `json:"release,omitempty"`
}

type releaseList struct {
	ID       string              `json:"id"`
	Packages []inventory.Package `json:"packages"`
}

// releaseRef is a ReleaseLine with the ID of its package list.
type releaseRef struct {
	AppID          string          `json:"app_id"`
	Image          string          `json:"image"`
	Tag            string          `json:"tag"`
	Version        string          `json:"version"`
	IndexDigest    string          `json:"index_digest,omitempty"`
	Platform       ReleasePlatform `json:"platform"`
	ManifestDigest string          `json:"manifest_digest"`
	Read           time.Time       `json:"read"`
	Distro         string          `json:"distro,omitempty"`
	OS             string          `json:"os_name,omitempty"`
	Partial        bool            `json:"partial,omitempty"`
	Packages       string          `json:"packages"`
}

func refOf(l ReleaseLine, list string) releaseRef {
	return releaseRef{AppID: l.AppID, Image: l.Image, Tag: l.Tag, Version: l.Version, IndexDigest: l.IndexDigest, Platform: l.Platform,
		ManifestDigest: l.ManifestDigest, Read: l.Read, Distro: l.Distro, OS: l.OS, Partial: l.Partial, Packages: list}
}

func (r releaseRef) line(pkgs []inventory.Package) ReleaseLine {
	return ReleaseLine{AppID: r.AppID, Image: r.Image, Tag: r.Tag, Version: r.Version, IndexDigest: r.IndexDigest, Platform: r.Platform,
		ManifestDigest: r.ManifestDigest, Read: r.Read, Distro: r.Distro, OS: r.OS, Partial: r.Partial, Packages: pkgs}
}

// releaseEncoder writes the records of lines, each package list once.
type releaseEncoder struct {
	lists map[string]bool
}

// records returns the encoded records lines add to the blob: the lists
// not written yet, then the releases. It does not mark the lists written.
func (e *releaseEncoder) records(lines []ReleaseLine) (out [][]byte, ids []string, err error) {
	fresh := map[string]bool{}
	for _, l := range lines {
		pkgs := l.Packages
		if pkgs == nil {
			// Both encode the same; nil would write null.
			pkgs = []inventory.Package{}
		}
		enc, err := json.Marshal(pkgs)
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(enc)
		id := "sha256:" + hex.EncodeToString(sum[:])
		if !e.lists[id] && !fresh[id] {
			fresh[id] = true
			ids = append(ids, id)
			b, err := json.Marshal(releaseRecord{List: &releaseList{ID: id, Packages: pkgs}})
			if err != nil {
				return nil, nil, err
			}
			out = append(out, b)
		}
		ref := refOf(l, id)
		b, err := json.Marshal(releaseRecord{Release: &ref})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, b)
	}
	return out, ids, nil
}

func (e *releaseEncoder) mark(ids []string) {
	if e.lists == nil {
		e.lists = map[string]bool{}
	}
	for _, id := range ids {
		e.lists[id] = true
	}
}

// DefaultReleasesBudget is the most bytes the releases blob takes
// unpacked when the builder leaves room for it (FitReleases): a tenth of
// it compressed, far below the 32 MiB cap on the compressed blob, and a
// quarter of what an installation unpacks of a whole package.
const DefaultReleasesBudget = 64 << 20

// ReleaseSizer counts the bytes app images' lines take in the releases
// blob, each package list once, as FitReleases counts them.
type ReleaseSizer struct {
	enc releaseEncoder
	// Size is the blob's size with the lines added so far.
	Size int64
}

// Cost returns the bytes lines would add.
func (z *ReleaseSizer) Cost(lines []ReleaseLine) (int64, error) {
	n, _, err := z.cost(lines)
	return n, err
}

// Add adds lines and returns the bytes they took.
func (z *ReleaseSizer) Add(lines []ReleaseLine) (int64, error) {
	n, ids, err := z.cost(lines)
	if err != nil {
		return 0, err
	}
	z.enc.mark(ids)
	z.Size += n
	return n, nil
}

func (z *ReleaseSizer) cost(lines []ReleaseLine) (int64, []string, error) {
	recs, ids, err := z.enc.records(lines)
	if err != nil {
		return 0, nil, err
	}
	var n int64
	for _, r := range recs {
		n += int64(len(r)) + 1
	}
	return n, ids, nil
}

// FitReleases returns the lines that fit into budget bytes of the
// releases blob, in the order given, which is the order of priority: the
// lines of one app image ship together or not at all, and once an image
// does not fit, neither does any after it. size is the blob's size with
// the lines kept.
func FitReleases(lines []ReleaseLine, budget int64) (kept []ReleaseLine, size int64, err error) {
	type image struct{ app, name string }
	var order []image
	byImage := map[image][]ReleaseLine{}
	for _, l := range lines {
		k := image{l.AppID, l.Image}
		if _, ok := byImage[k]; !ok {
			order = append(order, k)
		}
		byImage[k] = append(byImage[k], l)
	}
	var z ReleaseSizer
	for _, k := range order {
		n, err := z.Cost(byImage[k])
		if err != nil {
			return nil, 0, err
		}
		if z.Size+n > budget {
			break
		}
		if _, err := z.Add(byImage[k]); err != nil {
			return nil, 0, err
		}
		kept = append(kept, byImage[k]...)
	}
	return kept, z.Size, nil
}

// marshalReleases encodes lines as sorted JSONL records. The builder
// refuses a line installations would refuse.
func marshalReleases(lines []ReleaseLine) ([]byte, error) {
	sorted := append([]ReleaseLine(nil), lines...)
	sort.SliceStable(sorted, func(i, j int) bool { return releaseLess(sorted[i], sorted[j]) })
	var buf bytes.Buffer
	var enc releaseEncoder
	for i, l := range sorted {
		if err := l.Validate(); err != nil {
			return nil, fmt.Errorf("releases: %w", err)
		}
		if i > 0 && sorted[i-1].key() == l.key() {
			return nil, fmt.Errorf("releases: %s listed twice", l)
		}
		recs, ids, err := enc.records([]ReleaseLine{l})
		if err != nil {
			return nil, err
		}
		enc.mark(ids)
		for _, r := range recs {
			buf.Write(r)
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes(), nil
}

// parseReleases decodes and validates the releases blob. Lines that share
// a package list share its slice.
func parseReleases(data []byte) ([]ReleaseLine, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), maxReleaseLine)
	var out []ReleaseLine
	seen := map[[5]string]bool{}
	lists := map[string][]inventory.Package{}
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec releaseRecord
		if err := decodeStrict(line, &rec); err != nil {
			return nil, fmt.Errorf("releases line %d: %w", n, err)
		}
		switch {
		case rec.List != nil && rec.Release == nil:
			if !digestRe.MatchString(rec.List.ID) {
				return nil, fmt.Errorf("releases line %d: invalid list id", n)
			}
			if _, ok := lists[rec.List.ID]; ok {
				return nil, fmt.Errorf("releases line %d: list %s listed twice", n, rec.List.ID)
			}
			if rec.List.Packages == nil {
				rec.List.Packages = []inventory.Package{}
			}
			lists[rec.List.ID] = rec.List.Packages
		case rec.Release != nil && rec.List == nil:
			pkgs, ok := lists[rec.Release.Packages]
			if !ok {
				return nil, fmt.Errorf("releases line %d: %s names a package list not listed before it", n, rec.Release.AppID)
			}
			l := rec.Release.line(pkgs)
			if err := l.Validate(); err != nil {
				return nil, fmt.Errorf("releases line %d: %w", n, err)
			}
			if seen[l.key()] {
				return nil, fmt.Errorf("releases line %d: %s listed twice", n, l)
			}
			seen[l.key()] = true
			out = append(out, l)
		default:
			return nil, fmt.Errorf("releases line %d: neither a package list nor a release", n)
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("releases line %d: longer than allowed", n+1)
		}
		return nil, fmt.Errorf("releases: %w", err)
	}
	return out, nil
}
