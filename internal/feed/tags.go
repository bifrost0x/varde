// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bifrost0x/varde/internal/imageref"
)

// TagLine is one line of the tags blob: the release tags of one image of
// a catalog app, as the package builder read them from the registry. With
// them an installation knows which releases of an image exist without
// asking a registry itself: the tag that brings a fixed version, and
// whether a version an advisory names was ever released.
type TagLine struct {
	AppID string `json:"app_id"`
	// Image is the normalised image repository ("docker.io/grafana/grafana").
	Image string    `json:"image"`
	Read  time.Time `json:"read"`
	// Tags are the tags the app's tag rule reads a release from, newest
	// release first; floating tags, branches and commit tags are not
	// among them. A repository with more than MaxTagsPerLine keeps the
	// newest.
	Tags []string `json:"tags"`
}

const (
	// MaxTagsPerLine bounds the tags of one image. Updates point to the
	// newest releases; a repository's oldest tags are of no use to them.
	MaxTagsPerLine = 600
	// maxTagLine bounds one line: MaxTagsPerLine tags of the longest form.
	maxTagLine = 128 << 10
	// maxTagLines bounds the images of the blob.
	maxTagLines = 20000
)

// Validate checks a line with the bounds of every other record that comes
// from outside the installation.
func (l TagLine) Validate() error {
	if !appIDRe.MatchString(l.AppID) {
		return fmt.Errorf("invalid app id %q", l.AppID)
	}
	if repo, err := imageref.NormaliseRepository(l.Image); err != nil || repo != l.Image || len(l.Image) > 256 {
		return fmt.Errorf("%s: image is not a normalised repository", l.AppID)
	}
	if l.Read.IsZero() {
		return fmt.Errorf("%s: no read time", l.AppID)
	}
	if len(l.Tags) == 0 || len(l.Tags) > MaxTagsPerLine {
		return fmt.Errorf("%s: %d tags", l.AppID, len(l.Tags))
	}
	seen := make(map[string]bool, len(l.Tags))
	for _, t := range l.Tags {
		if !tagRe.MatchString(t) || seen[t] {
			return fmt.Errorf("%s: invalid or repeated tag", l.AppID)
		}
		seen[t] = true
	}
	return nil
}

// marshalTags encodes lines as JSONL sorted by image. The builder refuses
// a line installations would refuse.
func marshalTags(lines []TagLine) ([]byte, error) {
	if len(lines) > maxTagLines {
		return nil, fmt.Errorf("tags: %d images, installations read at most %d", len(lines), maxTagLines)
	}
	sorted := append([]TagLine(nil), lines...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Image < sorted[j].Image })
	var buf bytes.Buffer
	for i, l := range sorted {
		if err := l.Validate(); err != nil {
			return nil, fmt.Errorf("tags: %w", err)
		}
		if i > 0 && sorted[i-1].Image == l.Image {
			return nil, fmt.Errorf("tags: %s listed twice", l.Image)
		}
		rec, err := json.Marshal(l)
		if err != nil {
			return nil, fmt.Errorf("tags: %w", err)
		}
		if len(rec) > maxTagLine {
			return nil, fmt.Errorf("tags: line of %s longer than allowed", l.Image)
		}
		buf.Write(rec)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// parseTags decodes and validates the tags blob.
func parseTags(data []byte) ([]TagLine, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), maxTagLine)
	out := []TagLine{}
	seen := map[string]bool{}
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var l TagLine
		if err := decodeStrict(line, &l); err != nil {
			return nil, fmt.Errorf("tags line %d: %w", n, err)
		}
		if err := l.Validate(); err != nil {
			return nil, fmt.Errorf("tags line %d: %w", n, err)
		}
		if seen[l.Image] {
			return nil, fmt.Errorf("tags line %d: %s listed twice", n, l.Image)
		}
		seen[l.Image] = true
		if out = append(out, l); len(out) > maxTagLines {
			return nil, fmt.Errorf("tags: more than %d images", maxTagLines)
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("tags line %d: longer than allowed", n+1)
		}
		return nil, fmt.Errorf("tags: %w", err)
	}
	return out, nil
}
