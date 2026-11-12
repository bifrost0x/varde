// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/fsutil"
)

// Counts are the sizes of one published package: the baseline the next
// build is compared with.
type Counts struct {
	Sequence   int64 `json:"sequence"`
	Advisories int   `json:"advisories"`
	KEV        int   `json:"kev"`
	EPSS       int   `json:"epss"`
	Index      int   `json:"index"`
	// Generated is the number of generated catalog entries, Releases the
	// number of release package lines and ReleasesBytes the compressed
	// size of their blob. A baseline from before the generator has none.
	Generated     int   `json:"generated,omitempty"`
	Releases      int   `json:"releases,omitempty"`
	ReleasesBytes int64 `json:"releases_bytes,omitempty"`
}

// CountsOf returns the sizes of s; indexRows is the number of rows of its
// index. ReleasesBytes is known only once the package is written.
func CountsOf(s feed.Snapshot, indexRows int) Counts {
	return Counts{Sequence: s.Sequence, Advisories: len(s.Advisories), KEV: len(s.KEV), EPSS: len(s.EPSS), Index: indexRows,
		Generated: len(s.Generated), Releases: len(s.Releases)}
}

// countsFile lies beside v1/ in the published directory. Nothing an
// installation reads: it tells the next build what the last one
// published. The builder seals it (Seal, PurposeCounts) and trusts it only
// sealed, because the published branch is writable by more than can sign.
const countsFile = "stats.json"

// Purposes of sealed files.
const (
	PurposeStore  = "store"
	PurposeCounts = "counts"
)

// CountsPath is the file of the counts in a published directory.
func CountsPath(dir string) string { return filepath.Join(dir, countsFile) }

// ReadCounts reads the counts of the package published in dir; false when
// there is none.
func ReadCounts(dir string) (Counts, bool, error) {
	if dir == "" {
		return Counts{}, false, nil
	}
	data, err := ReadRegular(CountsPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return Counts{}, false, nil
	}
	if err != nil {
		return Counts{}, false, err
	}
	var c Counts
	if err := json.Unmarshal(data, &c); err != nil {
		return Counts{}, false, fmt.Errorf("%s: %w", countsFile, err)
	}
	return c, true, nil
}

// WriteCounts writes c beside the package in dir.
func WriteCounts(dir string, c Counts) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, countsFile), append(data, '\n'), 0o644)
}

// Limits of Guard.
const (
	// maxFailedPercent is the share of repositories that may fail.
	maxFailedPercent = 5
	// maxShrinkPercent is how much a count may fall against the last
	// package.
	maxShrinkPercent = 10
	// maxGeneratedShrinkPercent is how much the generated entries may
	// fall. They come and go with their checks, so the bound is wider than
	// for advisories; a larger drop more likely means a source that broke
	// the checks (a registry, GitHub) than projects that changed.
	maxGeneratedShrinkPercent = 30
	// MaxReleasesBytes caps the compressed releases blob. It keeps the
	// package well inside the 128 MiB blob limit of installations as the
	// number of apps grows.
	MaxReleasesBytes = 32 << 20
)

// ErrRefused reports a build the builder does not sign.
var ErrRefused = errors.New("build refused")

// Guard decides whether a build may be signed. Too many repositories that
// could not be read, or a package much smaller than the last one, more
// likely mean a broken build or a broken upstream than a real change; the
// package published before then stays. force lets a human who looked at
// the reason release a legitimate shrink; it does not release failures.
func Guard(stats Stats, previous Counts, havePrevious bool, current Counts, force bool) error {
	if stats.Failed*100 > maxFailedPercent*stats.Repos {
		return fmt.Errorf("%w: %d of %d repositories could not be read (more than %d %%)", ErrRefused, stats.Failed, stats.Repos, maxFailedPercent)
	}
	if !havePrevious {
		return nil
	}
	if current.Sequence <= previous.Sequence {
		return fmt.Errorf("%w: sequence %d is not above the published %d", ErrRefused, current.Sequence, previous.Sequence)
	}
	if force {
		return nil
	}
	// EPSS is left out: scores come and go with the advisories.
	for _, c := range []struct {
		name     string
		was, now int
	}{{"advisories", previous.Advisories, current.Advisories}, {"KEV entries", previous.KEV, current.KEV}, {"index rows", previous.Index, current.Index}} {
		if c.now*100 < (100-maxShrinkPercent)*c.was {
			return fmt.Errorf("%w: %s fell from %d to %d (more than %d %%); check the reason, then build with -force", ErrRefused, c.name, c.was, c.now, maxShrinkPercent)
		}
	}
	if current.Generated*100 < (100-maxGeneratedShrinkPercent)*previous.Generated {
		return fmt.Errorf("%w: generated entries fell from %d to %d (more than %d %%); check catalog/generated.md, then build with -force",
			ErrRefused, previous.Generated, current.Generated, maxGeneratedShrinkPercent)
	}
	return nil
}

// GuardReleases refuses a releases blob of more than MaxReleasesBytes
// compressed. force does not lift it: the reader's budgets bound what one
// build adds, so a blob that size is a fault to fix in the builder.
func GuardReleases(compressed int64) error {
	if compressed > MaxReleasesBytes {
		return fmt.Errorf("%w: the releases blob is %d bytes compressed, more than the cap of %d", ErrRefused, compressed, MaxReleasesBytes)
	}
	return nil
}
