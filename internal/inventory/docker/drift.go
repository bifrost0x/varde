// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pkgdb"
)

// Container drift: a container that no longer matches what Varde learns
// from its image. Two kinds are read, both read-only:
//   - the tag the container was created from now points to another local
//     image (pulled, but the container was not recreated);
//   - files that carry version evidence (package databases, the app's
//     manifest) were changed inside the container, so the image's
//     evidence does not describe it.

// Change is one entry of GET /containers/{id}/changes.
type Change struct {
	Path string `json:"Path"`
	Kind int    `json:"Kind"`
}

const (
	// maxChangesBytes bounds the change list; a container that writes
	// many files into its own layer is skipped, not read in full.
	maxChangesBytes = 4 << 20
	// changesEvery is how often one container's changes are checked, and
	// changesPerList bounds the checks of one sync.
	changesEvery   = 24 * time.Hour
	changesPerList = 8
)

// Changes returns the paths changed in a container's writable layer.
func (c *Client) Changes(ctx context.Context, id string) ([]Change, error) {
	if !validID(id) {
		return nil, fmt.Errorf("invalid container id %q", id)
	}
	var out []Change
	err := c.getVersioned(ctx, "/containers/"+id+"/changes", nil, maxChangesBytes, &out)
	return out, err
}

// imageName is a plain image reference: repository and optional tag, as
// given to docker run. No digest, no "..", no empty path segment.
var imageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:-]{0,254}$`)

// ImageIDByRef returns the ID of the local image a reference points to now.
func (c *Client) ImageIDByRef(ctx context.Context, ref string) (string, error) {
	if !imageName.MatchString(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "//") {
		return "", fmt.Errorf("invalid image reference %q", ref)
	}
	var out struct {
		ID string `json:"Id"`
	}
	err := c.getVersioned(ctx, "/images/"+ref+"/json", nil, maxInspectBytes, &out)
	return out.ID, err
}

// pulledImage sets PulledImageID on containers whose tag points to another
// local image than the one they run. refs caches the answers of one sync.
func (c *Collector) pulledImage(ctx context.Context, w *inventory.Workload, refs map[string]string) {
	ct := w.Container
	if ct == nil || ct.ImageRef == "" || strings.ContainsRune(ct.ImageRef, '@') || validID(ct.ImageRef) || strings.HasPrefix(ct.ImageRef, "sha256:") {
		return
	}
	id, ok := refs[ct.ImageRef]
	if !ok {
		var err error
		if id, err = c.client.ImageIDByRef(ctx, ct.ImageRef); err != nil {
			// Not present any more, or not inspectable: no statement.
			id = ""
		}
		refs[ct.ImageRef] = id
	}
	if id != "" && id != ct.ImageID {
		ct.PulledImageID = id
	}
}

type changeState struct {
	checked time.Time
	files   []string
}

// changedFiles sets ChangedFiles on containers whose version evidence
// files were changed inside them. Checks are spread over syncs; the last
// answer is kept in memory.
func (c *Collector) changedFiles(ctx context.Context, ws []inventory.Workload, config func(string) ImageConfig) {
	if c.Packages == nil || (c.Packages.Enabled != nil && !c.Packages.Enabled()) {
		c.changes = nil
		return
	}
	now := time.Now
	if c.Packages.Now != nil {
		now = c.Packages.Now
	}
	next := make(map[string]changeState, len(ws))
	checks := 0
	for i := range ws {
		ct := ws[i].Container
		if ct == nil || !validID(ws[i].RuntimeID) {
			continue
		}
		st, ok := c.changes[ws[i].RuntimeID]
		if (!ok || now().Sub(st.checked) >= changesEvery) && checks < changesPerList && ctx.Err() == nil {
			checks++
			changes, err := c.client.Changes(ctx, ws[i].RuntimeID)
			if err != nil {
				// Too many changes or not readable: no statement, retried
				// with the next check.
				c.log.Debug("container changes not read", "container", ws[i].Name, "err", err)
				st = changeState{checked: now()}
			} else {
				st = changeState{checked: now(), files: evidenceChanges(changes, config(ct.ImageID))}
			}
			ok = true
		}
		if ok {
			next[ws[i].RuntimeID] = st
			ct.ChangedFiles = st.files
		}
	}
	c.changes = next
}

// evidenceChanges keeps the changed paths that carry version evidence.
func evidenceChanges(changes []Change, cfg ImageConfig) []string {
	watched := map[string]bool{}
	for _, f := range PackageFiles {
		watched[f] = true
	}
	for _, f := range manifestPaths(cfg.WorkingDir) {
		watched[f] = true
		watched[path.Join(path.Dir(f), pkgdb.LockFile)] = true
	}
	for _, f := range binaryPaths(cfg) {
		watched[f] = true
	}
	roots := append([]string(nil), LanguageRoots...)
	if wd := path.Clean(cfg.WorkingDir); cfg.WorkingDir != "" && path.IsAbs(wd) && wd != "/" {
		roots = append(roots, wd)
	}
	var out []string
	for _, ch := range changes {
		if watched[ch.Path] || languageEvidence(ch.Path, roots) || path.Dir(ch.Path) == ProgramDir {
			out = append(out, ch.Path)
		}
	}
	return out
}

// languageEvidence reports whether a changed path is language package
// metadata Varde reads, or a package directory holding it (pip removes
// the whole .dist-info directory of an upgraded package, and the change
// list then names only the directory).
func languageEvidence(p string, roots []string) bool {
	if !under(p, roots) {
		return false
	}
	base := path.Base(p)
	return languageFile(p) != "" || strings.HasSuffix(base, ".dist-info") || strings.HasSuffix(base, ".egg-info") ||
		path.Base(path.Dir(p)) == "specifications" || base == "composer" && path.Base(path.Dir(p)) == "vendor"
}
