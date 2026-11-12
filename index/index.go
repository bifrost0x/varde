// SPDX-License-Identifier: Apache-2.0

// Package index holds the first-party index (ADR 0038): image repositories
// and the GitHub repositories of their projects, each row resting on what
// the project or the registry states itself. cmd/indexbuilder writes
// images.tsv; SOURCES.md says how and when. The table is embedded, so an
// installation needs no connection for it.
package index

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/bifrost0x/varde/internal/applists"
)

//go:embed images.tsv
var images []byte

var (
	once  sync.Once
	table *applists.Table
	err   error
)

// Table returns the embedded table. The kinds of evidence of a row take
// the place of list names (applists.Entry.Lists): two kinds confirm it.
func Table() (*applists.Table, error) {
	once.Do(func() {
		if table, err = applists.Unmarshal(images); err == nil {
			err = Check(table)
		}
	})
	return table, err
}

// Check verifies that every row carries the evidence the index promises,
// so a hand-edited or faulty table cannot ship and alert: only the known
// kinds, never the registry namespace alone, the namespace only for the
// owner's own image named like the repository, and no helper images.
func Check(t *applists.Table) error {
	for _, e := range t.Entries() {
		kinds := map[string]bool{}
		for _, k := range e.Lists {
			if k != "readme" && k != "hub" && k != "ghcr" {
				return fmt.Errorf("index: %s: unknown kind of evidence %q", e.Image, k)
			}
			kinds[k] = true
		}
		switch {
		case applists.IsHelper(e.Image):
			return fmt.Errorf("index: %s is a base or helper image", e.Image)
		case kinds["ghcr"] && len(kinds) == 1:
			return fmt.Errorf("index: %s rests on the registry namespace alone", e.Image)
		case kinds["ghcr"] && (!strings.HasPrefix(e.Image, "ghcr.io/") || !applists.OwnedBy(e.Image, e.Repo) || !applists.NamedLike(e.Image, e.Repo)):
			return fmt.Errorf("index: %s: the registry namespace counts only for the owner's image named like %s", e.Image, e.Repo)
		}
	}
	return nil
}
