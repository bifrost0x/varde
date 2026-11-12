// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"embed"
	"io/fs"
)

//go:embed roots
var rootsFS embed.FS

// EmbeddedRoot returns the production trust root built into this binary,
// or nil when the build has none (see roots/README.md).
func EmbeddedRoot() []byte { return rootFrom(rootsFS) }

func rootFrom(fsys fs.FS) []byte {
	data, err := fs.ReadFile(fsys, "roots/production.json")
	if err != nil {
		return nil
	}
	return data
}
