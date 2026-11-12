// SPDX-License-Identifier: Apache-2.0

// Package catalogdata embeds the built-in app catalog (catalog/apps/*.yaml)
// into the binary. Parsing and validation live in internal/catalog.
package catalogdata

import (
	"embed"
	"io/fs"
)

//go:embed apps/*.yaml
var embedded embed.FS

// FS returns the built-in catalog entries, one *.yaml file per app.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "apps")
	if err != nil {
		// "apps" is a constant, valid path; fs.Sub cannot fail for it.
		panic(err)
	}
	return sub
}
