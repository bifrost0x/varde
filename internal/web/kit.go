// SPDX-License-Identifier: Apache-2.0

//go:build !dev

package web

import "net/http"

// registerKit is a no-op in release builds; the component kit exists only
// in builds with the "dev" tag.
func registerKit(*http.ServeMux, *app) {}
