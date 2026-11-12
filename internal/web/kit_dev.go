// SPDX-License-Identifier: Apache-2.0

//go:build dev

package web

import (
	"net/http"

	"github.com/bifrost0x/varde/internal/auth"
)

// registerKit serves the component overview at /ui/kit (dev builds only).
func registerKit(mux *http.ServeMux, a *app) {
	mux.Handle("GET /ui/kit", a.user(func(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
		rows := []findingRow{
			{ID: "x1", Priority: "P1", KEV: true, AppName: "Immich", WorkloadName: "immich_server", Version: "1.120.0", AdvisoryID: "GHSA-xxxx-xxxx-xxxx", Summary: "Example urgent finding", FixedIn: "1.121.0", Exposure: "public"},
			{ID: "x2", Priority: "P2", AppName: "Navidrome", WorkloadName: "navidrome", Version: "0.60.0", AdvisoryID: "GHSA-yyyy-yyyy-yyyy", Summary: "Example daily-digest finding", FixedIn: "0.64.0", Exposure: "lan"},
			{ID: "x3", Priority: "P3", AppName: "Authelia", WorkloadName: "authelia", Version: "4.39.15", AdvisoryID: "GHSA-zzzz-zzzz-zzzz", Summary: "Example low-impact finding", Exposure: "internal"},
			{ID: "x4", Priority: "", AppName: "Homarr", WorkloadName: "homarr", AdvisoryID: "GHSA-aaaa-aaaa-aaaa", Summary: "Example unverified finding", Exposure: "unknown"},
		}
		a.page(w, r, cur, http.StatusOK, "kit", view{Title: "Component kit", Data: rows})
	}))
}
