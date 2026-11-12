// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/datapkg"
	"github.com/bifrost0x/varde/internal/feed"
)

// Package is the data package as the pages use it
// (internal/datapkg.Manager).
type Package interface {
	// Available reports whether the installation reads the data package;
	// it is cheap, unlike Status.
	Available() bool
	Status(ctx context.Context) datapkg.Status
	UpdateNow(ctx context.Context) (feed.Result, error)
	// NoSource reports that nothing tells Varde about advisories of app:
	// the package does not cover it and the public sources are not asked.
	NoSource(app *catalog.App) bool
}

// packageStatus is the state shown on the settings page; without a manager
// the package is unavailable.
func (a *app) packageStatus(ctx context.Context) datapkg.Status {
	if a.d.Package == nil {
		return datapkg.Status{}
	}
	return a.d.Package.Status(ctx)
}

// updatePackage is "Update now": one check of the package mirrors inside
// the request, whatever the daily schedule says.
func (a *app) updatePackage(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if a.d.Package == nil {
		a.renderSettings(w, r, cur, http.StatusConflict, "", "Not updated: "+datapkg.ErrUnavailable.Error()+".")
		return
	}
	// It has to end before the server's write timeout cuts the answer off.
	ctx, cancel := context.WithTimeout(r.Context(), uplinkSwitchTimeout)
	defer cancel()
	res, err := a.d.Package.UpdateNow(ctx)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		a.renderSettings(w, r, cur, http.StatusGatewayTimeout, "", "Not updated: the package mirror did not answer in time. The data in use stays. If a download is already running it goes on; look here again in a minute.")
		return
	case errors.Is(err, datapkg.ErrUnavailable):
		a.renderSettings(w, r, cur, http.StatusConflict, "", "Not updated: "+err.Error()+".")
		return
	case err != nil:
		a.renderSettings(w, r, cur, http.StatusBadGateway, "", "Not updated: "+err.Error())
		return
	}
	a.audit(r, cur, "package.update", "", "")
	if res.Applied {
		http.Redirect(w, r, "/settings?ok=package#package", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?ok=package-current#package", http.StatusSeeOther)
}
