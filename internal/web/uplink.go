// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/uplink"
)

// Uplink is the uplink switch as the settings page uses it
// (internal/uplink.Manager).
type Uplink interface {
	Status() uplink.Status
	Enable(ctx context.Context, input []byte, by string) error
	Disable(ctx context.Context, by string) error
	Remove(ctx context.Context, by string) error
}

// uplinkStatus is the state shown on the settings page; without a manager
// the uplink is unavailable.
func (a *app) uplinkStatus() uplink.Status {
	if a.d.Uplink == nil {
		return uplink.Status{State: uplink.Unavailable}
	}
	return a.d.Uplink.Status()
}

// mode is where advisories come from now: the configured mode, hybrid
// while the uplink is switched on, or the data package.
func (a *app) mode() string {
	if a.d.Uplink != nil && a.d.Uplink.Status().State == uplink.Active {
		return "hybrid"
	}
	if a.d.Package != nil && a.d.Package.Available() {
		return "package"
	}
	return a.d.Mode
}

// uplinkSwitchTimeout bounds a switch-on; below the server's write timeout.
const uplinkSwitchTimeout = 20 * time.Second

func (a *app) enableUplink(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	if a.d.Uplink == nil {
		a.renderSettings(w, r, cur, http.StatusConflict, "", "The uplink is not available in this build.")
		return
	}
	license := r.PostFormValue("license")
	if len(license) > feed.MaxLicenseBytes {
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "Not switched on: this is too long for a license.")
		return
	}
	// The switch-on fetches the feed inside this request; it has to end
	// before the server's write timeout cuts the answer off.
	ctx, cancel := context.WithTimeout(r.Context(), uplinkSwitchTimeout)
	defer cancel()
	err := a.d.Uplink.Enable(ctx, []byte(license), cur.User.Username)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		a.renderSettings(w, r, cur, http.StatusGatewayTimeout, "", "Not switched on: the uplink servers did not answer in time. Nothing was changed; try again later.")
		return
	case errors.Is(err, uplink.ErrLocked), errors.Is(err, uplink.ErrUnavailable):
		a.renderSettings(w, r, cur, http.StatusConflict, "", "Not switched on: "+err.Error()+".")
		return
	case errors.Is(err, uplink.ErrNoLicense):
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "Not switched on: enter the license first.")
		return
	case err != nil:
		// The reason never contains the license itself.
		a.renderSettings(w, r, cur, http.StatusBadRequest, "", "Not switched on: "+err.Error())
		return
	}
	a.audit(r, cur, "uplink.enable", "", a.uplinkStatus().LicenseID)
	http.Redirect(w, r, "/settings?ok=uplink#uplink", http.StatusSeeOther)
}

func (a *app) disableUplink(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	a.uplinkOff(w, r, cur, "uplink.disable", func(ctx context.Context) error { return a.d.Uplink.Disable(ctx, cur.User.Username) })
}

func (a *app) removeUplink(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	a.uplinkOff(w, r, cur, "uplink.remove", func(ctx context.Context) error { return a.d.Uplink.Remove(ctx, cur.User.Username) })
}

func (a *app) uplinkOff(w http.ResponseWriter, r *http.Request, cur *auth.Current, action string, do func(context.Context) error) {
	if a.d.Uplink == nil {
		a.renderSettings(w, r, cur, http.StatusConflict, "", "The uplink is not available in this build.")
		return
	}
	if err := do(r.Context()); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, uplink.ErrLocked) || errors.Is(err, uplink.ErrUnavailable) {
			status = http.StatusConflict
		}
		a.renderSettings(w, r, cur, status, "", "Not changed: "+err.Error())
		return
	}
	a.audit(r, cur, action, "", "")
	http.Redirect(w, r, "/settings?ok=uplink-off#uplink", http.StatusSeeOther)
}
