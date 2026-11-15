// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
)

// deviceView is what the system page shows of the scanned device behind a
// machine: how far it is identified, what it states, and how to get it
// recognised.
type deviceView struct {
	Level string
	// Stated are the values the device reported, Derived those Varde
	// recognised from its web interface; Names are display names, which
	// never identify the device.
	Stated, Derived, Names []fieldRow
	// Identity says whether the device keeps an identity across addresses.
	Identity string
	NextStep string
	// Help is set below the model level; IssueURL is empty when the link
	// would be too long, and the evidence goes in as a file.
	Help     bool
	IssueURL string
}

type fieldRow struct{ Label, Value string }

// scannedDevice returns the scanned device behind a machine, and the keys
// shared by several addresses of the scan.
func (a *app) scannedDevice(s *snapshot, m *coverage.Machine) (discovery.Device, map[string]bool, bool) {
	for _, e := range m.Evidence {
		if e.Source != coverage.EvidenceScan {
			continue
		}
		for _, addr := range e.Addresses {
			for _, d := range s.devices {
				if d.Address == addr {
					return d.Device, coverage.SharedKeys(s.devices), true
				}
			}
		}
	}
	return discovery.Device{}, nil, false
}

// levelOf parses the level word of a machine.
func levelOf(word string) discovery.Level {
	for l := discovery.LevelSeen; l <= discovery.LevelSoftware; l++ {
		if l.String() == word {
			return l
		}
	}
	return discovery.LevelSeen
}

// newDeviceView shows the device under the level of its machine, so the
// list and the page agree; the device's own fields are listed as stated.
func newDeviceView(d discovery.Device, shared map[string]bool, machineLevel string) *deviceView {
	l := levelOf(machineLevel)
	v := &deviceView{Level: l.String(), NextStep: discovery.NextStep(l), Help: l < discovery.LevelModel}
	for _, f := range d.Fields() {
		row := fieldRow{Label: strings.ReplaceAll(f.Name, "_", " "), Value: f.Value}
		switch {
		case f.Name == discovery.FieldDisplayName:
			v.Names = append(v.Names, row)
		case f.Trust == discovery.TrustDerived:
			v.Derived = append(v.Derived, row)
		default:
			v.Stated = append(v.Stated, row)
		}
	}
	switch n := len(discovery.Anchors(d, shared)); n {
	case 0:
		v.Identity = "Its identity follows its address."
	case 1:
		v.Identity = "Identified by 1 key that stays the same."
	default:
		v.Identity = "Identified by " + strconv.Itoa(n) + " keys that stay the same."
	}
	if v.Help {
		if u, ok := discovery.MakeBundle(d, shared).IssueURL(); ok {
			v.IssueURL = u
		}
	}
	return v
}

// evidence downloads the privacy-filtered bundle of a machine's scanned
// device. Nothing is sent anywhere: the user attaches the file to an issue.
func (a *app) evidence(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	s, err := a.load(r.Context(), false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	id := r.PathValue("id")
	for i := range s.machines {
		if s.machines[i].ID != id {
			continue
		}
		if d, shared, ok := a.scannedDevice(s, &s.machines[i]); ok {
			raw, err := json.MarshalIndent(discovery.MakeBundle(d, shared), "", "  ")
			if err != nil {
				a.fail(w, r, cur, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", `attachment; filename="device-evidence.json"`)
			_, _ = w.Write(append(raw, '\n'))
			return
		}
	}
	a.renderError(w, r, cur, http.StatusNotFound, "No evidence", "Varde has no scanned device for this machine.")
}
