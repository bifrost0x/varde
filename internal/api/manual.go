// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// ManualRequest creates a manual workload. Exactly one of HostID (an
// existing host) and HostName (a manual host, created on first use) is set.
type ManualRequest struct {
	HostID   string `json:"host_id"`
	HostName string `json:"host_name"`
	Name     string `json:"name"`
	AppID    string `json:"app_id"`
	Version  string `json:"version"`
	Exposure string `json:"exposure"`
	Note     string `json:"note"`
}

// ErrInvalidRequest wraps validation errors; the message is safe to show.
var ErrInvalidRequest = errors.New("invalid request")

// ManualStore is what creating manual entries needs.
type ManualStore interface {
	Host(ctx context.Context, id string) (inventory.Host, error)
	UpsertHost(ctx context.Context, h inventory.Host) error
	AddManual(ctx context.Context, w inventory.Workload, now time.Time) (inventory.Workload, error)
}

var (
	appIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_~-]{0,63}$`)
)

// CreateManual validates req and stores a manual workload (API and UI).
func CreateManual(ctx context.Context, st ManualStore, req ManualRequest, now time.Time) (inventory.Workload, error) {
	if err := req.validate(); err != nil {
		return inventory.Workload{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	hostID := req.HostID
	if hostID != "" {
		if _, err := st.Host(ctx, hostID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return inventory.Workload{}, fmt.Errorf("%w: host_id does not exist", ErrInvalidRequest)
			}
			return inventory.Workload{}, err
		}
	} else {
		hostID = manualHostID(req.HostName)
		existing, err := st.Host(ctx, hostID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			existing = inventory.Host{
				ID: hostID, Name: req.HostName, Kind: inventory.HostAppliance,
				Source: inventory.SourceManual, CreatedAt: now,
			}
		case err != nil:
			return inventory.Workload{}, err
		}
		existing.LastContact = now
		if err := st.UpsertHost(ctx, existing); err != nil {
			return inventory.Workload{}, err
		}
	}
	runtimeID, err := randomID()
	if err != nil {
		return inventory.Workload{}, err
	}
	return st.AddManual(ctx, inventory.Workload{
		HostID: hostID, Kind: inventory.KindManual, RuntimeID: runtimeID, Name: req.Name, State: "manual",
		Manual: &inventory.Manual{
			AppID: req.AppID, Version: req.Version, Exposure: inventory.Exposure(req.Exposure), Note: req.Note,
		},
	}, now)
}

func (a *api) createManual(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	var req ManualRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain a single JSON object")
		return
	}
	ctx := r.Context()
	wl, err := CreateManual(ctx, a.store, req, a.now())
	if errors.Is(err, ErrInvalidRequest) {
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), ErrInvalidRequest.Error()+": "))
		return
	}
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	a.audit(r, "manual.create", wl.ID, req.AppID+" "+req.Version)
	a.changed(ctx)
	ids, err := a.store.Identifications(ctx)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	w.Header().Set("Location", Prefix+"workloads/"+wl.ID)
	writeJSON(w, http.StatusCreated, view(wl, ids))
}

func (m *ManualRequest) validate() error {
	m.HostID = strings.TrimSpace(m.HostID)
	m.HostName = strings.TrimSpace(m.HostName)
	m.Name = strings.TrimSpace(m.Name)
	m.AppID = strings.TrimSpace(m.AppID)
	m.Version = strings.TrimSpace(m.Version)
	m.Note = strings.TrimSpace(m.Note)
	if m.Exposure == "" {
		m.Exposure = string(inventory.ExposureUnknown)
	}

	switch {
	case (m.HostID == "") == (m.HostName == ""):
		return errors.New("set exactly one of host_id and host_name")
	case m.HostName != "" && !plainText(m.HostName, 128):
		return errors.New("host_name must be 1-128 printable characters")
	case !plainText(m.Name, 128):
		return errors.New("name must be 1-128 printable characters")
	case !appIDPattern.MatchString(m.AppID):
		return errors.New("app_id must be a catalog id (lowercase letters, digits, hyphens)")
	case !versionPattern.MatchString(m.Version):
		return errors.New("version must be 1-64 characters of letters, digits and . + _ ~ -")
	case !inventory.Exposure(m.Exposure).Valid():
		return fmt.Errorf("exposure must be one of public, lan, internal, unknown")
	case m.Note != "" && !plainText(m.Note, 1024):
		return errors.New("note must be at most 1024 printable characters")
	}
	return nil
}

// plainText accepts non-empty printable text without control characters.
func plainText(s string, maxRunes int) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// manualHostID derives a stable ID from the host name, case-insensitively.
func manualHostID(name string) string {
	h := sha256.Sum256([]byte(strings.ToLower(name)))
	return "manual-" + hex.EncodeToString(h[:6])
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
