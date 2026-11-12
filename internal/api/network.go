// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/store"
)

// machines merges hosts and devices the same way the UI does (ADR 0021).
func (a *api) machines(r *http.Request) ([]coverage.Machine, []store.StoredDevice, error) {
	ctx := r.Context()
	hosts, err := a.store.Hosts(ctx)
	if err != nil {
		return nil, nil, err
	}
	devs, err := a.store.Devices(ctx)
	if err != nil {
		return nil, nil, err
	}
	ins, err := a.store.Integrations(ctx)
	if err != nil {
		return nil, nil, err
	}
	ws, err := a.store.Workloads(ctx, store.WorkloadFilter{})
	if err != nil {
		return nil, nil, err
	}
	perHost := map[string]int{}
	for _, w := range ws {
		perHost[w.HostID]++
	}
	ms := coverage.Machines(coverage.MachineInput{
		Hosts: hosts, Devices: devs, Integrations: ins, Scope: a.scope(), Workloads: perHost, Now: a.now(), Interval: a.interval,
	})
	owner, err := a.store.AssetIDs(ctx)
	if err != nil {
		return nil, nil, err
	}
	coverage.ApplyAssetIDs(ms, owner)
	return ms, devs, nil
}

func (a *api) listMergedHosts(w http.ResponseWriter, r *http.Request) {
	ms, _, err := a.machines(r)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	out := []coverage.Machine{}
	for _, m := range ms {
		if m.IsHost() {
			out = append(out, m)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out, "counts": coverage.CountMachines(ms)})
}

// deviceView is a scanned address with the host it belongs to.
type deviceView struct {
	store.StoredDevice
	// HostID is the merged host the device belongs to; empty when only
	// the scan knows it.
	HostID string `json:"host_id,omitempty"`
}

func (a *api) listDevices(w http.ResponseWriter, r *http.Request) {
	ms, devs, err := a.machines(r)
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	hostOf := map[string]string{}
	for _, m := range ms {
		if !m.IsHost() {
			continue
		}
		for _, e := range m.Evidence {
			if e.Source == coverage.EvidenceScan {
				hostOf[e.Addresses[0]] = m.ID
			}
		}
	}
	scope := a.scope()
	out := []deviceView{}
	for _, d := range devs {
		addr, err := netip.ParseAddr(d.Address)
		if err != nil || !scope.Contains(addr) {
			continue
		}
		if d.Services == nil {
			d.Services = []discovery.Service{}
		}
		out = append(out, deviceView{StoredDevice: d, HostID: hostOf[d.Address]})
	}
	resp := map[string]any{"devices": out}
	switch last, err := a.store.LastScanRun(r.Context()); {
	case err == nil:
		resp["last_scan"] = last
	case !errors.Is(err, store.ErrNotFound):
		a.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// integrationView is an integration without its configuration and secret:
// the configuration holds pinned keys and token IDs, and neither is needed
// to monitor the integration.
type integrationView struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Address     string          `json:"address"`
	Enabled     bool            `json:"enabled"`
	Health      string          `json:"health"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	LastSuccess *time.Time      `json:"last_success,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
	Status      json.RawMessage `json:"status"`
}

func (a *api) listIntegrations(w http.ResponseWriter, r *http.Request) {
	ins, err := a.store.Integrations(r.Context())
	if err != nil {
		a.internalError(w, r, err)
		return
	}
	now := a.now()
	out := []integrationView{}
	for _, in := range ins {
		st := in.Status
		if len(st) == 0 || !json.Valid(st) {
			st = json.RawMessage("{}")
		}
		out = append(out, integrationView{
			ID: in.ID, Kind: in.Kind, Name: in.Name, Address: in.Address, Enabled: in.Enabled,
			Health: coverage.IntegrationHealth(in, now, a.interval(in.Kind)), CreatedBy: in.CreatedBy, CreatedAt: in.CreatedAt,
			LastSuccess: in.LastSuccess, LastError: in.LastError, Status: st,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"integrations": out})
}
