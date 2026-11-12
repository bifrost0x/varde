// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/store"
)

// metrics serves Prometheus text format. It requires an API token or a
// session (read scope is enough) because counts reveal security posture.
func (a *app) metrics(w http.ResponseWriter, r *http.Request) {
	if a.d.APIAuth == nil {
		http.NotFound(w, r)
		return
	}
	if _, ok := a.d.APIAuth.Authenticate(r); !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="varde"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	fs, err := a.d.Store.Findings(ctx, store.FindingFilter{})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ws, err := a.d.Store.Workloads(ctx, store.WorkloadFilter{})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	states, err := a.d.Store.SourceStates(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	notes, err := a.d.Store.Notifications(ctx, 1000)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type key struct{ priority, state, match string }
	counts := map[key]int{}
	for _, f := range fs {
		counts[key{f.Priority, f.State, f.MatchState}]++
	}
	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })

	var b strings.Builder
	gauge := func(name, help string) { fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name) }

	gauge("varde_build_info", "Build information.")
	fmt.Fprintf(&b, "varde_build_info{version=%q} 1\n", buildinfo.Version)
	gauge("varde_findings", "Findings by priority, state and match state (resolved excluded).")
	for _, k := range keys {
		fmt.Fprintf(&b, "varde_findings{priority=%q,state=%q,match=%q} %d\n", k.priority, k.state, k.match, counts[k])
	}
	gauge("varde_workloads", "Active workloads.")
	fmt.Fprintf(&b, "varde_workloads %d\n", len(ws))
	gauge("varde_inventory_last_sync_timestamp_seconds", "Last successful inventory sync.")
	fmt.Fprintf(&b, "varde_inventory_last_sync_timestamp_seconds %d\n", unix(a.d.LastScan()))
	gauge("varde_source_last_success_timestamp_seconds", "Last successful refresh per advisory source.")
	gauge("varde_source_error", "1 when the last attempt of a source failed.")
	for _, st := range states {
		fmt.Fprintf(&b, "varde_source_last_success_timestamp_seconds{source=%q,key=%q} %d\n", st.Source, st.Key, unix(st.LastSuccess))
	}
	for _, st := range states {
		failed := 0
		if st.LastError != "" {
			failed = 1
		}
		fmt.Fprintf(&b, "varde_source_error{source=%q,key=%q} %d\n", st.Source, st.Key, failed)
	}
	failures := 0
	cutoff := a.d.Now().Add(-24 * time.Hour)
	for _, n := range notes {
		if n.Status == "failed" && n.SentAt.After(cutoff) {
			failures++
		}
	}
	gauge("varde_notification_failures_24h", "Failed notification deliveries in the last 24 hours.")
	fmt.Fprintf(&b, "varde_notification_failures_24h %d\n", failures)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
