// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

func TestTagListJobs(t *testing.T) {
	now := time.Now()
	ws := []inventory.Workload{
		{ID: "a", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "vaultwarden/server:1.30.0"}},
		{ID: "b", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "vaultwarden/server:1.30.0"}},
		{ID: "c", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "vaultwarden/server:1.37.5"}},
	}
	ids := map[string]identify.Result{
		"a": {AppID: "vaultwarden", Confidence: identify.Exact},
		"b": {AppID: "vaultwarden", Confidence: identify.Exact},
		"c": {AppID: "vaultwarden", Confidence: identify.Exact},
	}
	findings := []store.Finding{
		{WorkloadID: "a", MatchState: "affected", State: store.StateOpen},
		{WorkloadID: "b", MatchState: "affected", State: store.StateOpen},
		{WorkloadID: "c", MatchState: "unverified", State: store.StateOpen},
	}
	// Only repositories with open affected findings, once each.
	jobs := TagListJobs(mustCatalog(t), ws, ids, findings, nil, now)
	if len(jobs) != 1 || jobs[0].Repository != "docker.io/vaultwarden/server" {
		t.Fatalf("jobs %+v", jobs)
	}
	known := map[string]store.RepositoryTags{"docker.io/vaultwarden/server": {Checked: now.Add(-time.Hour)}}
	if len(TagListJobs(mustCatalog(t), ws, ids, findings, known, now)) != 0 {
		t.Error("fresh list read again")
	}
	known["docker.io/vaultwarden/server"] = store.RepositoryTags{Checked: now.Add(-25 * time.Hour)}
	if len(TagListJobs(mustCatalog(t), ws, ids, findings, known, now)) != 1 {
		t.Error("old list not read again")
	}
	findings[0].State, findings[1].State = store.StateResolved, store.StateResolved
	if len(TagListJobs(mustCatalog(t), ws, ids, findings, nil, now)) != 0 {
		t.Error("resolved findings need no tag list")
	}
}
