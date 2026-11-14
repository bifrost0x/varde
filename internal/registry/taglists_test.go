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
	// Each repository once.
	jobs := TagListJobs(mustCatalog(t), ws, ids, findings, nil, now)
	if len(jobs) != 1 || jobs[0].Repository != "docker.io/vaultwarden/server" {
		t.Fatalf("jobs %+v", jobs)
	}
	// A repository with an open affected finding comes before one that is
	// only listed to say whether a newer release exists.
	more := append([]inventory.Workload{{ID: "d", Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: "aaa/vaultwarden:1.37.5"}}}, ws...)
	ids["d"] = identify.Result{AppID: "vaultwarden", Confidence: identify.Exact}
	if jobs := TagListJobs(mustCatalog(t), more, ids, findings, nil, now); len(jobs) != 2 || jobs[0].Repository != "docker.io/vaultwarden/server" || jobs[1].Repository != "docker.io/aaa/vaultwarden" {
		t.Fatalf("order %+v", jobs)
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
	if len(TagListJobs(mustCatalog(t), ws, ids, findings, nil, now)) != 1 {
		t.Error("a container without findings is not listed for its newest release")
	}
}
