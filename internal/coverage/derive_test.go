// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// An image on GitHub's registry without a source label is derived from its
// path, but only for "ghcr.io/<owner>/<repo>".
func TestDeriveAppsFromGHCRPath(t *testing.T) {
	cat, err := catalog.Load(fstest.MapFS{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ws := []inventory.Workload{
		{ID: "1", Container: &inventory.Container{ImageRef: "ghcr.io/gethomepage/homepage:v0.9.10"}},
		{ID: "2", Container: &inventory.Container{ImageRef: "ghcr.io/linuxserver/baseimage/alpine:3.20"}},
		{ID: "3", Container: &inventory.Container{ImageRef: "docker.io/library/nginx:1.27"}},
	}
	got := DeriveApps(cat, nil, ws)
	if len(got) != 1 || got[0].ID != "gh-gethomepage-homepage" || got[0].Advisories.GitHubRepos[0] != "gethomepage/homepage" {
		t.Fatalf("derived: %+v", got)
	}
}

func TestFirmwareNotices(t *testing.T) {
	ins := []store.Integration{
		{ID: "u1", Name: "UniFi", Enabled: true, Status: []byte(`{"devices":[
			{"name":"Gateway","model":"UCG Ultra","mac":"74:ac:b9:00:00:01","ip":"10.10.1.1","firmware":"4.0.6","updatable":true},
			{"name":"AP","model":"U7 Pro","mac":"74:ac:b9:00:00:02","firmware":"7.0.82"}]}`)},
		{ID: "u2", Name: "Off", Enabled: false, Status: []byte(`{"devices":[{"mac":"aa","updatable":true}]}`)},
	}
	got := FirmwareNotices(ins)
	if len(got) != 1 || got[0].Key != store.NoticeFirmware+":u1:74:ac:b9:00:00:01" || got[0].Title != "Firmware update for Gateway" {
		t.Fatalf("notices: %+v", got)
	}
}
