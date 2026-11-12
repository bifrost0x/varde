// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"testing"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

// An app the feed covers is judged by the feed alone: records the direct
// sources stored before the uplink was switched on are no longer refreshed
// and must not keep findings open. They are used again after leaving.
func TestAdvisoriesForFollowsOrigin(t *testing.T) {
	recs := []store.AdvisoryRecord{
		{Source: "github", Vuln: advisory.Vulnerability{ID: "GHSA-old-direct"}},
		{Source: store.FeedSource, Vuln: advisory.Vulnerability{ID: "GHSA-feed"}},
		{Source: "nvd", Vuln: advisory.Vulnerability{ID: "CVE-old-direct"}},
	}
	ids := func(app *catalog.App) string {
		out := ""
		for _, a := range AdvisoriesFor(app, recs, nil) {
			out += a.Vuln.ID + " "
		}
		return out
	}
	if got := ids(&catalog.App{ID: "immich", Origin: catalog.OriginFeed}); got != "GHSA-feed " {
		t.Errorf("feed app: %q", got)
	}
	for _, o := range []catalog.Origin{catalog.OriginBuiltin, catalog.OriginLocal} {
		if got := ids(&catalog.App{ID: "immich", Origin: o}); got != "GHSA-old-direct GHSA-feed CVE-old-direct " {
			t.Errorf("%s app: %q", o, got)
		}
	}
	if got := ids(nil); got != "GHSA-old-direct GHSA-feed CVE-old-direct " {
		t.Errorf("unknown app: %q", got)
	}
}

// With the data package the feed replaces GitHub only; what osv.dev or the
// NVD stored for an app, because the user switched them on, still counts.
func TestAdvisoriesForSupersededHook(t *testing.T) {
	recs := []store.AdvisoryRecord{
		{Source: "github:immich-app/immich", Vuln: advisory.Vulnerability{ID: "GHSA-old-direct"}},
		{Source: store.FeedSource, Vuln: advisory.Vulnerability{ID: "GHSA-feed"}},
		{Source: "nvd", Vuln: advisory.Vulnerability{ID: "CVE-nvd"}},
	}
	githubOnly := func(_ *catalog.App, source string) bool { return len(source) >= 7 && source[:7] == "github:" }
	out := ""
	for _, a := range AdvisoriesFor(&catalog.App{ID: "immich", Origin: catalog.OriginFeed}, recs, githubOnly) {
		out += a.Vuln.ID + " "
	}
	if out != "GHSA-feed CVE-nvd " {
		t.Errorf("advisories = %q", out)
	}
}
