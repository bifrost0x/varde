// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"testing"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/match"
)

// An image read as its derived entry does not carry the generated entry's
// CPE: NVD records stored for it are left out, whether the installation
// read them itself or the data package brought them.
func TestForeignCPEsByOrigin(t *testing.T) {
	const cpe = "cpe:2.3:a:acme:widget"
	adv := func(source, origin, id string) match.Advisory {
		v := advisory.Vulnerability{ID: id}
		if origin != "" {
			v = advisory.WithOrigin(v, origin)
		}
		return match.Advisory{Source: source, Vuln: v}
	}
	stored := []match.Advisory{
		adv("feed", "", "GHSA-project"),
		adv("feed", "osv", "GO-2026-0001"),
		adv("feed", "nvd:"+cpe, "CVE-2026-0001"),
		adv("nvd:"+cpe, "", "CVE-2026-0002"),
	}
	ids := func(app *catalog.App) string {
		var out string
		for _, a := range withoutForeignCPEs(stored, app) {
			out += a.Vuln.ID + " "
		}
		return out
	}
	if got := ids(&catalog.App{ID: "gh-acme-widget"}); got != "GHSA-project GO-2026-0001 " {
		t.Errorf("derived view keeps %q", got)
	}
	with := &catalog.App{ID: "gh-acme-widget", Advisories: catalog.Advisories{CPE: []string{cpe}}}
	if got := ids(with); got != "GHSA-project GO-2026-0001 CVE-2026-0001 CVE-2026-0002 " {
		t.Errorf("entry with the CPE keeps %q", got)
	}
}
