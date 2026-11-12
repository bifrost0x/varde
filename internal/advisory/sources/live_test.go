// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"os"
	"testing"
	"time"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/match"
)

// TestLiveDistro fetches the real Debian and Alpine records of nginx from
// osv.dev and checks the corpus statements against them: the patched
// packages are not affected by the CVEs fixed for them, the older ones are.
// It only runs with VARDE_LIVE_OSV=1; it is not part of CI.
func TestLiveDistro(t *testing.T) {
	if os.Getenv("VARDE_LIVE_OSV") != "1" {
		t.Skip("set VARDE_LIVE_OSV=1 to query osv.dev")
	}
	cat, err := catalog.Load(catalogdata.FS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	app, ok := cat.App("nginx")
	if !ok {
		t.Fatal("nginx not in the catalog")
	}
	s := newStore(t)
	present := map[string][]distro.Package{"nginx": {
		{Ecosystem: "Debian:12", Name: "nginx", Version: "1.22.1-9+deb12u8"},
		{Ecosystem: "Alpine:v3.22", Name: "nginx", Version: "1.28.3-r2"},
	}}
	d := &Distro{Deps: Deps{HTTP: httpx.New(httpx.Options{Timeout: 60 * time.Second}), Store: s}, Packages: func(context.Context) (map[string][]distro.Package, error) {
		return present, nil
	}}
	for i := 0; i < 3; i++ {
		res, err := d.Refresh(t.Context(), []*catalog.App{app})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("refresh %d: %+v", i, res)
		if st, _ := s.SourceState(t.Context(), match.SourceDistro, "nginx"); st.LastError == "" {
			break
		}
	}
	recs, err := s.Advisories(t.Context(), "nginx")
	if err != nil || len(recs) == 0 {
		t.Fatalf("no records: %v", err)
	}
	advs := make([]match.Advisory, 0, len(recs))
	for _, r := range recs {
		advs = append(advs, match.Advisory{Source: r.Source, Vuln: r.Vuln})
	}
	t.Logf("%d records stored", len(advs))
	for _, c := range []struct {
		p        distro.Package
		id       string
		affected bool
	}{
		{distro.Package{Ecosystem: "Debian:12", Name: "nginx", Version: "1.22.1-9+deb12u8"}, "DEBIAN-CVE-2026-9256", false},
		{distro.Package{Ecosystem: "Debian:12", Name: "nginx", Version: "1.22.1-9+deb12u7"}, "DEBIAN-CVE-2026-9256", true},
		{distro.Package{Ecosystem: "Alpine:v3.22", Name: "nginx", Version: "1.28.3-r2"}, "ALPINE-CVE-2026-9256", false},
		{distro.Package{Ecosystem: "Alpine:v3.22", Name: "nginx", Version: "1.28.3-r1"}, "ALPINE-CVE-2026-9256", true},
	} {
		p := c.p
		got := false
		affected := 0
		for _, f := range match.Match(match.Input{App: app, Distro: &p}, advs, match.Enrichment{}) {
			if f.State == match.Affected {
				affected++
				if f.AdvisoryID == c.id {
					got = true
				}
			}
		}
		t.Logf("%s %s: %d affected", p.Ecosystem, p.Version, affected)
		if got != c.affected {
			t.Errorf("%s %s: %s affected %v, want %v", p.Ecosystem, p.Version, c.id, got, c.affected)
		}
	}
}
