// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

// secondSource reports whether a stored record of source belongs to app's
// second sources as the catalog names them now: an entry that dropped a
// CPE or its osv_packages must not ship what was stored for them.
func secondSource(app *catalog.App, source string) bool {
	if source == "osv" {
		return OSVApp(app)
	}
	cpe, ok := strings.CutPrefix(source, "nvd:")
	if !ok || !NVDApp(app) {
		return false
	}
	for _, c := range app.Advisories.CPE {
		if c == cpe {
			return true
		}
	}
	return false
}

// cveID is the form of a CVE ID the client accepts.
var cveID = regexp.MustCompile(`^CVE-\d{4}-\d{4,9}$`)

// Snapshot turns what Collect stored into the content of one package: the
// catalog entries, the index, the advisories of every repository under the
// derived ID and under each catalog app that names it, the KEV list, and
// EPSS scores for the CVEs the package names. The result is the same for
// the same store and clock.
//
// second are the catalog apps whose records from the second sources (OSV,
// the NVD) go into the package as well, under the app's own ID. A record
// a repository already published under that ID is not repeated, and each
// carries its origin (advisory.Origin), by which an installation ranks it
// below what the project published itself.
func Snapshot(ctx context.Context, st *store.Store, entries []catalog.Entry, index *applists.Table, repos []Repo, second []*catalog.App, now time.Time, valid time.Duration) (feed.Snapshot, error) {
	snap := feed.Snapshot{Channel: feed.ChannelPackage, Sequence: now.Unix(), CreatedAt: now.UTC(), ExpiresAt: now.Add(valid).UTC(),
		CatalogVersion: now.UTC().Format("2006.01.02"), Catalog: entries}
	if index.Len() > 0 {
		snap.Index = index.Marshal()
	}
	cves := map[string]bool{}
	for _, r := range repos {
		recs, err := st.Advisories(ctx, r.App.ID)
		if err != nil {
			return feed.Snapshot{}, err
		}
		for _, rec := range recs {
			// Only what this repository published: an ID can hold records
			// of another source, and must not lend them to the package.
			if rec.Source != "github:"+r.Name {
				continue
			}
			for _, id := range append([]string{rec.Vuln.ID}, rec.Vuln.Aliases...) {
				if strings.HasPrefix(id, "CVE-") {
					cves[id] = true
				}
			}
			for _, appID := range append([]string{r.App.ID}, r.CatalogIDs...) {
				snap.Advisories = append(snap.Advisories, feed.AdvisoryLine{AppID: appID, CVSS: rec.CVSS, Severity: rec.SeverityLabel, OSV: rec.Vuln})
			}
		}
	}
	have := map[[2]string]bool{}
	for _, a := range snap.Advisories {
		have[[2]string{a.AppID, a.OSV.ID}] = true
	}
	for _, app := range second {
		recs, err := st.Advisories(ctx, app.ID)
		if err != nil {
			return feed.Snapshot{}, err
		}
		// Project-published records first, so that the same ID from two
		// sources ships as the more precise one.
		sort.SliceStable(recs, func(i, j int) bool { return recs[i].Source == "osv" && recs[j].Source != "osv" })
		for _, rec := range recs {
			if !secondSource(app, rec.Source) || have[[2]string{app.ID, rec.Vuln.ID}] {
				continue
			}
			have[[2]string{app.ID, rec.Vuln.ID}] = true
			for _, id := range append([]string{rec.Vuln.ID}, rec.Vuln.Aliases...) {
				if strings.HasPrefix(id, "CVE-") {
					cves[id] = true
				}
			}
			snap.Advisories = append(snap.Advisories, feed.AdvisoryLine{AppID: app.ID, CVSS: rec.CVSS, Severity: rec.SeverityLabel,
				OSV: advisory.WithOrigin(rec.Vuln, rec.Source)})
		}
	}
	sort.SliceStable(snap.Advisories, func(i, j int) bool {
		a, b := snap.Advisories[i], snap.Advisories[j]
		if a.AppID != b.AppID {
			return a.AppID < b.AppID
		}
		return a.OSV.ID < b.OSV.ID
	})
	kev, err := st.KEVEntries(ctx)
	if err != nil {
		return feed.Snapshot{}, err
	}
	snap.KEV = []feed.KEVLine{}
	for _, e := range kev {
		if !cveID.MatchString(e.CVE) {
			continue // one malformed upstream record must not stop the package
		}
		snap.KEV = append(snap.KEV, feed.KEVLine{CVE: e.CVE, DateAdded: e.DateAdded, Ransomware: e.Ransomware})
	}
	epss, err := st.EPSSEntries(ctx)
	if err != nil {
		return feed.Snapshot{}, err
	}
	snap.EPSS = []feed.EPSSLine{}
	for _, e := range epss {
		// The store keeps scores of CVEs that left the package; the
		// package carries the scores of its own CVEs only.
		if cves[e.CVE] && cveID.MatchString(e.CVE) {
			snap.EPSS = append(snap.EPSS, feed.EPSSLine{CVE: e.CVE, Score: e.Score, Percentile: e.Percentile, Date: e.Date})
		}
	}
	return snap, nil
}
