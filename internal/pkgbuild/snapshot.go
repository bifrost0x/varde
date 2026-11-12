// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

// cveID is the form of a CVE ID the client accepts.
var cveID = regexp.MustCompile(`^CVE-\d{4}-\d{4,9}$`)

// Snapshot turns what Collect stored into the content of one package: the
// catalog entries, the index, the advisories of every repository under the
// derived ID and under each catalog app that names it, the KEV list, and
// EPSS scores for the CVEs the package names. The result is the same for
// the same store and clock.
func Snapshot(ctx context.Context, st *store.Store, entries []catalog.Entry, index *applists.Table, repos []Repo, now time.Time, valid time.Duration) (feed.Snapshot, error) {
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
