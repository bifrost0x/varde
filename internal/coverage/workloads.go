// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"sort"

	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
)

// Gap is a workload Varde cannot fully assess, with what it knows.
type Gap struct {
	Workload inventory.Workload
	ID       identify.Result
	// Route is the public host name for a public-route gap.
	Route string
	// NotAppKind says why a workload is not counted (see NotAnApp).
	NotAppKind string
}

// Workloads is the coverage of the workloads: which ones Varde can check
// against advisories, and the gaps. It is the one definition every page, the
// notices and the API use.
type Workloads struct {
	// Total counts the workloads that are apps; helpers are left out.
	Total int
	// Identified are exact or strong identifications; Assessable of them
	// also have a known version.
	Identified, Assessable int
	VersionUnknown         []Gap
	Weak                   []Gap
	// NotInCatalog are containers no catalog entry matches.
	NotInCatalog []Gap
	// PublicRoutes are public routes whose workload Varde cannot assess,
	// one per workload and host name.
	PublicRoutes []Gap
	// NotApps are helpers and workloads the user marked; not counted.
	NotApps []Gap
}

// Percent is the share of identified workloads.
func (w Workloads) Percent() int {
	if w.Total == 0 {
		return 0
	}
	return w.Identified * 100 / w.Total
}

// BlindSpots counts the workloads with at least one gap; a workload behind a
// public route that is also not in the catalog counts once.
func (w Workloads) BlindSpots() int {
	seen := map[string]bool{}
	for _, list := range [][]Gap{w.VersionUnknown, w.Weak, w.NotInCatalog, w.PublicRoutes} {
		for _, g := range list {
			seen[g.Workload.ID] = true
		}
	}
	return len(seen)
}

// AssessWorkloads computes the workload coverage. Removed workloads must be
// left out by the caller.
func AssessWorkloads(ws []inventory.Workload, ids map[string]identify.Result, publicDomains []string, marked map[string]bool) Workloads {
	var c Workloads
	for _, wl := range ws {
		id := ids[wl.ID]
		if kind, skip := NotAnApp(wl, id, marked); skip {
			c.NotApps = append(c.NotApps, Gap{Workload: wl, ID: id, NotAppKind: kind})
			continue
		}
		c.Total++
		g := Gap{Workload: wl, ID: id}
		switch {
		case id.Confidence.Notifiable():
			c.Identified++
			if id.VersionKnown() {
				c.Assessable++
			} else {
				c.VersionUnknown = append(c.VersionUnknown, g)
			}
		case id.Confidence == identify.Weak:
			c.Weak = append(c.Weak, g)
		case wl.Kind == inventory.KindContainer:
			c.NotInCatalog = append(c.NotInCatalog, g)
		}
		if !Assessable(id) {
			for _, host := range PublicRouteHosts(wl, publicDomains) {
				pg := g
				pg.Route = host
				c.PublicRoutes = append(c.PublicRoutes, pg)
			}
		}
	}
	sort.SliceStable(c.PublicRoutes, func(i, j int) bool { return c.PublicRoutes[i].Route < c.PublicRoutes[j].Route })
	sort.SliceStable(c.NotApps, func(i, j int) bool { return c.NotApps[i].Workload.Name < c.NotApps[j].Workload.Name })
	return c
}
