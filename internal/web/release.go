// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/store"
)

// releaseView is what a page says about the newest release of the app a
// container runs, from the package lists of the data package.
type releaseView struct {
	remedy.ReleaseFix
	// Fixes is set when the release is newer than what runs: Fixed and
	// Open then say what updating to it fixes. Without it the page names
	// the release only, or says the container runs it already (Newest).
	Fixes bool
	// OpenShown are the first open advisories, OpenMore the rest.
	OpenShown []string
	OpenMore  int
	// This and ThisOpen are set on a finding's page when the release
	// fixes that finding, or does not.
	This, ThisOpen bool
}

// maxOpenShown bounds the open advisories a line lists.
const maxOpenShown = 8

// containerRelease compares the image findings of container workload wl
// with the newest release of its app, for the host's architecture (arch;
// empty when unknown). It reads the release's lists once and the
// advisories of every compared package together; nil when there is no
// release to speak of.
func (a *app) containerRelease(ctx context.Context, wl inventory.Workload, id identify.Result, arch string, findings []match.Finding) *releaseView {
	if wl.Container == nil || id.AppID == "" || !id.Confidence.Notifiable() {
		return nil
	}
	app, ok := a.d.Catalog.Current().App(id.AppID)
	if !ok {
		return nil
	}
	ref, err := imageref.Parse(wl.Container.ImageRef)
	if err != nil {
		return nil
	}
	// An image a generated entry did not check is read as its derived
	// entry; no release was read for it, and another image's list must
	// not stand in.
	if identify.ReadsAsDerived(app, ref.Repository) {
		return nil
	}
	app = identify.AppForImage(app, ref.Repository)
	raw, err := a.d.Store.ReleasePackagesFor(ctx, app.ID, ref.Repository)
	if err != nil || len(raw) == 0 {
		return nil
	}
	lines := make([]feed.ReleaseLine, 0, len(raw))
	for _, r := range raw {
		var l feed.ReleaseLine
		if json.Unmarshal(r, &l) != nil || l.AppID != app.ID || l.Image != ref.Repository {
			continue
		}
		lines = append(lines, l)
	}
	// A version Varde doubts is no ground to say what a release fixes.
	running := id.Version
	if id.Doubt() != "" {
		running = ""
	}
	fix, ok := remedy.ReleaseFixFor(app, running, remedy.HostPlatform(arch), findings, lines, a.packageAdvisories(ctx, findings))
	if fix.Tag == "" {
		return nil
	}
	v := &releaseView{ReleaseFix: fix, Fixes: ok}
	// An advisory open in several packages is listed once.
	seen := map[string]bool{}
	for _, f := range fix.Open {
		if seen[f.AdvisoryID] {
			continue
		}
		seen[f.AdvisoryID] = true
		if len(v.OpenShown) == maxOpenShown {
			v.OpenMore++
			continue
		}
		v.OpenShown = append(v.OpenShown, f.AdvisoryID)
	}
	return v
}

// packageAdvisories returns the advisories of the image findings'
// packages, as the analysis matched them. They are read together, on the
// first call: only a newer release compares packages at all.
func (a *app) packageAdvisories(ctx context.Context, findings []match.Finding) func(distro.Package) []match.Advisory {
	var byApp map[string][]store.AdvisoryRecord
	return func(p distro.Package) []match.Advisory {
		if byApp == nil {
			seen := map[string]bool{}
			var ids []string
			for _, f := range findings {
				if eco, name, ok := cutPackage(f.Evidence.Package); ok && f.Image {
					if id := distro.SystemAppID(eco, name); !seen[id] {
						seen[id] = true
						ids = append(ids, id)
					}
				}
			}
			recs, err := a.d.Store.AdvisoriesFor(ctx, ids)
			if err != nil {
				recs = map[string][]store.AdvisoryRecord{}
			}
			byApp = recs
		}
		// A package's own app, which no source but its distribution's
		// and the language records refreshes: every record counts.
		recs := byApp[distro.SystemAppID(p.Ecosystem, p.Name)]
		out := make([]match.Advisory, 0, len(recs))
		for _, r := range recs {
			out = append(out, match.Advisory{Source: r.Source, Vuln: r.Vuln, CVSS: r.CVSS, SeverityLabel: r.SeverityLabel})
		}
		return out
	}
}

// cutPackage splits a finding's evidence package ("Debian:12/openssl",
// "npm/@scope/name"); ecosystems have no slash.
func cutPackage(s string) (eco, name string, ok bool) {
	eco, name, ok = strings.Cut(s, "/")
	return eco, name, ok && eco != "" && name != ""
}

// imageFindings decodes the active image findings among fs.
func imageFindings(fs []store.Finding) []match.Finding {
	var out []match.Finding
	for _, f := range fs {
		if !active(f.State) {
			continue
		}
		var m match.Finding
		if json.Unmarshal(f.Detail, &m) == nil && m.Image {
			out = append(out, m)
		}
	}
	return out
}
