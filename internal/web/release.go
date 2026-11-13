// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/pipeline"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/version"
)

// releaseView is what a page says about the newest release of the app a
// container runs, from the package lists of the data package.
type releaseView struct {
	remedy.ReleaseFix
	// Fixes is set when the release is newer than what runs and of the
	// same image variant: Fixed, Open and Unknown then say what updating
	// to it fixes. Without it the page names the release only, or says the
	// container runs it already (Newest).
	Fixes bool
	// OpenShown and UnknownShown are the first advisories of Open and
	// Unknown, each once; OpenMore and UnknownMore count the rest.
	OpenShown, UnknownShown []string
	OpenMore, UnknownMore   int
	// This, ThisOpen and ThisUnknown are set on a finding's page when the
	// release fixes that finding, still has it, or Varde cannot tell.
	This, ThisOpen, ThisUnknown bool
}

// maxShown bounds the advisories a line lists.
const maxShown = 8

// shown lists the advisories of flaws once each, the first maxShown of
// them, and counts the rest.
func shown(flaws []remedy.Flaw) (ids []string, more int) {
	seen := map[string]bool{}
	for _, f := range flaws {
		if seen[f.AdvisoryID] {
			continue
		}
		seen[f.AdvisoryID] = true
		if len(ids) == maxShown {
			more++
			continue
		}
		ids = append(ids, f.AdvisoryID)
	}
	return ids, more
}

// releaseInput is one container whose image findings are compared with
// the newest release of its app.
type releaseInput struct {
	wl inventory.Workload
	id identify.Result
	// host is the container's host; nil when it could not be read, and
	// then nothing is claimed: the platform decides which list counts.
	host *inventory.Host
	// findings are the container's active image findings.
	findings []match.Finding
}

// releaseCandidate is a container with release lists to compare.
type releaseCandidate struct {
	in    releaseInput
	app   *catalog.App
	run   remedy.Running
	lines []feed.ReleaseLine
}

// containerReleases compares each container's image findings with the
// newest release of its app. However many containers, it reads the
// release lists once, the registry's tags once and the advisories of
// every compared package once. A nil entry means there is nothing to say.
func (a *app) containerReleases(ctx context.Context, ins []releaseInput) []*releaseView {
	out := make([]*releaseView, len(ins))
	type pending struct {
		in   releaseInput
		app  *catalog.App
		ref  imageref.Ref
		slot int
	}
	var todo []pending
	var images []store.ReleaseImage
	floating := false
	for i, in := range ins {
		c := in.wl.Container
		if c == nil || in.host == nil || len(in.findings) == 0 || in.id.AppID == "" || !in.id.Confidence.Notifiable() {
			continue
		}
		app, ok := a.d.Catalog.Current().App(in.id.AppID)
		if !ok {
			continue
		}
		ref, err := imageref.Parse(c.ImageRef)
		if err != nil {
			continue
		}
		// An image a generated entry did not check is read as its
		// derived entry; no release was read for it, and another image's
		// list must not stand in.
		if identify.ReadsAsDerived(app, ref.Repository) {
			continue
		}
		app = identify.AppForImage(app, ref.Repository)
		todo = append(todo, pending{in, app, ref, i})
		images = append(images, store.ReleaseImage{AppID: app.ID, Image: ref.Repository})
		floating = floating || ref.Tag == "" || version.IsFloating(ref.Tag)
	}
	if len(todo) == 0 {
		return out
	}
	rows, err := a.d.Store.ReleasePackagesOf(ctx, images)
	if err != nil {
		a.d.Log.Warn("release package lists not read", "err", err)
		return out
	}
	var tags map[string]store.ImageTag
	if floating {
		if tags, err = a.d.Store.ImageTags(ctx); err != nil {
			a.d.Log.Warn("image tags not read", "err", err)
		}
	}
	var cands []releaseCandidate
	var slots []int
	for _, p := range todo {
		lines := decodeLines(rows[store.ReleaseImage{AppID: p.app.ID, Image: p.ref.Repository}], p.app.ID, p.ref.Repository)
		if len(lines) == 0 {
			continue
		}
		cands = append(cands, releaseCandidate{in: p.in, app: p.app, run: running(p.in, p.ref, tags), lines: lines})
		slots = append(slots, p.slot)
	}
	if len(cands) == 0 {
		return out
	}
	advs, err := a.packageAdvisories(ctx, cands)
	if err != nil {
		// Without the records nothing can be compared; claiming fixes
		// from an empty set would call every flaw fixed.
		a.d.Log.Warn("advisories for release fixes not read", "err", err)
		return out
	}
	for i, c := range cands {
		fix, ok := remedy.ReleaseFixFor(c.app, c.run, remedy.HostPlatform(c.in.host.Arch), c.in.findings, c.lines, advs)
		if fix.Tag == "" {
			continue
		}
		v := &releaseView{ReleaseFix: fix, Fixes: ok}
		v.OpenShown, v.OpenMore = shown(fix.Open)
		v.UnknownShown, v.UnknownMore = shown(fix.Unknown)
		out[slots[i]] = v
	}
	return out
}

// running is the image tag a container runs, as far as it is trusted: the
// registry's tag for a floating one, nothing when Varde doubts the
// identification.
func running(in releaseInput, ref imageref.Ref, tags map[string]store.ImageTag) remedy.Running {
	r := remedy.Running{Repository: ref.Repository, Tag: ref.Tag}
	if ref.Tag == "" || version.IsFloating(ref.Tag) {
		r.Tag = tags[ref.Repository+"@"+registry.RepoDigest(in.wl.Container, ref.Repository)].Tag
	}
	if in.id.Doubt() != "" {
		r.Tag = ""
	}
	return r
}

// decodeLines decodes stored release lines of app's image.
func decodeLines(raw [][]byte, appID, image string) []feed.ReleaseLine {
	lines := make([]feed.ReleaseLine, 0, len(raw))
	for _, r := range raw {
		var l feed.ReleaseLine
		if json.Unmarshal(r, &l) != nil || l.AppID != appID || l.Image != image {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

// packageAdvisories reads the advisories of every image finding's package
// of the candidates in one read, as the analysis counts them.
func (a *app) packageAdvisories(ctx context.Context, cands []releaseCandidate) (func(distro.Package) []match.Advisory, error) {
	seen := map[string]bool{}
	var ids []string
	for _, c := range cands {
		for _, f := range c.in.findings {
			if eco, name, ok := cutPackage(f.Evidence.Package); ok && f.Image {
				if id := distro.SystemAppID(eco, name); !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	recs, err := a.d.Store.AdvisoriesFor(ctx, ids)
	if err != nil {
		return nil, err
	}
	conv := a.d.Advisories
	if conv == nil {
		conv = func(app *catalog.App, recs []store.AdvisoryRecord) []match.Advisory {
			return pipeline.AdvisoriesFor(app, recs, nil)
		}
	}
	byApp := make(map[string][]match.Advisory, len(recs))
	for id, rs := range recs {
		// The package's own app, as the analysis makes it.
		_, name, _ := distro.ParseSystemAppID(id)
		byApp[id] = conv(&catalog.App{ID: id, Name: name}, rs)
	}
	return func(p distro.Package) []match.Advisory { return byApp[distro.SystemAppID(p.Ecosystem, p.Name)] }, nil
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
