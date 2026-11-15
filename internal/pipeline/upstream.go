// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/paths"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/upstream"
	"github.com/bifrost0x/varde/internal/version"
)

// upstreamStore is the part of the store that keeps the upstream status of
// containers (ADR 0045); a store without it leaves the status out.
type upstreamStore interface {
	UpstreamChecks(ctx context.Context) (map[store.UpstreamKey]store.UpstreamCheck, error)
	ReplaceUpstreamStatus(ctx context.Context, status map[string]json.RawMessage, now time.Time) error
	WakeUpstreamSnoozes(ctx context.Context, ids []string, now time.Time) (int64, error)
	ReleasePackagesOf(ctx context.Context, images []store.ReleaseImage) (map[store.ReleaseImage][][]byte, error)
	AdvisoriesFor(ctx context.Context, appIDs []string) (map[string][]store.AdvisoryRecord, error)
}

// componentPriority caps the priority of a finding in a package of a
// container's image by what that package is to the container (ADR 0045):
// only a package that serves what the container exposes, or a library such
// a program loads, can be urgent. Known exploitation of a package that is
// merely in the image is at most "update soon".
func componentPriority(prio policy.Priority, reason string, m match.Finding, pkg string, c *inventory.Container, exposure inventory.Exposure) (policy.Priority, string) {
	if !m.Image || pkg == "" || prio != policy.P1 {
		return prio, reason
	}
	exposed := exposure == inventory.ExposurePublic || exposure == inventory.ExposureLAN
	var command []string
	if c != nil && c.Runtime != nil {
		command = c.Runtime.Command
	}
	if paths.ComponentOf(pkg, command, exposed).Reach == paths.Served {
		return prio, reason
	}
	what := "severe"
	if m.KEV {
		what = "known exploited"
	}
	switch {
	case !exposed:
		return policy.P2, what + ", but in a package of the image of a container nothing outside its host reaches"
	case len(command) == 0:
		return policy.P2, what + ", in a package of the image; Varde does not know what the container runs, so it cannot tie " + pkg + " to what it serves"
	}
	return policy.P2, what + ", but " + pkg + " is a package in the image that nothing ties to what the container serves"
}

// imagePackageName is the package of an image finding's app
// ("Debian:12/openssl" gives "openssl"); empty for other findings.
func imagePackageName(appID string) string {
	if _, name, ok := distro.ParseSystemAppID(appID); ok {
		return name
	}
	return ""
}

// upstreamInput is one container whose upstream status is decided.
type upstreamInput struct {
	w        inventory.Workload
	findings []match.Finding
	// byKey maps "advisory|package" to the container's finding IDs.
	byKey map[string][]string
	in    upstream.Input
	cand  *remedy.Candidate
}

// assessUpstream decides the upstream status of every container with
// active, affected image findings, stores it and opens the findings that
// were snoozed until an image that fixes them appears.
func (p *Pipeline) assessUpstream(ctx context.Context, ws []inventory.Workload, hosts []inventory.Host, fs []store.Finding, details map[string]match.Finding, ids map[string]identify.Result) error {
	us, ok := p.store.(upstreamStore)
	if !ok {
		return nil
	}
	checks, err := us.UpstreamChecks(ctx)
	if err != nil {
		return err
	}
	arch := map[string]string{}
	for _, h := range hosts {
		arch[h.ID] = h.Arch
	}
	byWorkload := map[string][]store.Finding{}
	for _, f := range fs {
		if status.Active(f.State) && f.MatchState == string(match.Affected) && details[f.ID].Image {
			byWorkload[f.WorkloadID] = append(byWorkload[f.WorkloadID], f)
		}
	}
	cat := p.cat.Current()
	var todo []*upstreamInput
	var images []store.ReleaseImage
	for _, w := range ws {
		c := w.Container
		if c == nil || w.RemovedAt != nil || len(byWorkload[w.ID]) == 0 {
			continue
		}
		u := &upstreamInput{w: w, byKey: map[string][]string{}}
		for _, f := range byWorkload[w.ID] {
			m := details[f.ID]
			u.findings = append(u.findings, m)
			k := m.AdvisoryID + "|" + m.Evidence.Package
			u.byKey[k] = append(u.byKey[k], f.ID)
		}
		platform := remedy.HostPlatform(arch[w.HostID])
		u.in = upstream.Input{Container: c, Platform: platform, Findings: u.findings, RegistryOn: p.registryOn()}
		if key, ok := upstream.KeyOf(c, platform); ok {
			if ck, ok := checks[key]; ok {
				u.in.Check = &ck
				if ck.Candidate != nil {
					if cand, err := upstream.DecodeCandidate(ck.Candidate); err == nil {
						u.cand = &cand
					} else {
						p.log.Warn("stored candidate image unreadable; it is read again", "repository", key.Repository, "err", err)
					}
				}
			}
		}
		if app, run, ok := releaseApp(cat, c, ids[w.ID]); ok {
			u.in.App, u.in.Running = app, run
			images = append(images, store.ReleaseImage{AppID: app.ID, Image: run.Repository})
		}
		todo = append(todo, u)
	}
	lines := map[store.ReleaseImage][][]byte{}
	if len(images) > 0 {
		if lines, err = us.ReleasePackagesOf(ctx, images); err != nil {
			return fmt.Errorf("release package lists: %w", err)
		}
	}
	// The advisories of every package the comparisons judge: those of the
	// findings and every checked package of a candidate, so that flaws the
	// candidate brings are found too.
	seen := map[string]bool{}
	var appIDs []string
	addPkg := func(p distro.Package) {
		if id := distro.SystemAppID(p.Ecosystem, p.Name); !seen[id] {
			seen[id] = true
			appIDs = append(appIDs, id)
		}
	}
	for _, u := range todo {
		if u.in.App != nil {
			u.in.Lines = decodeReleaseLines(lines[store.ReleaseImage{AppID: u.in.App.ID, Image: u.in.Running.Repository}], u.in.App.ID, u.in.Running.Repository)
		}
		for _, f := range u.findings {
			if eco, name, ok := cutPackage(f.Evidence.Package); ok {
				addPkg(distro.Package{Ecosystem: eco, Name: name})
			}
		}
		if u.cand != nil {
			for _, pkg := range candidatePackages(*u.cand) {
				addPkg(pkg)
			}
		}
		if l, ok := remedy.ReleaseLineFor(u.in.Lines, u.in.Platform); ok {
			for _, pkg := range candidatePackages(remedy.Candidate{Distro: l.Distro, Packages: l.Packages}) {
				addPkg(pkg)
			}
		}
	}
	recs, err := us.AdvisoriesFor(ctx, appIDs)
	if err != nil {
		return fmt.Errorf("advisories for upstream images: %w", err)
	}
	byApp := make(map[string][]match.Advisory, len(recs))
	for id, rs := range recs {
		_, name, _ := distro.ParseSystemAppID(id)
		byApp[id] = AdvisoriesFor(&catalog.App{ID: id, Name: name}, rs, p.Superseded)
	}
	advs := func(pkg distro.Package) []match.Advisory { return byApp[distro.SystemAppID(pkg.Ecosystem, pkg.Name)] }

	out := make(map[string]json.RawMessage, len(todo))
	var wake []string
	for _, u := range todo {
		u.in.Advisories = advs
		st := upstream.Evaluate(u.in)
		b, err := json.Marshal(st)
		if err != nil {
			return fmt.Errorf("encode upstream status: %w", err)
		}
		out[u.w.ID] = b
		if st.Actionable() {
			for _, f := range st.Fixed {
				wake = append(wake, u.byKey[f.AdvisoryID+"|"+f.Package]...)
			}
		}
	}
	if err := us.ReplaceUpstreamStatus(ctx, out, p.now()); err != nil {
		return err
	}
	if len(wake) > 0 {
		n, err := us.WakeUpstreamSnoozes(ctx, wake, p.now())
		if err != nil {
			return err
		}
		if n > 0 {
			p.log.Info("findings snoozed until a fixed image reopened", "count", n)
		}
	}
	return nil
}

// releaseApp is the app whose newest release the data package read for a
// container's image, and the release the container runs; ok is false when
// no release read applies.
func releaseApp(cat *catalog.Catalog, c *inventory.Container, id identify.Result) (*catalog.App, remedy.Running, bool) {
	if id.AppID == "" || !id.Confidence.Notifiable() {
		return nil, remedy.Running{}, false
	}
	app, ok := cat.App(id.AppID)
	if !ok {
		return nil, remedy.Running{}, false
	}
	ref, err := imageref.Parse(c.ImageRef)
	if err != nil || identify.ReadsAsDerived(app, ref.Repository) {
		return nil, remedy.Running{}, false
	}
	run := remedy.Running{Repository: ref.Repository, Tag: ref.Tag}
	if ref.Tag == "" || version.IsFloating(ref.Tag) {
		run.Tag = c.ResolvedTag
	}
	if id.Doubt() != "" {
		run.Tag = ""
	}
	return identify.AppForImage(app, ref.Repository), run, true
}

// decodeReleaseLines decodes the stored release lines of an app's image.
func decodeReleaseLines(raw [][]byte, appID, image string) []feed.ReleaseLine {
	out := make([]feed.ReleaseLine, 0, len(raw))
	for _, r := range raw {
		var l feed.ReleaseLine
		if json.Unmarshal(r, &l) != nil || l.AppID != appID || l.Image != image {
			continue
		}
		out = append(out, l)
	}
	return out
}

// candidatePackages are the checked packages of a candidate image.
func candidatePackages(c remedy.Candidate) []distro.Package {
	img := &inventory.Container{Distro: c.Distro, Packages: c.Packages}
	return append(identify.ImageSystemPackages(img), identify.ImageLanguagePackages(img)...)
}

// cutPackage splits a finding's evidence package ("Debian:12/openssl").
func cutPackage(s string) (eco, name string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return s[:i], s[i+1:], i > 0 && i < len(s)-1
		}
	}
	return "", "", false
}

func (p *Pipeline) registryOn() bool {
	return p.opts.RegistryChecks != nil && p.opts.RegistryChecks()
}

// statusStore reads the stored upstream status (for notifications).
type statusStore interface {
	UpstreamStatus(ctx context.Context) (map[string]json.RawMessage, error)
}

// upstreamStatuses reads the stored upstream status of each container; a
// store without it, or a failed read, gives none, and notifications then
// promise no image.
func (p *Pipeline) upstreamStatuses(ctx context.Context) map[string]upstream.Status {
	ss, ok := p.store.(statusStore)
	if !ok {
		return nil
	}
	raw, err := ss.UpstreamStatus(ctx)
	if err != nil {
		p.log.Warn("upstream status not read; notifications name no image", "err", err)
		return nil
	}
	out := make(map[string]upstream.Status, len(raw))
	for id, b := range raw {
		var st upstream.Status
		if err := json.Unmarshal(b, &st); err != nil {
			p.log.Warn("upstream status unreadable", "workload", id, "err", err)
			continue
		}
		out[id] = st
	}
	return out
}

// imageAction words what to do about one image finding from the upstream
// status of its container, and the tag of an image that fixes it.
func imageAction(st upstream.Status, m match.Finding) (action, update string) {
	switch {
	case st.Fixes(m.AdvisoryID, m.Evidence.Package) && st.Rebuilt:
		return fmt.Sprintf("pull the rebuilt image and recreate the container (it fixes %d of %d flaws in the image's packages)", len(st.Fixed), st.Total()), st.TargetTag
	case st.Fixes(m.AdvisoryID, m.Evidence.Package):
		return fmt.Sprintf("update the image to %s and recreate the container (it fixes %d of %d flaws in the image's packages)", st.TargetTag, len(st.Fixed), st.Total()), st.TargetTag
	case st.Kind == upstream.UpdateAvailable, st.Kind == upstream.UpdateNoEffect, st.Kind == upstream.NoUpstreamFix:
		return "no fixed image upstream yet: limit who can reach the container, or build an image with the package updates", ""
	}
	if st.Reason != "" {
		return "Varde cannot tell whether a fixed image exists: " + st.Reason, ""
	}
	return "", ""
}
