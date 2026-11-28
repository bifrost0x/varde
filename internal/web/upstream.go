// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/remedy"
	"github.com/bifrost0x/varde/internal/status"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/upstream"
)

// loadUpstream reads the upstream status of each container the last
// analysis decided. A status that cannot be read is left out: the card
// then says that Varde has not compared the image, never that an update
// exists.
func (a *app) loadUpstream(ctx context.Context) map[string]upstream.Status {
	raw, err := a.d.Store.UpstreamStatus(ctx)
	if err != nil {
		a.d.Log.Warn("upstream status not read", "err", err)
		return nil
	}
	out := make(map[string]upstream.Status, len(raw))
	for id, b := range raw {
		var st upstream.Status
		if err := json.Unmarshal(b, &st); err != nil {
			a.d.Log.Warn("upstream status unreadable", "workload", id, "err", err)
			continue
		}
		out[id] = st
	}
	return out
}

// upstreamOf is the upstream status of a container; nil when the analysis
// decided none yet.
func (s *snapshot) upstreamOf(id string) *upstream.Status {
	st, ok := s.upstream[id]
	if !ok {
		return nil
	}
	return &st
}

// workloadOf is the workload of a card key, nil for other cards.
func workloadOf(s *snapshot, key string) *inventory.Workload {
	if w, ok := s.byID[key]; ok {
		return &w
	}
	return nil
}

// imagePlan words the one thing to do about the findings in a container
// image's packages, from what Varde knows about a newer image: an update
// only for an image known to fix at least one of them.
func (a *app) imagePlan(c *appCard, wl inventory.Workload, fs []store.Finding, st *upstream.Status, image int) {
	c.Compose = remedy.ComposeOf(wl.Container)
	defer c.fitCommand()
	inImage := plural(image, "flaw") + " in packages inside the image"
	// What the newer image fixes of the flaws the card lists: the status
	// also judged snoozed ones, which the card leaves out.
	fixed := fixedOpen(st, fs)
	switch {
	case st != nil && st.Actionable() && fixed == 0:
		c.Action = "No fixed image for the open flaws yet"
		c.Fixes = "the newer image " + st.TargetTag + " fixes none of the " + inImage + " that are not snoozed"
		c.Mitigation = mitigationOf(c, wl, fs, st)
	case st != nil && st.Actionable():
		c.Fixes = "fixes " + strconv.Itoa(fixed) + " of " + plural(image, "flaw") + " in packages inside the image"
		switch {
		case pinned(wl.Container.ImageRef) && st.TargetDigest != "":
			// A digest pin keeps the old image however often it is
			// pulled: the pin itself has to change.
			c.Action = "Update the image's digest pin"
			if !st.Rebuilt {
				c.Action = "Update to " + st.TargetTag
			}
			c.Line, c.Verified = "image: "+withTag(wl.Container.ImageRef, st.TargetTag)+"@"+st.TargetDigest, true
		case st.Rebuilt:
			c.Action = "Pull the rebuilt image and recreate the container"
		default:
			c.Action = "Update to " + st.TargetTag
			c.Line, c.Verified = "image: "+withTag(wl.Container.ImageRef, st.TargetTag), true
		}
		if n := len(st.Introduced); n > 0 {
			c.Introduced = "introduces " + plural(n, "flaw") + " the running image does not have"
		}
		if rest := image - fixed; rest > 0 {
			c.Rest = plural(rest, "flaw") + " stay until a later image fixes them"
		}
		if c.Compose != nil {
			c.Command = c.Compose.Pull()
		}
	case st != nil && st.Kind == upstream.UpdateNoEffect:
		c.Action = "No fixed image upstream yet"
		c.Fixes = "the newer image " + st.TargetTag + " fixes none of the " + inImage
		c.Mitigation = mitigationOf(c, wl, fs, st)
	case st != nil && st.Kind == upstream.NoUpstreamFix:
		c.Action = "No fixed image upstream yet"
		c.Fixes = inImage + "; no newer image of this tag exists"
		c.Mitigation = mitigationOf(c, wl, fs, st)
	case st != nil && st.Reason == upstream.ReasonLocal:
		// Nobody publishes this image: whoever builds it fixes it.
		c.Action = "Rebuild the image"
		c.Fixes = inImage + "; it was built on this host, so a rebuild with current packages fixes them"
		c.Mitigation = mitigationOf(c, wl, fs, st)
		if m := c.Mitigation; m != nil && m.Rebuild != "" {
			c.Command = m.Rebuild
		}
	default:
		c.Action = "Varde cannot tell whether a fixed image exists"
		reason := "the image has not been compared yet"
		if st != nil && st.Reason != "" {
			reason = st.Reason
		}
		c.Fixes = inImage + ": " + reason
		c.Mitigation = mitigationOf(c, wl, fs, st)
	}
}

// UpstreamText says in one line what Varde knows about a newer image of
// the card's container, and where that comes from.
func (c appCard) UpstreamText() string {
	st := c.Upstream
	if st == nil {
		return ""
	}
	var text string
	switch st.Kind {
	case upstream.UpdateAvailable:
		text = st.TargetTag + " fixes " + strconv.Itoa(len(st.Fixed)) + " of " + plural(st.Total(), "flaw") + " in the image's packages"
		if st.Rebuilt {
			text = "the tag " + st.TargetTag + " points to a rebuilt image that fixes " + strconv.Itoa(len(st.Fixed)) + " of " + plural(st.Total(), "flaw")
		}
		if n := len(st.Introduced); n > 0 {
			text += " and introduces " + plural(n, "flaw")
		}
	case upstream.UpdateNoEffect:
		text = st.TargetTag + " exists but fixes none of the flaws in the image's packages"
	case upstream.NoUpstreamFix:
		text = "none: the running image is the newest of its tag"
	default:
		return "unknown: " + st.Reason
	}
	switch st.Source {
	case upstream.SourceRegistry:
		text += " (registry, " + st.Checked.Format("2 Jan 15:04") + ")"
	case upstream.SourceDataPackage:
		text += " (data package, read " + st.Checked.Format("2 Jan") + ")"
	}
	return text
}

// pinned reports whether an image reference names a digest besides its tag
// ("app:1.2@sha256:..."): pulling it again never changes the image.
func pinned(ref string) bool { return strings.Contains(ref, "@") }

// withTag is an image reference with another tag ("nginx:1.27" and
// "1.28" give "nginx:1.28").
func withTag(ref, tag string) string {
	name, _, _ := strings.Cut(ref, "@")
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		name = name[:i]
	}
	return name + ":" + tag
}

// mitigation is what to do about urgent flaws while no update fixes them.
type mitigation struct {
	// Exposed is set when the container is reachable from outside its
	// host: limiting that is the first step.
	Exposed bool
	// Distro names the image's distribution, Dockerfile a derived image
	// that installs its package updates; empty when Varde does not know
	// how the distribution upgrades.
	Distro, Dockerfile string
	// Local is set for an image without a registry digest: built from a
	// Dockerfile on the host, so no maker will publish a fixed image.
	// Rebuild is the command that builds it again, when the container is a
	// Compose service.
	Local   bool
	Rebuild string
	// Snooze is set when open findings can be snoozed until a fixed image
	// appears.
	Snooze bool
	// Recheck says how Varde notices a fixed image.
	Recheck string
}

// mitigationOf is the guidance of a card without an update that fixes it.
func mitigationOf(c *appCard, wl inventory.Workload, fs []store.Finding, st *upstream.Status) *mitigation {
	m := &mitigation{Exposed: c.Exposure == "public" || c.Exposure == "lan"}
	eco := ""
	for _, f := range fs {
		if f.MatchState != string(match.Affected) || !status.Active(f.State) {
			continue
		}
		var d match.Finding
		if json.Unmarshal(f.Detail, &d) != nil || !d.Image {
			continue
		}
		if f.State == store.StateOpen || f.State == store.StateAcknowledged {
			m.Snooze = true
		}
		if e, _, ok := strings.Cut(d.Evidence.Package, "/"); ok && eco == "" {
			eco = e
		}
	}
	if wl.Container != nil {
		user := ""
		if wl.Container.Runtime != nil {
			user = wl.Container.Runtime.User
		}
		m.Distro, m.Dockerfile = derivedImage(wl.Container.ImageRef, eco, user)
	}
	if st != nil && st.Reason == upstream.ReasonLocal {
		m.Local, m.Snooze = true, false
		if c := remedy.ComposeOf(wl.Container); c != nil && c.Portainer == "" {
			m.Rebuild = c.Rebuild()
		}
		m.Recheck = "Varde reads the packages of the rebuilt image when the container runs it, and clears what the rebuild fixed."
		return m
	}
	switch {
	case st != nil && st.Source == upstream.SourceRegistry:
		m.Recheck = "Varde asks the registry again by itself and moves this card to \"Update now\" once an image fixes these flaws."
	case st != nil && st.Source == upstream.SourceDataPackage:
		m.Recheck = "Varde compares again with every data package and moves this card to \"Update now\" once a release fixes these flaws."
	default:
		m.Recheck = "Switch on registry checks under Settings so that Varde notices a fixed image by itself."
	}
	return m
}

// derivedImage is a Dockerfile that builds the running image again with
// its distribution's package updates, for the distributions whose upgrade
// command Varde knows. user is the user the container runs as; the image
// switches back to it after the upgrade.
func derivedImage(ref, ecosystem, user string) (distro, dockerfile string) {
	name, _, _ := strings.Cut(ecosystem, ":")
	var run string
	switch strings.ToLower(name) {
	case "alpine":
		distro, run = "Alpine", "apk upgrade --no-cache"
	case "debian", "ubuntu", "raspbian":
		distro, run = name, "apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*"
	case "almalinux", "rocky linux", "red hat", "centos", "fedora", "amazon linux":
		distro, run = name, "(dnf -y upgrade || microdnf -y upgrade) && (dnf clean all || microdnf clean all)"
	default:
		return "", ""
	}
	var b strings.Builder
	b.WriteString("FROM " + ref + "\n")
	b.WriteString("USER root\n")
	b.WriteString("RUN " + run + "\n")
	if user != "" && user != "root" && user != "0" && user != "0:0" {
		b.WriteString("USER " + user + "\n")
	}
	return distro, b.String()
}

// snoozeUpstream snoozes the open findings in a container image's
// packages until an image that fixes them appears (at most
// store.MaxUpstreamSnooze).
func (a *app) snoozeUpstream(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	id := r.PathValue("id")
	s, err := a.load(ctx, false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	wl, ok := s.byID[id]
	if !ok || wl.Container == nil || identify.IsSystem(wl) {
		a.renderError(w, r, cur, http.StatusNotFound, "App not found", "It may have been removed.")
		return
	}
	st := s.upstreamOf(id)
	var ids []string
	for _, f := range s.findings {
		if f.WorkloadID != id || f.MatchState != string(match.Affected) || (f.State != store.StateOpen && f.State != store.StateAcknowledged) {
			continue
		}
		var m match.Finding
		if json.Unmarshal(f.Detail, &m) != nil || !m.Image {
			continue
		}
		// What a known image fixes is to be updated, not snoozed.
		if st != nil && st.Fixes(m.AdvisoryID, m.Evidence.Package) {
			continue
		}
		ids = append(ids, f.ID)
	}
	n, err := a.d.Store.SnoozeUntilUpstream(ctx, id, ids, a.d.Now())
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	a.audit(r, cur, "finding.snooze-upstream", id, strconv.Itoa(n)+" findings")
	a.d.Analyze(ctx)
	http.Redirect(w, r, "/apps/"+url.PathEscape(id)+"?ok=snoozed-upstream", http.StatusSeeOther) //nolint:gosec // local path only
}

// wakeApp reopens every snoozed finding of an app: the user takes back a
// snooze, which puts the app among the updates again.
func (a *app) wakeApp(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	id := r.PathValue("id")
	s, err := a.load(ctx, false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	if wl, ok := s.byID[id]; !ok || identify.IsSystem(wl) {
		a.renderError(w, r, cur, http.StatusNotFound, "App not found", "It may have been removed.")
		return
	}
	n := 0
	for _, f := range s.findings {
		if f.WorkloadID != id || f.State != store.StateSnoozed {
			continue
		}
		if err := a.d.Store.Reopen(ctx, f.ID, a.d.Now()); err != nil {
			a.fail(w, r, cur, err)
			return
		}
		n++
	}
	a.audit(r, cur, "finding.wake", id, strconv.Itoa(n)+" findings")
	a.d.Analyze(ctx)
	http.Redirect(w, r, "/apps/"+url.PathEscape(id)+"?ok=woken", http.StatusSeeOther) //nolint:gosec // local path only
}

// fixedOpen counts the card's open, confirmed image flaws the upstream
// status names as fixed by the newer image.
func fixedOpen(st *upstream.Status, fs []store.Finding) int {
	if st == nil {
		return 0
	}
	n := 0
	for _, f := range fs {
		if !actionable(f.State) || f.MatchState != string(match.Affected) {
			continue
		}
		var m match.Finding
		if json.Unmarshal(f.Detail, &m) != nil || !m.Image {
			continue
		}
		if st.Fixes(m.AdvisoryID, m.Evidence.Package) {
			n++
		}
	}
	return n
}
