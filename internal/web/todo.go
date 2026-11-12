// SPDX-License-Identifier: Apache-2.0

package web

import (
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
)

// todoGroup is one thing to do on one system: pull a newer image of a
// container, install the package updates of a host, or update an app. It
// is how people fix findings, so it is how the findings page groups them;
// the app and package groups are its details.
type todoGroup struct {
	// Key is the workload or host the group belongs to.
	Key string
	// Kind is image, packages or app.
	Kind string
	// Name is the container, host or app; Where says where it runs.
	Name, Where string
	// Action is what to do, Note what it fixes when that needs saying,
	// Command an example of how.
	Action, Note, Command string
	Priority              string
	// NewPriority is the highest priority among its new confirmed
	// findings: what makes the update urgent now, not what was
	// acknowledged.
	NewPriority string
	KEV         bool
	PathClass   string
	Count       int
	Urgent, New int
	Groups      []findingGroup
}

// todoGroups groups findings by what fixes them on which system.
func (a *app) todoGroups(s *snapshot, fs []store.Finding) []todoGroup {
	hostNames := map[string]string{}
	for _, h := range s.hosts {
		hostNames[h.ID] = h.Name
	}
	index := map[string]int{}
	var out []todoGroup
	var members [][]store.Finding
	for _, f := range fs {
		w := s.byID[f.WorkloadID]
		key, kind := "w:"+f.WorkloadID, "app"
		switch {
		case identify.IsSystem(w):
			key, kind = "h:"+w.HostID, "packages"
		case w.Container != nil:
			kind = "image"
		}
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			g := todoGroup{Key: key, Kind: kind}
			switch kind {
			case "packages":
				g.Name, g.Where = hostNames[w.HostID], "system packages"
			case "image":
				g.Name, g.Where = w.Name, "container on "+hostNames[w.HostID]
				if w.Container != nil && w.Container.ImageRef != "" {
					g.Where += " · " + w.Container.ImageRef
				}
			default:
				g.Name, g.Where = a.appName(f.AppID), w.Name+" on "+hostNames[w.HostID]
			}
			if g.Name == "" {
				g.Name = w.Name
			}
			out = append(out, g)
			members = append(members, nil)
		}
		members[i] = append(members[i], f)
	}
	for i := range out {
		g := &out[i]
		g.Groups = a.groupFindings(s, members[i])
		seen := map[string]bool{}
		for _, f := range members[i] {
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			g.Count++
			if f.State == store.StateOpen {
				g.New++
				if f.MatchState != string(match.Unverified) && f.Priority != "" && (g.NewPriority == "" || priorityRank[f.Priority] < priorityRank[g.NewPriority]) {
					g.NewPriority = f.Priority
				}
			}
			if f.Priority == "P1" && f.MatchState != string(match.Unverified) {
				g.Urgent++
			}
		}
		for _, fg := range g.Groups {
			if fg.Priority != "" && (g.Priority == "" || priorityRank[fg.Priority] < priorityRank[g.Priority]) {
				g.Priority = fg.Priority
			}
			g.KEV = g.KEV || fg.KEV
			if fg.PathClass != "" && (g.PathClass == "" || pathRank[fg.PathClass] < pathRank[g.PathClass]) {
				g.PathClass = fg.PathClass
			}
		}
		g.Action, g.Note, g.Command = todoAction(*g, members[i])
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if priorityRank[a.Priority] != priorityRank[b.Priority] {
			return priorityRank[a.Priority] < priorityRank[b.Priority]
		}
		if a.Urgent != b.Urgent {
			return a.Urgent > b.Urgent
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Name < b.Name
	})
	return out
}

// todoAction says what fixes a group's findings, what needs saying about
// it, and how.
func todoAction(g todoGroup, fs []store.Finding) (action, note, command string) {
	switch g.Kind {
	case "image":
		for _, fg := range g.Groups {
			if !fg.Image && fg.Target != nil && fg.Target.Version != "" {
				note = "The image should bring " + fg.AppName + " " + fg.Target.Version + " or later, which fixes " + plural(fg.Target.Fixes, "finding") + " of the app itself; the rest are packages inside the image."
				break
			}
		}
		return "Pull a newer image and recreate the container", note, "docker compose pull && docker compose up -d"
	case "packages":
		eco := ""
		for _, f := range fs {
			if e, _, ok := distro.ParseSystemAppID(f.AppID); ok {
				eco = e
				break
			}
		}
		return "Install the package updates", "", upgradeCommand(eco)
	}
	for _, fg := range g.Groups {
		if fg.Target != nil && fg.Target.Version != "" {
			return "Update to " + fg.Target.Version + " or later", "", ""
		}
	}
	return "No fixed version yet: see the advisories", "", ""
}

// upgradeCommand is how a distribution installs its updates.
func upgradeCommand(ecosystem string) string {
	name, _, _ := strings.Cut(ecosystem, ":")
	switch strings.ToLower(name) {
	case "debian", "ubuntu", "raspbian":
		return "sudo apt update && sudo apt upgrade"
	case "alpine":
		return "apk upgrade"
	case "almalinux", "rocky linux", "red hat", "centos", "fedora":
		return "sudo dnf upgrade"
	case "opensuse", "suse", "opensuse-leap", "sles":
		return "sudo zypper update"
	}
	return ""
}
