// SPDX-License-Identifier: Apache-2.0

package match

import (
	"strings"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
)

// Advisories of a repository often name packages of other projects: a
// runner that lives beside the server, a library the report blames, a
// sibling image of the same author. Reviewed entries can list their own
// packages (advisories.packages); most entries, and every generated or
// derived one, cannot. For those, an affected package is left out when its
// own name proves that it is a different project, and an advisory that
// names nothing else is never more than unverified.
//
// Package names in repository advisories are free text, so the proof is
// narrow on purpose. Only two forms name a project precisely enough:
//
//   - a module path ("gitea.com/gitea/runner", "golang.org/x/oauth2/jws"),
//   - an owner/name reference ("louislam/dockge").
//
// Everything else ("redis-server", "Home Assistant Core", a file name, a
// typo of the app's name) may well be the app and stays.

// identity is what an app is known by, for the comparison with the package
// names of advisories.
type identity struct {
	// names are normalised words the app goes by: its id, aliases and
	// name, its repositories, images, packages and advisory packages.
	names []string
	// roots are lowercase references that are the app itself or a part of
	// it when a package name equals one or lies below one.
	roots []string
}

// forges host repositories as host/owner/repository, so the third segment
// of a module path names the project there. Elsewhere (vanity import paths,
// registries) any segment may.
var forges = map[string]bool{
	"github.com": true, "gitlab.com": true, "gitea.com": true,
	"codeberg.org": true, "bitbucket.org": true,
}

func newIdentity(app *catalog.App) *identity {
	id := &identity{}
	name := func(s string) {
		if n := normaliseName(s); n != "" {
			id.names = append(id.names, n)
		}
	}
	root := func(s string) {
		s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "/"))
		if s == "" {
			return
		}
		id.roots = append(id.roots, s)
		name(lastSegment(s))
	}
	name(app.ID)
	name(app.Name)
	for _, a := range app.Aliases {
		name(a)
	}
	for _, r := range app.Advisories.GitHubRepos {
		root(r)
		root("github.com/" + r)
	}
	for _, src := range app.OCISource {
		src = strings.TrimSuffix(strings.TrimSpace(src), ".git")
		if i := strings.Index(src, "://"); i >= 0 {
			src = src[i+3:]
		}
		root(src)
		if _, rest, ok := strings.Cut(src, "/"); ok {
			root(rest)
		}
	}
	for _, img := range app.Images {
		root(img.Match)
	}
	for _, p := range app.Advisories.OSVPackages {
		root(p.Name)
	}
	for _, p := range app.Packages {
		name(p.Name)
	}
	return id
}

// foreign reports whether the package name proves a different project.
func (id *identity) foreign(pkg string) bool {
	pkg = strings.ToLower(strings.TrimSpace(pkg))
	if pkg == "" || strings.ContainsAny(pkg, " \t,()") {
		return false // unnamed or free text
	}
	for _, r := range id.roots {
		if pkg == r || strings.HasPrefix(pkg, r+"/") {
			return false
		}
	}
	segs := strings.Split(strings.Trim(pkg, "/"), "/")
	for len(segs) > 1 && isMajorSuffix(segs[len(segs)-1]) {
		segs = segs[:len(segs)-1]
	}
	switch {
	case len(segs) >= 2 && strings.Contains(segs[0], ".") && !strings.HasPrefix(segs[0], "@"):
		// A module path. On a forge the repository names the project,
		// its owner does not: the owner of a runner is often the
		// project it runs for.
		if forges[segs[0]] {
			if len(segs) < 3 {
				return false // an owner alone, not a project
			}
			return !id.akin(segs[2])
		}
		for _, s := range segs[1:] {
			if id.akin(s) {
				return false
			}
		}
		for _, label := range strings.Split(segs[0], ".") {
			if id.akin(label) {
				return false
			}
		}
		return true
	case len(segs) == 2:
		// owner/name as people write it: either part may carry the
		// project's name ("@actual-app/sync-server", "pi-hole/FTL").
		// An owner counts only when it holds a whole name of the app:
		// the author of the app is the author of other things too.
		return !id.within(segs[0]) && !id.akin(segs[1])
	}
	return false
}

// akin reports whether a word and one of the app's names are the same or
// one contains the other. Short words prove nothing ("go", "ssh", "web").
func (id *identity) akin(word string) bool {
	w := normaliseName(word)
	if w == "" {
		return false
	}
	for _, n := range id.names {
		if w == n {
			return true
		}
		short, long := w, n
		if len(short) > len(long) {
			short, long = long, short
		}
		if len(short) >= 4 && strings.Contains(long, short) {
			return true
		}
	}
	return false
}

// within reports whether the word holds one of the app's names whole.
func (id *identity) within(word string) bool {
	w := normaliseName(word)
	for _, n := range id.names {
		if len(n) >= 4 && strings.Contains(w, n) {
			return true
		}
	}
	return false
}

// ownEntries leaves out the affected packages whose names prove another
// project, when the advisory also names the app or a package that may be
// it. When every package is another project's, all of them stay and other
// names the first one: a renamed project keeps publishing under its old
// module path ("github.com/docker/docker" for Moby), so such an advisory is
// not dropped, it is doubted.
func ownEntries(app *catalog.App, entries []advisory.Affected) (own []advisory.Affected, other string) {
	var id *identity
	var kept []advisory.Affected
	dropped := false
	for i, e := range entries {
		// Only a name with a slash can be a module path or an
		// owner/name reference; the app's identity is not needed for
		// the others, which are the many.
		if strings.Contains(e.Package.Name, "/") {
			if id == nil {
				id = newIdentity(app)
			}
			if id.foreign(e.Package.Name) {
				if !dropped {
					kept = append(kept, entries[:i]...)
					dropped = true
					other, _ = describeEntry(e)
				}
				continue
			}
		}
		if dropped {
			kept = append(kept, e)
		}
	}
	switch {
	case !dropped:
		return entries, ""
	case len(kept) == 0:
		return entries, other
	}
	return kept, ""
}

// normaliseName lowercases and keeps letters and digits only, so
// "Uptime Kuma", "uptime-kuma" and "uptime_kuma" compare equal.
func normaliseName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func lastSegment(s string) string {
	segs := strings.Split(s, "/")
	for len(segs) > 1 && isMajorSuffix(segs[len(segs)-1]) {
		segs = segs[:len(segs)-1]
	}
	return segs[len(segs)-1]
}

// isMajorSuffix reports a Go major version suffix ("v2", "v11").
func isMajorSuffix(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
