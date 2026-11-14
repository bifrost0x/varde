// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/auth"
)

// publicRegistries are the registries anyone can pull from. An image on
// another host (a registry of your own, a mirror in your network) is left
// out of the list of unrecognised images: its name says nothing to a
// catalog and is nobody else's business.
var publicRegistries = map[string]bool{
	"docker.io": true, "ghcr.io": true, "quay.io": true, "lscr.io": true, "gcr.io": true,
	"registry.k8s.io": true, "public.ecr.aws": true, "codeberg.org": true, "registry.gitlab.com": true,
	"mcr.microsoft.com": true,
}

// unrecognisedList is the text of the list: one image repository per line,
// sorted, each once, without tags, digests, container or host names.
func unrecognisedList(gaps []gap) (text string, listed, withheld int) {
	seen := map[string]bool{}
	var repos []string
	for _, g := range gaps {
		repo := g.Repository
		if repo == "" || seen[repo] {
			continue
		}
		seen[repo] = true
		host, _, _ := strings.Cut(repo, "/")
		if !publicRegistries[host] {
			withheld++
			continue
		}
		repos = append(repos, repo)
	}
	sort.Strings(repos)
	var b strings.Builder
	b.WriteString("# Images Varde does not recognise, by repository.\n")
	b.WriteString("# No versions, no container names, no hosts; images on registries of your own are left out.\n")
	b.WriteString("# Nothing is sent anywhere: this file is yours to read and, if you like, to attach to a catalog suggestion.\n")
	for _, r := range repos {
		b.WriteString(r)
		b.WriteByte('\n')
	}
	return b.String(), len(repos), withheld
}

// unrecognised serves the list of images that match no catalog entry, as
// a file the user may hand to the project. Varde itself sends it nowhere.
func (a *app) unrecognised(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	s, err := a.load(r.Context(), false)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	text, _, _ := unrecognisedList(a.coverageData(s).Unidentified)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="varde-unrecognised-images.txt"`)
	_, _ = w.Write([]byte(text))
}
