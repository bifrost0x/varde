// SPDX-License-Identifier: Apache-2.0

package indexbuild

import (
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/applists"
)

// Kinds of evidence. Each is a statement of the project or the registry,
// never of a list or a search result.
const (
	// KindReadme: the repository's README or root Compose file names the
	// image as something to run.
	KindReadme = "readme"
	// KindHub: the image's Docker Hub description links the repository.
	KindHub = "hub"
	// KindGHCR: the image is in the repository owner's namespace on
	// GitHub's registry. Packages are often named differently from their
	// repository, so this alone says nothing about the name.
	KindGHCR = "ghcr"
)

// Evidence is one first-party statement that ties an image to a repository.
type Evidence struct {
	Image string // normalised image repository
	Repo  string // "github.com/<owner>/<name>", lower case
	Kind  string
}

// Build reduces evidence to the index table. Two kinds of evidence confirm
// a row, one is a report. The rules keep what a project says about other
// projects' images out:
//
//   - The registry namespace alone is not kept.
//   - The namespace and the README together are two statements only for an
//     image named like the repository; for a differently named image in
//     the same namespace (a sidecar of a Compose file) they are one, and
//     the row is a report.
//   - The README alone counts only for an image in the owner's namespace.
//     Compose files name what a project runs beside itself, companion
//     projects name the image they extend, forks copy a README: with a
//     foreign owner the image's own page has to link the project.
//
// An image several repositories claim goes to the one with the most
// evidence and is dropped on a tie. The second result names the dropped
// images with the reason. In the table the kinds of evidence take the
// place of list names (applists.Entry.Lists).
func Build(ev []Evidence) (*applists.Table, map[string]string) {
	// image -> repository -> kinds
	byImage := map[string]map[string]map[string]bool{}
	for _, e := range ev {
		repos := byImage[e.Image]
		if repos == nil {
			repos = map[string]map[string]bool{}
			byImage[e.Image] = repos
		}
		if repos[e.Repo] == nil {
			repos[e.Repo] = map[string]bool{}
		}
		repos[e.Repo][e.Kind] = true
	}
	dropped := map[string]string{}
	var lines []string
	for image, repos := range byImage {
		if applists.IsHelper(image) {
			dropped[image] = "base or helper image"
			continue
		}
		best, bestN, tie := "", 0, false
		foreign := false
		for repo, kinds := range repos {
			if len(kinds) == 1 && kinds[KindGHCR] {
				continue
			}
			if kinds[KindGHCR] && kinds[KindReadme] && len(kinds) == 2 && !applists.NamedLike(image, repo) {
				// One statement, not two: the README names an image that
				// merely sits in the owner's namespace.
				kinds = map[string]bool{KindReadme: true}
				repos[repo] = kinds
			}
			if len(kinds) == 1 && kinds[KindReadme] && !applists.OwnedBy(image, repo) {
				// A README or Compose file also names other projects'
				// images.
				foreign = true
				continue
			}
			switch n := len(kinds); {
			case n > bestN:
				best, bestN, tie = repo, n, false
			case n == bestN:
				tie = true
			}
		}
		switch {
		case best == "" && foreign:
			dropped[image] = "named by another project only"
			continue
		case best == "":
			dropped[image] = "registry namespace alone"
			continue
		case tie:
			dropped[image] = "several repositories, equal evidence"
			continue
		}
		kinds := make([]string, 0, bestN)
		for k := range repos[best] {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		lines = append(lines, image+"\t"+best+"\t"+strings.Join(kinds, ","))
	}
	sort.Strings(lines)
	text := ""
	if len(lines) > 0 {
		text = strings.Join(lines, "\n") + "\n"
	}
	t, err := applists.Unmarshal([]byte(text))
	if err != nil {
		// Every field was normalised on the way in; a row the table refuses
		// is a defect of this package.
		panic("indexbuild: built table is not valid: " + err.Error())
	}
	return t, dropped
}
