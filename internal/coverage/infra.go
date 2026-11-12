// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
)

// Helper kinds shown next to containers that are not counted as gaps.
const (
	KindDatabase = "database or cache"
	KindProxy    = "Docker socket proxy"
	KindUpdater  = "update helper"
	KindVarde    = "Varde itself"
	KindUser     = "marked as not an app"
)

// helpers are well-known images that support apps rather than being one
// and have no catalog entry: listing them as "not in the catalog" buries
// the gaps that matter. The packages of their images are checked like those
// of every container. The databases with advisories of their own
// (PostgreSQL, Redis, Valkey, MariaDB, MySQL, MongoDB, Memcached) are
// catalog entries and count as apps. Keys are normalised repositories.
var helpers = map[string]string{
	"docker.io/bitnami/postgresql":            KindDatabase,
	"docker.io/bitnami/redis":                 KindDatabase,
	"docker.io/bitnami/mariadb":               KindDatabase,
	"docker.io/eqalpha/keydb":                 KindDatabase,
	"docker.io/pgvector/pgvector":             KindDatabase,
	"docker.io/tensorchord/pgvecto-rs":        KindDatabase,
	"ghcr.io/immich-app/postgres":             KindDatabase,
	"docker.io/tecnativa/docker-socket-proxy": KindProxy,
	"ghcr.io/tecnativa/docker-socket-proxy":   KindProxy,
	"lscr.io/linuxserver/socket-proxy":        KindProxy,
	"docker.io/wollomatic/socket-proxy":       KindProxy,
	"ghcr.io/wollomatic/socket-proxy":         KindProxy,
	"docker.io/containrrr/watchtower":         KindUpdater,
	"docker.io/nickfedor/watchtower":          KindUpdater,
	"ghcr.io/nicholas-fedor/watchtower":       KindUpdater,
	"docker.io/crazymax/diun":                 KindUpdater,
	"ghcr.io/crazy-max/diun":                  KindUpdater,
	"docker.io/willfarrell/autoheal":          KindUpdater,
	"docker.io/bifrost0x/varde":               KindVarde,
	"ghcr.io/bifrost0x/varde":                 KindVarde,
}

// Repository returns the normalised image repository of a container
// workload, empty for anything else.
func Repository(wl inventory.Workload) string {
	if wl.Container == nil {
		return ""
	}
	ref, err := imageref.Parse(wl.Container.ImageRef)
	if err != nil {
		return ""
	}
	return ref.Repository
}

// NotAnApp reports why a workload is left out of the coverage gaps: a known
// helper image, or one the user marked. Identified apps always count, so a
// catalog entry overrides both.
func NotAnApp(wl inventory.Workload, id identify.Result, marked map[string]bool) (string, bool) {
	if id.Confidence.Notifiable() {
		return "", false
	}
	repo := Repository(wl)
	if repo == "" {
		return "", false
	}
	if marked[repo] {
		return KindUser, true
	}
	kind, ok := helpers[repo]
	return kind, ok
}

// ImageLookup finds the GitHub repository ("github.com/<owner>/<name>")
// that public app store lists state for an image repository, the lists
// that state it, and whether that is confirmed (internal/applists).
type ImageLookup func(imageRepository string) (repo string, lists []string, confirmed bool, ok bool)

// DeriveApps makes provisional catalog entries for containers whose image
// the catalog does not know. Per image, in this order:
//
//  1. The image's source label, when it names the image's own repository
//     (catalog.Derive): the publisher's statement, confirmed.
//  2. The tables: the embedded first-party index and, when the uplink
//     feed delivers one, a second table. Confirmed with two
//     pieces of evidence (two kinds of first-party evidence, two lists, or
//     one of each), or when one agrees with the image's source label or
//     with its place on GitHub's registry. A source label that names
//     anything else overrules the tables.
//  3. "ghcr.io/<owner>/<repo>" as github.com/<owner>/<repo>: a guess, since
//     packages are often named differently from their repository; it is
//     never confirmed on its own.
//
// Whether findings may alert is recorded per image (App.DerivationFor), so
// an image one list reports stays unconfirmed beside a confirmed image of
// the same project. Helpers such as databases and proxies are left out.
// The result does not depend on the order of the workloads. The analysis
// calls it on every run, so a new app needs no catalog release, and an app
// known only through the lists goes away when they are switched off.
func DeriveApps(cat *catalog.Catalog, lookup ImageLookup, ws []inventory.Workload) []*catalog.App {
	return DeriveAppsWith(cat, Lookups{Lists: lookup}, ws)
}

// Lookups are the tables an image is looked up in. Index is the embedded
// first-party index (always there, no connection), Lists the app store
// table from the uplink feed (nil; no installation downloads lists). Their
// evidence adds up when they name the same repository.
type Lookups struct {
	Index ImageLookup
	Lists ImageLookup
}

// find looks an image up in both tables. When both know it and agree, the
// first-party evidence and the lists count together; when they disagree,
// the one with more behind it wins and a tie is no answer.
func (l Lookups) find(image string) (repo string, d catalog.Derivation, ok bool) {
	var ir, lr string
	var ie, ll []string
	var iok, lok bool
	if l.Index != nil {
		ir, ie, _, iok = l.Index(image)
	}
	if l.Lists != nil {
		lr, ll, _, lok = l.Lists(image)
	}
	switch {
	case iok && lok && ir != lr:
		switch {
		case len(ie) > len(ll):
			lok = false
		case len(ll) > len(ie):
			iok = false
		default:
			return "", catalog.Derivation{}, false
		}
	case !iok && !lok:
		return "", catalog.Derivation{}, false
	}
	switch {
	case iok && lok:
		return ir, catalog.Derivation{Basis: catalog.BasisIndex, Evidence: ie, Lists: ll, Confirmed: len(ie)+len(ll) >= 2}, true
	case iok:
		return ir, catalog.Derivation{Basis: catalog.BasisIndex, Evidence: ie, Confirmed: len(ie) >= 2}, true
	}
	return lr, catalog.Derivation{Basis: catalog.BasisLists, Lists: ll, Confirmed: len(ll) >= 2}, true
}

// DeriveAppsWith is DeriveApps with the embedded index beside the lists.
func DeriveAppsWith(cat *catalog.Catalog, lookups Lookups, ws []inventory.Workload) []*catalog.App {
	type candidate struct {
		image, label string
	}
	// One decision per image; an image with a source label on any of its
	// containers is decided with that label.
	byImage := map[string]candidate{}
	for _, w := range ws {
		c := w.Container
		if c == nil {
			continue
		}
		if _, helper := NotAnApp(w, identify.Result{}, nil); helper {
			continue
		}
		ref, err := imageref.Parse(c.ImageRef)
		if err != nil {
			continue
		}
		// An image a reviewed entry matches, or one the generator
		// checked, is decided; the images a generated entry took over
		// from its derived entry are derived again, as derived ones are.
		if a, ok := cat.ByImage(ref.Repository); ok &&
			(a.Origin.Reviewed() || (a.Origin == catalog.OriginGenerated && a.DerivationFor(ref.Repository) == nil)) {
			continue
		}
		label := strings.TrimSpace(c.ImageLabels[identify.LabelOCISource])
		if have, seen := byImage[ref.Repository]; !seen || (have.label == "" && label != "") || (label != "" && label < have.label) {
			byImage[ref.Repository] = candidate{image: ref.Repository, label: label}
		}
	}
	images := make([]string, 0, len(byImage))
	for image := range byImage {
		images = append(images, image)
	}
	sort.Strings(images)

	var out []*catalog.App
	byRepo := map[string]*catalog.App{} // "https://github.com/<owner>/<name>" -> entry
	idOf := map[string]string{}         // entry ID -> repository
	add := func(app *catalog.App, image string, byName bool) {
		repo := app.OCISource[0]
		d := *app.Derivation
		if have := byRepo[repo]; have != nil {
			// One project, several images: each keeps its own derivation.
			if byName {
				have.AddDerivedImage(image, d)
			} else {
				have.RecordDerivedImage(image, d)
			}
			return
		}
		if other, taken := idOf[app.ID]; taken && other != repo {
			// Two repositories whose names give the same ID: the first
			// keeps it, the second stays unrecognised.
			return
		}
		idOf[app.ID], byRepo[repo] = repo, app
		out = append(out, app)
	}
	for _, image := range images {
		c := byImage[image]
		if c.label != "" {
			// A generated entry stands in for the derived one: the entry
			// derived here joins it (Catalog.WithDerived).
			if a, ok := cat.ByOCISource(c.label); ok && a.Origin.Reviewed() {
				continue
			}
			if app, ok := catalog.Derive(c.label, image); ok {
				// The label ties this image repository to the project, so
				// the entry matches it by name too: another tag of the
				// same repository that lacks the label is the same app.
				app.AddDerivedImage(image, *app.Derivation)
				add(app, image, true)
				continue
			}
		}
		guess := ghcrRepository(image)
		if repo, d, ok := lookups.find(image); ok {
			if c.label != "" {
				// The publisher's label: it confirms a table that names the
				// same repository and overrules one that does not, whatever
				// else it names.
				if labelRepo, isRepo := labelRepository(c.label); !isRepo || labelRepo != repo {
					continue
				}
				d.Confirmed = true
			}
			if guess == repo {
				d.Confirmed = true
			}
			// A reviewed entry for the project wins; its image list decides
			// which images it stands for.
			if _, known := cat.ByGitHubRepo(strings.TrimPrefix(repo, "github.com/")); known {
				continue
			}
			if a, known := cat.ByOCISource("https://" + repo); known && a.Origin.Reviewed() {
				continue
			}
			if app, ok := catalog.DeriveFor(repo, image, d); ok {
				add(app, image, true)
			}
			continue
		}
		if c.label != "" || guess == "" {
			// A label that did not name the image's repository says the
			// image comes from elsewhere: no guess against it.
			continue
		}
		if _, known := cat.ByGitHubRepo(strings.TrimPrefix(guess, "github.com/")); known {
			continue
		}
		if a, known := cat.ByOCISource("https://" + guess); known && a.Origin.Reviewed() {
			continue
		}
		if app, ok := catalog.DeriveFor(guess, image, catalog.Derivation{Basis: catalog.BasisGHCR}); ok {
			add(app, image, true)
		}
	}
	return out
}

// labelRepository is "github.com/<owner>/<name>" for a source label that
// names a GitHub repository.
func labelRepository(label string) (string, bool) {
	s := strings.ToLower(label)
	// A link into the repository names the repository (the catalog reads
	// source labels the same way).
	for _, marker := range []string{"/tree/", "/commit/", "/blob/"} {
		if i := strings.Index(s, marker); i >= 0 {
			s = s[:i]
		}
	}
	rest, ok := strings.CutPrefix(strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git"), "https://github.com/")
	if !ok || strings.Count(rest, "/") != 1 {
		return "", false
	}
	return "github.com/" + rest, true
}

// ghcrRepository is "github.com/<owner>/<repo>" for an image
// "ghcr.io/<owner>/<repo>", empty for other images. GitHub's registry
// publishes packages in their owner's namespace, often but not always
// under the repository's name.
func ghcrRepository(repository string) string {
	rest, ok := strings.CutPrefix(repository, "ghcr.io/")
	if !ok || strings.Count(rest, "/") != 1 {
		return ""
	}
	return "github.com/" + rest
}
