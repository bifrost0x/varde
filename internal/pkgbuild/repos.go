// SPDX-License-Identifier: Apache-2.0

// Package pkgbuild builds the daily data package (ADR 0039): it collects
// the published security advisories of every repository the catalog and
// the first-party index know, the KEV list and EPSS scores, checks the
// result against the package published before, and hands a snapshot to
// the feed writer. It runs in the project's build, never in an
// installation: the server does not import it.
package pkgbuild

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/applists"
	"github.com/bifrost0x/varde/internal/catalog"
)

// Repo is one GitHub repository whose advisories go into the package.
type Repo struct {
	// Name is "owner/name" in lower case.
	Name string
	// App is the derived entry the advisories are collected under; its ID
	// is the one an installation gives the app it derives for the
	// repository.
	App *catalog.App
	// CatalogIDs are the reviewed catalog apps that name the repository;
	// the package repeats the advisories under each.
	CatalogIDs []string
	// Complete is set when a catalog app that names the repository has
	// coverage full: its advisories are complete, and its release notes
	// are not read (ADR 0044).
	Complete bool
}

// Repos lists every GitHub repository of a catalog app or an index row,
// once, sorted by name. It fails on a repository name it cannot use and on
// two repositories that derive the same ID ("a-b/c" and "a/b-c"): their
// advisories could not be told apart in the package.
func Repos(cat *catalog.Catalog, index *applists.Table) ([]Repo, error) {
	byName := map[string]*Repo{}
	byID := map[string]string{}
	add := func(name string) (*Repo, error) {
		name = strings.ToLower(name)
		if r, ok := byName[name]; ok {
			return r, nil
		}
		// The image only makes the derived entry complete; the builder
		// never matches images.
		app, ok := catalog.DeriveFor("github.com/"+name, "ghcr.io/"+name, catalog.Derivation{Basis: catalog.BasisIndex})
		if !ok {
			return nil, fmt.Errorf("%q is not a GitHub repository the builder can ask about", name)
		}
		if other, taken := byID[app.ID]; taken {
			return nil, fmt.Errorf("the repositories %s and %s both derive the ID %s; one of them has to leave the index or get a catalog entry of its own design", other, name, app.ID)
		}
		byID[app.ID] = name
		r := &Repo{Name: name, App: app}
		byName[name] = r
		return r, nil
	}
	for _, app := range cat.Apps() {
		for _, name := range app.Advisories.GitHubRepos {
			r, err := add(name)
			if err != nil {
				return nil, fmt.Errorf("catalog entry %s: %w", app.ID, err)
			}
			r.CatalogIDs = append(r.CatalogIDs, app.ID)
			if app.Advisories.Coverage == catalog.CoverageFull {
				r.Complete = true
			}
			// A reviewed entry names a repository that exists: for it a
			// 404 is a failure, not "no advisories" as for a derived one.
			r.App.Origin = catalog.OriginBuiltin
		}
	}
	for _, e := range index.Entries() {
		if _, err := add(strings.TrimPrefix(e.Repo, "github.com/")); err != nil {
			return nil, fmt.Errorf("index: %w", err)
		}
	}
	out := make([]Repo, 0, len(byName))
	for _, r := range byName {
		sort.Strings(r.CatalogIDs)
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
