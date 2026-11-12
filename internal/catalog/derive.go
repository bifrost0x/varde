// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"regexp"
	"strings"
)

// OriginDerived marks an entry Varde made itself from an image's source
// label, for an app the catalog does not know yet.
const OriginDerived Origin = "derived"

// Bases of a derivation.
const (
	// BasisLabel: the image's own source label names the repository.
	BasisLabel = "label"
	// BasisGHCR: the image lives in the repository's namespace on GitHub's
	// registry.
	BasisGHCR = "ghcr"
	// BasisLists: public app store lists tie the image to the repository.
	BasisLists = "lists"
	// BasisIndex: the embedded first-party index ties the image to the
	// repository: the project or the registry states it (Evidence).
	BasisIndex = "index"
)

// Derivation says how Varde found a derived entry and whether that is
// enough to alert. The publisher's own statement (label, registry
// namespace) or two independent lists confirm it; one list alone is a
// report (ADR 0023, ADR 0038).
type Derivation struct {
	Basis string `json:"basis"`
	// Lists are the app store lists that state the pair.
	Lists []string `json:"lists,omitempty"`
	// Evidence are the kinds of first-party evidence of the embedded index
	// (readme, hub, ghcr), for BasisIndex.
	Evidence  []string `json:"evidence,omitempty"`
	Confirmed bool     `json:"confirmed"`
}

var (
	githubRepo   = regexp.MustCompile(`^github\.com/([a-z0-9-]{1,39})/([a-z0-9._-]{1,100})$`)
	githubSource = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})$`)
	idUnsafe     = regexp.MustCompile(`[^a-z0-9-]+`)
)

// Derive makes a provisional entry for an unknown app from the image's
// org.opencontainers.image.source label. Labels are inherited from base
// images, so a label alone could name the base image's project: the entry
// is made only when the image name matches the repository name
// ("ghcr.io/homarr-labs/homarr" and github.com/homarr-labs/homarr). The
// entry reads the repository's security advisories. The image is recorded
// as confirmed by its publisher's label (DerivationFor); other images that
// merely carry the same label are not.
func Derive(source, imageRepository string) (*App, bool) {
	m := githubSource.FindStringSubmatch(normaliseSource(source))
	if m == nil {
		return nil, false
	}
	owner, repo := strings.ToLower(m[1]), strings.ToLower(strings.TrimSuffix(m[2], ".git"))
	image := strings.ToLower(imageRepository[strings.LastIndexByte(imageRepository, '/')+1:])
	if image != repo && !strings.HasPrefix(image, repo+"-") && !strings.HasPrefix(repo, image+"-") {
		return nil, false
	}
	return &App{
		ID: derivedID(owner, repo), Name: m[2], Homepage: "https://github.com/" + m[1] + "/" + m[2],
		OCISource: []string{"https://github.com/" + owner + "/" + repo},
		Version:   VersionSpec{Scheme: "semver"},
		Advisories: Advisories{Coverage: CoveragePartial, GitHubRepos: []string{owner + "/" + repo},
			Notes: "Recognised automatically from the image's source label; not reviewed."},
		Origin:        OriginDerived,
		Derivation:    &Derivation{Basis: BasisLabel, Confirmed: true},
		DerivedImages: map[string]Derivation{imageRepository: {Basis: BasisLabel, Confirmed: true}},
	}, true
}

// derivedID is the ID of the entry derived for a GitHub repository.
func derivedID(owner, repo string) string {
	id := strings.Trim(idUnsafe.ReplaceAllString("gh-"+owner+"-"+repo, "-"), "-")
	if len(id) > 64 {
		id = strings.TrimRight(id[:64], "-")
	}
	return id
}

// DeriveFromLists makes a provisional entry for an image that public app
// store lists tie to a GitHub repository ("github.com/<owner>/<name>", lower
// case). The lists state the pair, so the image need not be named like the
// repository. The entry matches the image and reads the repository's
// security advisories.
func DeriveFromLists(repo, imageRepository string, lists []string, confirmed bool) (*App, bool) {
	return DeriveFor(repo, imageRepository, Derivation{Basis: BasisLists, Lists: lists, Confirmed: confirmed})
}

// DeriveFor makes a provisional entry for a GitHub repository
// ("github.com/<owner>/<name>", lower case) that matches one image, with
// how the image was tied to it.
func DeriveFor(repo, imageRepository string, d Derivation) (*App, bool) {
	m := githubRepo.FindStringSubmatch(repo)
	if m == nil || imageRepository == "" {
		return nil, false
	}
	note := "Recognised automatically through a table of images and their projects; not reviewed."
	switch d.Basis {
	case BasisGHCR:
		note = "Recognised automatically from the image's place on GitHub's registry; not reviewed."
	case BasisIndex:
		note = "Recognised automatically from what the project and the registry state; not reviewed."
	}
	app := &App{
		ID: derivedID(m[1], m[2]), Name: m[2], Homepage: "https://" + repo,
		OCISource:  []string{"https://" + repo},
		Version:    VersionSpec{Scheme: "semver"},
		Advisories: Advisories{Coverage: CoveragePartial, GitHubRepos: []string{m[1] + "/" + m[2]}, Notes: note},
		Origin:     OriginDerived,
		Derivation: &d,
	}
	app.AddDerivedImage(imageRepository, d)
	return app, true
}

// AddDerivedImage makes a derived entry match one more image repository
// (in its normalised form) and records how that image was tied to it.
// Reviewed entries are not changed.
func (a *App) AddDerivedImage(imageRepository string, d Derivation) {
	if a.Origin != OriginDerived {
		return
	}
	if a.DerivedImages == nil {
		a.DerivedImages = map[string]Derivation{}
	}
	a.DerivedImages[imageRepository] = d
	for _, img := range a.Images {
		if img.repo == imageRepository {
			return
		}
	}
	a.Images = append(a.Images, Image{Match: imageRepository, repo: imageRepository})
}

// RecordDerivedImage records how an image was tied to a derived entry
// without making the entry match the image by name (the image is found by
// its source label).
func (a *App) RecordDerivedImage(imageRepository string, d Derivation) {
	if a.Origin != OriginDerived {
		return
	}
	if a.DerivedImages == nil {
		a.DerivedImages = map[string]Derivation{}
	}
	a.DerivedImages[imageRepository] = d
}

// DerivationFor says how an image repository was tied to a derived entry;
// nil when the entry does not know the image (for example an image that
// only inherited the entry's source label from its base image). Only a
// confirmed derivation lets findings alert.
func (a *App) DerivationFor(imageRepository string) *Derivation {
	if d, ok := a.DerivedImages[imageRepository]; ok {
		return &d
	}
	return nil
}

// ByGitHubRepo returns the reviewed entry that reads the advisories of a
// GitHub repository ("owner/name", any case), if there is one.
func (c *Catalog) ByGitHubRepo(repo string) (*App, bool) {
	for _, a := range c.apps {
		if a.Origin == OriginDerived {
			continue
		}
		for _, r := range a.Advisories.GitHubRepos {
			if strings.EqualFold(r, repo) {
				return a, true
			}
		}
	}
	return nil, false
}

// WithDerived returns the catalog with the derived entries added. Entries
// whose ID or source the catalog already has are skipped: a reviewed entry
// always wins.
func (c *Catalog) WithDerived(derived []*App) (*Catalog, error) {
	apps := make(map[string]*App, len(c.apps)+len(derived))
	for id, a := range c.apps {
		apps[id] = a
	}
	// An ID, a source or an image belongs to the first entry that claims
	// it: a collision drops the later claim instead of failing the set,
	// which would cost every derived app.
	sources, images := map[string]bool{}, map[string]bool{}
	for _, d := range derived {
		if _, exists := apps[d.ID]; exists {
			continue
		}
		src := normaliseSource(d.OCISource[0])
		if _, known := c.ByOCISource(d.OCISource[0]); known || sources[src] {
			continue
		}
		kept := d.Images[:0:0]
		for _, img := range d.Images {
			if _, taken := c.byImage[img.repo]; taken || images[img.repo] {
				continue
			}
			images[img.repo] = true
			kept = append(kept, img)
		}
		if len(kept) != len(d.Images) {
			cp := *d
			cp.Images = kept
			d = &cp
		}
		sources[src] = true
		apps[d.ID] = d
	}
	return newCatalog(apps)
}

// SetDerived replaces the derived entries of the live catalog. The base set
// by Set stays; Set drops derived entries until the next SetDerived.
func (l *Live) SetDerived(derived []*App) error {
	base := l.base.Load()
	if base == nil {
		base = l.p.Load()
		l.base.Store(base)
	}
	c, err := base.WithDerived(derived)
	if err != nil {
		return err
	}
	l.p.Store(c)
	return nil
}
