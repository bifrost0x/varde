// SPDX-License-Identifier: Apache-2.0

// Package catalog loads, validates and indexes the app catalog.
package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"go.yaml.in/yaml/v3"

	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/version"
)

const (
	maxEntryBytes = 64 << 10
	maxEntries    = 2000
	// maxGenerated bounds the generated entries, which come in a blob of
	// their own beside the reviewed catalog.
	maxGenerated = 20000
	maxRegexLen  = 256
)

// Origin records where an entry came from.
type Origin string

// Origins.
const (
	OriginBuiltin Origin = "builtin"
	OriginLocal   Origin = "local"
	// OriginFeed marks entries from the signed central feed.
	OriginFeed Origin = "feed"
	// OriginGenerated marks entries the package builder made and checked
	// by machine, not reviewed by a person. They rank between the reviewed
	// entries (feed, built-in, local) and the ones Varde derives itself.
	OriginGenerated Origin = "generated"
)

// Coverage levels (ADR 0017).
const (
	CoverageFull    = "full"
	CoveragePartial = "partial"
	CoverageLimited = "limited"
)

// App is one catalog entry.
type App struct {
	ID            string        `yaml:"id" json:"id"`
	Aliases       []string      `yaml:"aliases" json:"aliases,omitempty"`
	Name          string        `yaml:"name" json:"name"`
	Homepage      string        `yaml:"homepage" json:"homepage"`
	Tags          []string      `yaml:"tags" json:"tags,omitempty"`
	Images        []Image       `yaml:"images" json:"images,omitempty"`
	OCISource     []string      `yaml:"oci_source" json:"oci_source,omitempty"`
	Packages      []Package     `yaml:"packages" json:"packages,omitempty"`
	Services      []ServiceUnit `yaml:"services" json:"services,omitempty"`
	Version       VersionSpec   `yaml:"version" json:"version"`
	Advisories    Advisories    `yaml:"advisories" json:"advisories"`
	ExposureHints ExposureHints `yaml:"exposure_hints" json:"exposure_hints"`
	// EOL is the product name on endoflife.date, whose release lines say
	// when a version stops getting fixes.
	EOL         string   `yaml:"eol" json:"eol,omitempty"`
	Maintainers []string `yaml:"maintainers_of_entry" json:"maintainers_of_entry"`
	Verified    string   `yaml:"verified" json:"verified"`

	Origin Origin `yaml:"-" json:"origin"`
	// Derivation says how a derived entry was first found; nil for reviewed
	// ones. Whether an image of the entry is confirmed is kept per image
	// (DerivationFor): one project can have a confirmed image and one that
	// a single list reports.
	Derivation *Derivation `yaml:"-" json:"derivation,omitempty"`
	// DerivedImages holds, per image repository, how that image was tied
	// to the derived entry.
	DerivedImages map[string]Derivation `yaml:"-" json:"derived_images,omitempty"`
}

// Image matches an image repository.
type Image struct {
	Match  string `yaml:"match" json:"match"`
	Flavor string `yaml:"flavor" json:"flavor,omitempty"`
	Note   string `yaml:"note" json:"note,omitempty"`

	repo string // normalised Match
}

// Package matches a natively installed package.
type Package struct {
	Manager string `yaml:"manager" json:"manager"`
	Name    string `yaml:"name" json:"name"`
	// Versioning says whether the package version is the app's release
	// version: "upstream" for packages from the project's own repository,
	// "distro" (the default) for distribution packages, whose maintainers
	// backport fixes without changing the upstream version. Only upstream
	// versions are compared with advisory ranges (ADR 0008).
	Versioning string `yaml:"versioning" json:"versioning,omitempty"`
	// VersionPattern extracts the release version from the package
	// version; it must contain the named group v. Default: the version
	// without epoch and revision.
	VersionPattern string `yaml:"version_pattern" json:"version_pattern,omitempty"`
	// Source is the source package distribution security data names
	// ("openssh" for openssh-server); default: the package name.
	Source string `yaml:"source" json:"source,omitempty"`

	pattern *regexp.Regexp
}

// SourceName is the source package name of p.
func (p Package) SourceName() string {
	if p.Source != "" {
		return p.Source
	}
	return p.Name
}

// Package versioning.
const (
	VersioningUpstream = "upstream"
	VersioningDistro   = "distro"
)

// Upstream reports whether the package version is the release version.
func (p Package) Upstream() bool { return p.Versioning == VersioningUpstream }

// Release extracts the release version from a package version, or reports
// false when the pattern does not match.
func (p Package) Release(pkgVersion string) (string, bool) {
	if p.pattern == nil {
		return "", false
	}
	m := p.pattern.FindStringSubmatch(pkgVersion)
	if m == nil {
		return "", false
	}
	return m[p.pattern.SubexpIndex("v")], true
}

// ServiceUnit matches a systemd unit.
type ServiceUnit struct {
	Unit string `yaml:"unit" json:"unit"`
}

// VersionSpec describes how to read and compare the app's version.
type VersionSpec struct {
	Scheme    version.Scheme  `yaml:"scheme" json:"scheme"`
	Sources   []VersionSource `yaml:"sources" json:"sources,omitempty"`
	Normalise Normalisation   `yaml:"normalise" json:"normalise"`
	Probe     *Probe          `yaml:"probe" json:"probe,omitempty"`
}

// VersionSource is one step of the extraction chain: exactly one of Label
// and Tag is set.
type VersionSource struct {
	Label      string `yaml:"label" json:"label,omitempty"`
	Tag        string `yaml:"tag" json:"tag,omitempty"`
	Normaliser string `yaml:"normaliser" json:"normaliser,omitempty"`

	tagRE *regexp.Regexp
}

// TagRegexp returns the compiled tag pattern, or nil for label sources.
func (s VersionSource) TagRegexp() *regexp.Regexp { return s.tagRE }

// Normalisation adjusts extracted versions.
type Normalisation struct {
	StripPrefix string `yaml:"strip_prefix" json:"strip_prefix,omitempty"`
}

// Probe describes how Varde reads the version from the app itself.
type Probe struct {
	HTTP *HTTPProbe `yaml:"http" json:"http,omitempty"`
}

// HTTPProbe reads the version from a documented, unauthenticated JSON
// endpoint of the app. Only a response that proves it comes from the app
// (Expect) yields a version.
type HTTPProbe struct {
	Path string `yaml:"path" json:"path"`
	// JSONPointer (RFC 6901) addresses the version string; empty means the
	// whole response is a JSON string.
	JSONPointer string `yaml:"json_pointer" json:"json_pointer"`
	// VersionPattern extracts the version with the named group v.
	VersionPattern string `yaml:"version_pattern" json:"version_pattern,omitempty"`
	// Expect maps JSON pointers to the exact strings the app returns there,
	// for example the product name. Required.
	Expect map[string]string `yaml:"expect" json:"expect"`
	// CheckPath, if set, is requested first and Expect is checked on its
	// response, for apps whose version endpoint carries no product field.
	CheckPath string `yaml:"check_path" json:"check_path,omitempty"`

	pattern *regexp.Regexp
}

// Pattern returns the compiled VersionPattern, nil when unset.
func (p *HTTPProbe) Pattern() *regexp.Regexp { return p.pattern }

// probePath allows an absolute path on the app with a simple query.
var probePath = regexp.MustCompile(`^/[A-Za-z0-9/._~-]*(\?[A-Za-z0-9=&._-]+)?$`)

// Advisories lists where advisories for the app are published.
type Advisories struct {
	Coverage    string   `yaml:"coverage" json:"coverage"`
	GitHubRepos []string `yaml:"github_repos" json:"github_repos,omitempty"`
	// Packages restricts which affected packages of an advisory apply to
	// this app (multi-product repositories). Empty means all.
	Packages    []PackageFilter `yaml:"packages" json:"packages,omitempty"`
	OSVPackages []OSVPackage    `yaml:"osv_packages" json:"osv_packages,omitempty"`
	CPE         []string        `yaml:"cpe" json:"cpe,omitempty"`
	Notes       string          `yaml:"notes" json:"notes,omitempty"`
}

// PackageFilter selects affected packages of an advisory by name and,
// optionally, ecosystem. Both compare case-insensitively.
type PackageFilter struct {
	Ecosystem string `yaml:"ecosystem" json:"ecosystem,omitempty"`
	Name      string `yaml:"name" json:"name"`
}

// Matches reports whether an advisory package matches the filter.
func (f PackageFilter) Matches(ecosystem, name string) bool {
	if !strings.EqualFold(f.Name, strings.TrimSpace(name)) {
		return false
	}
	return f.Ecosystem == "" || strings.EqualFold(f.Ecosystem, strings.TrimSpace(ecosystem))
}

// OSVPackage is a package in an OSV ecosystem.
type OSVPackage struct {
	Ecosystem string `yaml:"ecosystem" json:"ecosystem"`
	Name      string `yaml:"name" json:"name"`
}

// ExposureHints are weak hints for exposure detection.
type ExposureHints struct {
	DefaultPorts []int  `yaml:"default_ports" json:"default_ports,omitempty"`
	Typical      string `yaml:"typical" json:"typical,omitempty"`
}

// Catalog is a validated, indexed set of apps.
type Catalog struct {
	apps     map[string]*App
	aliases  map[string]string
	byImage  map[string]*App
	bySource map[string]*App
	// byPackage is keyed by manager + "\x00" + name, byUnit by unit name.
	byPackage map[string]packageMatch
	byUnit    map[string]*App
	ids       []string
	// dropped are the generated entries BuildLayered left out.
	dropped []string
}

type packageMatch struct {
	app *App
	pkg Package
}

// Parse decodes and validates one entry. name is used in errors only.
func Parse(name string, data []byte) (*App, error) {
	if len(data) > maxEntryBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxEntryBytes)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := rejectYAMLFeatures(&root); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var app App
	if err := dec.Decode(&app); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%s: more than one YAML document", name)
	}
	if err := app.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &app, nil
}

// rejectYAMLFeatures forbids anchors, aliases and merge keys, which the
// catalog does not need and which enable expansion attacks.
func rejectYAMLFeatures(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("line %d: anchors and aliases are not allowed", n.Line)
	}
	if n.Tag == "!!merge" {
		return fmt.Errorf("line %d: merge keys are not allowed", n.Line)
	}
	for _, c := range n.Content {
		if err := rejectYAMLFeatures(c); err != nil {
			return err
		}
	}
	return nil
}

// Entry is the source text of one catalog entry.
type Entry struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

// Load reads all *.yaml entries from builtin and, if not nil, from local.
// Local entries replace built-in entries with the same ID and are marked
// with OriginLocal.
func Load(builtin, local fs.FS) (*Catalog, error) {
	base, err := ReadEntries(builtin)
	if err != nil {
		return nil, fmt.Errorf("%s catalog: %w", OriginBuiltin, err)
	}
	return Build(base, OriginBuiltin, local)
}

// ReadEntries reads all *.yaml files of fsys.
func ReadEntries(fsys fs.FS) ([]Entry, error) {
	names, err := readDir(fsys)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(names))
	for _, name := range names {
		data, err := readFileLimited(fsys, name)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Name: name, Data: string(data)})
	}
	return out, nil
}

// Build creates a catalog from base entries (built-in or from the feed) and
// the optional local directory, whose entries take precedence.
func Build(base []Entry, origin Origin, local fs.FS) (*Catalog, error) {
	apps, err := reviewedApps(base, origin, local)
	if err != nil {
		return nil, err
	}
	return newCatalog(apps)
}

// reviewedApps parses base entries and the local directory, whose entries
// replace base entries with the same ID.
func reviewedApps(base []Entry, origin Origin, local fs.FS) (map[string]*App, error) {
	if len(base) > maxEntries {
		return nil, fmt.Errorf("%s catalog: more than %d entries", origin, maxEntries)
	}
	apps := map[string]*App{}
	if err := addEntries(apps, base, origin); err != nil {
		return nil, err
	}
	if local != nil {
		entries, err := ReadEntries(local)
		if err != nil {
			return nil, fmt.Errorf("%s catalog: %w", OriginLocal, err)
		}
		if err := addEntries(apps, entries, OriginLocal); err != nil {
			return nil, err
		}
	}
	return apps, nil
}

// BuildLayered is Build with generated entries beneath the reviewed ones.
// A reviewed entry always wins: a generated entry whose ID, alias, image,
// source, package or unit a reviewed entry (or an earlier generated one)
// already claims is dropped, and so is one that does not parse, claims
// full coverage or repeats a key of its own. Dropping one costs that app;
// refusing the set would cost the installation the whole package.
// DroppedGenerated lists the drops.
func BuildLayered(reviewed []Entry, reviewedOrigin Origin, generated []Entry, local fs.FS) (*Catalog, error) {
	if len(generated) > maxGenerated {
		return nil, fmt.Errorf("%s catalog: more than %d entries", OriginGenerated, maxGenerated)
	}
	apps, err := reviewedApps(reviewed, reviewedOrigin, local)
	if err != nil {
		return nil, err
	}
	layered := make(map[string]*App, len(apps)+len(generated))
	claimed := claims{}
	for id, a := range apps {
		layered[id] = a
		claimed.add(a)
	}
	var dropped []string
	added := 0
	for _, e := range generated {
		app, err := Parse(e.Name, []byte(e.Data))
		switch {
		case err != nil:
			dropped = append(dropped, err.Error())
			continue
		case app.Advisories.Coverage == CoverageFull:
			// A machine check cannot tell that every advisory of the
			// app is covered.
			dropped = append(dropped, e.Name+": generated entry claims full coverage")
			continue
		}
		if what, repeated := ownRepeat(app); repeated {
			// Validation lets a reviewed entry repeat some keys (and
			// newCatalog refuses it then); a generated one must not
			// fail the set that way.
			dropped = append(dropped, fmt.Sprintf("%s: %s listed twice", e.Name, what))
			continue
		}
		if what, taken := claimed.taken(app); taken {
			dropped = append(dropped, fmt.Sprintf("%s: %s already claimed", e.Name, what))
			continue
		}
		app.Origin = OriginGenerated
		claimed.add(app)
		layered[app.ID] = app
		added++
	}
	c, err := newCatalog(layered)
	if err != nil && added > 0 {
		// The checks above should leave nothing for newCatalog to refuse.
		// Should one slip through, the reviewed catalog still loads
		// without any generated entry.
		c, err = newCatalog(apps)
		if err == nil {
			dropped = append(dropped, fmt.Sprintf("all %d generated entries: the layered catalog was refused", added))
		}
	}
	if err != nil {
		return nil, err
	}
	c.dropped = dropped
	return c, nil
}

// ownRepeat names a key an entry lists twice itself; a variable so a test
// can switch it off and reach the last guard of BuildLayered.
var ownRepeat = func(a *App) (string, bool) {
	seen := map[string]bool{}
	for _, k := range (claims{}).keys(a) {
		if seen[k] {
			return claimKey(k), true
		}
		seen[k] = true
	}
	return "", false
}

// DroppedGenerated says which generated entries BuildLayered dropped and
// why, for the log.
func (c *Catalog) DroppedGenerated() []string { return c.dropped }

// claims are the keys newCatalog requires to be unique across entries.
type claims map[string]bool

func (c claims) keys(a *App) []string {
	keys := []string{"id\x00" + a.ID}
	for _, al := range a.Aliases {
		keys = append(keys, "id\x00"+al)
	}
	for _, img := range a.Images {
		keys = append(keys, "image\x00"+img.repo)
	}
	for _, src := range a.OCISource {
		keys = append(keys, "oci_source\x00"+normaliseSource(src))
	}
	for _, p := range a.Packages {
		// The same key newCatalog's byPackage uses.
		keys = append(keys, "package\x00"+p.Manager+"\x00"+p.Name)
	}
	for _, s := range a.Services {
		keys = append(keys, "service\x00"+s.Unit)
	}
	return keys
}

func (c claims) add(a *App) {
	for _, k := range c.keys(a) {
		c[k] = true
	}
}

// taken names the first key of a that another entry claims. IDs and
// aliases share one namespace, as App resolves both.
func (c claims) taken(a *App) (string, bool) {
	for _, k := range c.keys(a) {
		if c[k] {
			return claimKey(k), true
		}
	}
	return "", false
}

// claimKey makes a claim key readable for the log.
func claimKey(k string) string { return strings.ReplaceAll(k, "\x00", " ") }

func addEntries(apps map[string]*App, entries []Entry, origin Origin) error {
	seen := map[string]string{}
	for _, e := range entries {
		app, err := Parse(e.Name, []byte(e.Data))
		if err != nil {
			return fmt.Errorf("%s catalog: %w", origin, err)
		}
		if other, dup := seen[app.ID]; dup {
			return fmt.Errorf("%s catalog: id %q defined in %s and %s", origin, app.ID, other, e.Name)
		}
		seen[app.ID] = e.Name
		app.Origin = origin
		apps[app.ID] = app
	}
	return nil
}

// Live holds the current catalog. A new catalog from the feed replaces it
// without a restart; readers always see a complete catalog.
type Live struct {
	p atomic.Pointer[Catalog]
	// base is the catalog without derived entries (see SetDerived).
	base atomic.Pointer[Catalog]
}

// NewLive returns a holder for c.
func NewLive(c *Catalog) *Live {
	l := &Live{}
	l.p.Store(c)
	l.base.Store(c)
	return l
}

// Current returns the catalog in use.
func (l *Live) Current() *Catalog { return l.p.Load() }

// Set replaces the catalog.
func (l *Live) Set(c *Catalog) {
	l.base.Store(c)
	l.p.Store(c)
}

func readDir(fsys fs.FS) ([]string, error) {
	var names []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		if len(names) >= maxEntries {
			return fmt.Errorf("more than %d entries", maxEntries)
		}
		names = append(names, p)
		return nil
	})
	sort.Strings(names)
	return names, err
}

func readFileLimited(fsys fs.FS, name string) ([]byte, error) {
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxEntryBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxEntryBytes)
	}
	return fs.ReadFile(fsys, name)
}

func newCatalog(apps map[string]*App) (*Catalog, error) {
	c := &Catalog{
		apps:      apps,
		aliases:   map[string]string{},
		byImage:   map[string]*App{},
		bySource:  map[string]*App{},
		byPackage: map[string]packageMatch{},
		byUnit:    map[string]*App{},
	}
	var errs []error
	for id, app := range apps {
		c.ids = append(c.ids, id)
		for _, alias := range app.Aliases {
			if _, clash := apps[alias]; clash {
				errs = append(errs, fmt.Errorf("%s: alias %q is an existing id", id, alias))
			}
			if other, dup := c.aliases[alias]; dup {
				errs = append(errs, fmt.Errorf("alias %q used by %s and %s", alias, other, id))
			}
			c.aliases[alias] = id
		}
		for _, img := range app.Images {
			if other, dup := c.byImage[img.repo]; dup {
				errs = append(errs, fmt.Errorf("image %s matched by %s and %s", img.repo, other.ID, id))
			}
			c.byImage[img.repo] = app
		}
		for _, pkg := range app.Packages {
			key := pkg.Manager + "\x00" + pkg.Name
			if other, dup := c.byPackage[key]; dup {
				errs = append(errs, fmt.Errorf("package %s %s matched by %s and %s", pkg.Manager, pkg.Name, other.app.ID, id))
			}
			c.byPackage[key] = packageMatch{app, pkg}
		}
		for _, s := range app.Services {
			if other, dup := c.byUnit[s.Unit]; dup {
				errs = append(errs, fmt.Errorf("service %s matched by %s and %s", s.Unit, other.ID, id))
			}
			c.byUnit[s.Unit] = app
		}
		for _, src := range app.OCISource {
			key := normaliseSource(src)
			if other, dup := c.bySource[key]; dup {
				errs = append(errs, fmt.Errorf("oci_source %s used by %s and %s", src, other.ID, id))
			}
			c.bySource[key] = app
		}
	}
	sort.Strings(c.ids)
	if len(errs) > 0 {
		sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// Len returns the number of apps.
func (c *Catalog) Len() int { return len(c.apps) }

// Apps returns all apps ordered by ID.
func (c *Catalog) Apps() []*App {
	out := make([]*App, 0, len(c.ids))
	for _, id := range c.ids {
		out = append(out, c.apps[id])
	}
	return out
}

// App returns the app with id or alias.
func (c *Catalog) App(id string) (*App, bool) {
	if a, ok := c.apps[id]; ok {
		return a, true
	}
	if real, ok := c.aliases[id]; ok {
		return c.apps[real], true
	}
	return nil, false
}

// ByImage returns the app matching a normalised image repository.
func (c *Catalog) ByImage(repo string) (*App, bool) {
	a, ok := c.byImage[repo]
	return a, ok
}

// ByPackage returns the app and matcher for a native package.
func (c *Catalog) ByPackage(manager, name string) (*App, Package, bool) {
	m, ok := c.byPackage[manager+"\x00"+name]
	return m.app, m.pkg, ok
}

// ByService returns the app matching a systemd unit name.
func (c *Catalog) ByService(unit string) (*App, bool) {
	a, ok := c.byUnit[unit]
	return a, ok
}

// ByOCISource returns the app matching an org.opencontainers.image.source
// label value.
func (c *Catalog) ByOCISource(src string) (*App, bool) {
	a, ok := c.bySource[normaliseSource(src)]
	return a, ok
}

// ImageFlavor returns the flavor of the matcher for repo, if any.
func (a *App) ImageFlavor(repo string) string {
	for _, img := range a.Images {
		if img.repo == repo {
			return img.Flavor
		}
	}
	return ""
}

// normaliseSource folds spellings of a source URL onto one key: case,
// trailing slash, ".git", and the "/tree/<ref>" or "/commit/<sha>" suffix
// that some images put into org.opencontainers.image.source.
func normaliseSource(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, marker := range []string{"/tree/", "/commit/", "/blob/"} {
		if i := strings.Index(s, marker); i >= 0 {
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	return strings.TrimSuffix(s, "/")
}

var (
	idPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	tagPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	repoPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	cpePattern      = regexp.MustCompile(`^cpe:2\.3:[aho]:[a-z0-9._\-~%]+:[a-z0-9._\-~%]+(:.*)?$`)
	labelKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	datePattern     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	handlePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	unitPattern     = regexp.MustCompile(`^[A-Za-z0-9@._:*-]{1,128}$`)
	osvEcosystems   = map[string]bool{"Go": true, "npm": true, "PyPI": true, "Packagist": true, "NuGet": true, "Maven": true, "crates.io": true, "RubyGems": true, "Hex": true, "Pub": true}
)

func (a *App) validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if !idPattern.MatchString(a.ID) {
		fail("id %q must match %s", a.ID, idPattern)
	}
	for _, al := range a.Aliases {
		if !idPattern.MatchString(al) || al == a.ID {
			fail("alias %q invalid", al)
		}
	}
	if strings.TrimSpace(a.Name) == "" || len(a.Name) > 128 {
		fail("name must be 1-128 characters")
	}
	if !strings.HasPrefix(a.Homepage, "https://") || len(a.Homepage) > 256 {
		fail("homepage must be an https URL")
	}
	for _, t := range a.Tags {
		if !tagPattern.MatchString(t) {
			fail("tag %q invalid", t)
		}
	}
	if len(a.Images)+len(a.OCISource)+len(a.Packages)+len(a.Services) == 0 {
		fail("at least one of images, oci_source, packages, services is required")
	}
	seenRepo := map[string]bool{}
	for i := range a.Images {
		img := &a.Images[i]
		if strings.ContainsAny(img.Match, "*?[:@") {
			fail("image %q: no wildcards, tags or digests", img.Match)
			continue
		}
		repo, err := imageref.NormaliseRepository(img.Match)
		if err != nil {
			fail("image %q: %v", img.Match, err)
			continue
		}
		if seenRepo[repo] {
			fail("image %q listed twice (normalised %s)", img.Match, repo)
		}
		seenRepo[repo] = true
		img.repo = repo
		switch img.Flavor {
		case "":
		case "lsio":
			if !imageref.IsLSIO(repo) {
				fail("image %q: flavor lsio on a non-linuxserver repository", img.Match)
			}
		default:
			fail("image %q: unknown flavor %q", img.Match, img.Flavor)
		}
	}
	if a.EOL != "" && !eolProduct.MatchString(a.EOL) {
		fail("eol %q must be an endoflife.date product name", a.EOL)
	}
	for _, s := range a.OCISource {
		if !strings.HasPrefix(s, "https://") || strings.HasSuffix(s, "/") || strings.HasSuffix(s, ".git") || len(s) > 256 {
			fail("oci_source %q must be an https URL without trailing slash or .git", s)
		}
	}
	for i := range a.Packages {
		p := &a.Packages[i]
		switch p.Manager {
		case "dpkg", "rpm", "apk":
		case "firmware":
			// An appliance's own version: there is no distribution
			// revision to strip.
			if p.Versioning != VersioningUpstream {
				fail("package %q: a firmware package needs versioning upstream", p.Name)
			}
		default:
			fail("package %q: manager must be dpkg, rpm, apk or firmware", p.Name)
		}
		if !unitPattern.MatchString(p.Name) || strings.Contains(p.Name, "*") {
			fail("package name %q invalid", p.Name)
		}
		if p.Source != "" && (!unitPattern.MatchString(p.Source) || strings.ContainsAny(p.Source, "*?[")) {
			fail("package %q: source %q invalid", p.Name, p.Source)
		}
		switch p.Versioning {
		case "":
			p.Versioning = VersioningDistro
		case VersioningUpstream, VersioningDistro:
		default:
			fail("package %q: versioning must be upstream or distro", p.Name)
		}
		if p.VersionPattern != "" {
			re, err := regexp.Compile(p.VersionPattern)
			switch {
			case err != nil || len(p.VersionPattern) > 256:
				fail("package %q: version_pattern is not a valid regular expression", p.Name)
			case re.SubexpIndex("v") < 0:
				fail("package %q: version_pattern needs the named group v", p.Name)
			default:
				p.pattern = re
			}
		}
	}
	for _, s := range a.Services {
		// Units are matched by exact name: a pattern would match units of
		// other apps.
		if !unitPattern.MatchString(s.Unit) || strings.ContainsAny(s.Unit, "*?[") {
			fail("service unit %q invalid", s.Unit)
		}
	}
	a.validateVersion(fail)
	a.validateAdvisories(fail)
	for _, p := range a.ExposureHints.DefaultPorts {
		if p < 1 || p > 65535 {
			fail("default port %d out of range", p)
		}
	}
	switch a.ExposureHints.Typical {
	case "", "public", "lan", "internal":
	default:
		fail("exposure_hints.typical %q must be public, lan or internal", a.ExposureHints.Typical)
	}
	if len(a.Maintainers) == 0 {
		fail("maintainers_of_entry is required")
	}
	for _, m := range a.Maintainers {
		if !handlePattern.MatchString(m) {
			fail("maintainer %q is not a GitHub handle", m)
		}
	}
	if !datePattern.MatchString(a.Verified) {
		fail("verified must be a YYYY-MM-DD date")
	}
	return errors.Join(errs...)
}

func (a *App) validateVersion(fail func(string, ...any)) {
	v := &a.Version
	if !v.Scheme.Valid() {
		fail("version.scheme %q must be semver or calver", v.Scheme)
	}
	for i := range v.Sources {
		s := &v.Sources[i]
		switch {
		case (s.Label == "") == (s.Tag == ""):
			fail("version.sources[%d]: set exactly one of label and tag", i)
		case s.Label != "" && !labelKeyPattern.MatchString(s.Label):
			fail("version.sources[%d]: label key %q invalid", i, s.Label)
		case s.Tag != "":
			if len(s.Tag) > maxRegexLen {
				fail("version.sources[%d]: regex longer than %d", i, maxRegexLen)
				continue
			}
			re, err := regexp.Compile(s.Tag)
			if err != nil {
				fail("version.sources[%d]: %v", i, err)
				continue
			}
			if re.SubexpIndex("v") < 0 {
				fail("version.sources[%d]: regex needs a named group (?P<v>...)", i)
			}
			if !strings.HasPrefix(s.Tag, "^") || !strings.HasSuffix(s.Tag, "$") {
				fail("version.sources[%d]: regex must be anchored with ^ and $", i)
			}
			s.tagRE = re
		}
		if s.Normaliser != "" && !version.ValidNormaliser(s.Normaliser) {
			fail("version.sources[%d]: unknown normaliser %q", i, s.Normaliser)
		}
	}
	if len(v.Normalise.StripPrefix) > 32 {
		fail("version.normalise.strip_prefix too long")
	}
	if v.Probe != nil && v.Probe.HTTP != nil {
		p := v.Probe.HTTP
		paths := []string{p.Path}
		if p.CheckPath != "" {
			paths = append(paths, p.CheckPath)
		}
		for _, path := range paths {
			if !probePath.MatchString(path) || strings.Contains(path, "..") || strings.Contains(path, "//") || len(path) > 256 {
				fail("version.probe.http paths must be absolute paths on the app itself")
			}
		}
		if p.JSONPointer != "" && !strings.HasPrefix(p.JSONPointer, "/") {
			fail("version.probe.http.json_pointer must start with /")
		}
		if len(p.Expect) == 0 || len(p.Expect) > 4 {
			fail("version.probe.http.expect needs one to four fields that prove the response comes from the app")
		}
		for ptr, val := range p.Expect {
			if !strings.HasPrefix(ptr, "/") || val == "" || len(ptr) > 128 || len(val) > 128 {
				fail("version.probe.http.expect: %q must be a JSON pointer with a non-empty value", ptr)
			}
		}
		if p.VersionPattern != "" {
			re, err := regexp.Compile(p.VersionPattern)
			switch {
			case err != nil || len(p.VersionPattern) > 256:
				fail("version.probe.http.version_pattern is not a valid regular expression")
			case re.SubexpIndex("v") < 0:
				fail("version.probe.http.version_pattern needs the named group v")
			default:
				p.pattern = re
			}
		}
	}
}

func (a *App) validateAdvisories(fail func(string, ...any)) {
	adv := &a.Advisories
	switch adv.Coverage {
	case CoverageFull, CoveragePartial, CoverageLimited:
	default:
		fail("advisories.coverage %q must be full, partial or limited", adv.Coverage)
	}
	for _, r := range adv.GitHubRepos {
		if !repoPattern.MatchString(r) {
			fail("github repo %q must be owner/name", r)
		}
	}
	for _, p := range adv.Packages {
		if strings.TrimSpace(p.Name) == "" || len(p.Name) > 256 || len(p.Ecosystem) > 64 {
			fail("advisories.packages: name required, at most 256 characters")
		}
	}
	for _, p := range adv.OSVPackages {
		if !osvEcosystems[p.Ecosystem] {
			fail("osv package %q: unsupported ecosystem %q", p.Name, p.Ecosystem)
		}
		if p.Name == "" || len(p.Name) > 256 {
			fail("osv package name invalid")
		}
	}
	for _, c := range adv.CPE {
		if !cpePattern.MatchString(c) {
			fail("cpe %q must look like cpe:2.3:a:vendor:product", c)
		}
	}
	if adv.Coverage == CoverageFull && len(adv.GitHubRepos)+len(adv.OSVPackages) == 0 {
		fail("coverage full requires github_repos or osv_packages")
	}
	if len(adv.Notes) > 2048 {
		fail("advisories.notes longer than 2048 characters")
	}
	if adv.Coverage == CoverageLimited && len(adv.GitHubRepos)+len(adv.OSVPackages)+len(adv.CPE) == 0 && adv.Notes == "" {
		fail("coverage limited still needs at least one source or notes on where advisories appear")
	}
}

// eolProduct is an endoflife.date product name ("nginx", "proxmox-ve").
var eolProduct = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}$`)
