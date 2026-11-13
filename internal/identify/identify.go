// SPDX-License-Identifier: Apache-2.0

// Package identify maps workloads to catalog apps and resolves the version
// they run. It is pure: no I/O, deterministic for the same inputs.
//
// Precision first (ADR 0008): a version is only reported when a source
// yields a value that parses under the app's scheme; otherwise the result
// says why it is unknown.
package identify

import (
	"path"
	"regexp"
	"strings"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/purl"
	"github.com/bifrost0x/varde/internal/version"
)

// Confidence of an identification.
type Confidence string

// Confidence levels, strongest first.
const (
	Exact  Confidence = "exact"
	Strong Confidence = "strong"
	Weak   Confidence = "weak"
	None   Confidence = "none"
)

// Notifiable reports whether findings for this confidence may notify.
func (c Confidence) Notifiable() bool { return c == Exact || c == Strong }

// Well-known labels.
const (
	LabelApp       = buildinfo.LabelPrefix + "app"
	LabelVersion   = buildinfo.LabelPrefix + "version"
	LabelOCISource = "org.opencontainers.image.source"
	LabelOCIVer    = "org.opencontainers.image.version"
	labelLSIOBuild = "build_version"
)

// Result is the identification of one workload.
type Result struct {
	WorkloadID string     `json:"-"`
	AppID      string     `json:"app_id,omitempty"`
	Confidence Confidence `json:"confidence"`
	Rule       string     `json:"rule,omitempty"`

	// Version is the canonical version, empty when unknown.
	Version       string `json:"version,omitempty"`
	VersionRaw    string `json:"version_raw,omitempty"`
	VersionSource string `json:"version_source,omitempty"`
	// Note explains an unknown version or a weak/absent identification.
	Note string `json:"note,omitempty"`
	// Trust says how far the version can be relied on (see the Trust
	// constants); empty when the version is unknown.
	Trust Trust `json:"trust,omitempty"`
	// Evidence lists every observation of the version, also the ones not
	// used, so a reader can see where it comes from and what disagrees.
	Evidence []Evidence `json:"evidence,omitempty"`
	// PURL identifies the component (package URL), empty when unknown.
	PURL string `json:"purl,omitempty"`
	// Derived marks an app Varde recognised automatically (catalog entry
	// of origin derived) and the user has not confirmed with varde.app.
	Derived bool `json:"derived,omitempty"`
	// DerivedFrom says what the automatic recognition rests on, for the
	// reason shown with unconfirmed findings.
	DerivedFrom string `json:"derived_from,omitempty"`
	// DistroPackage is set for a distribution package of a release with
	// security data: its version is compared with the distribution's
	// records, not with upstream ranges (ADR 0028).
	DistroPackage *distro.Package `json:"distro_package,omitempty"`
	// Unfixed counts the distribution's open issues of a system package
	// that no update fixes yet (ADR 0032); they are not findings.
	Unfixed int `json:"unfixed,omitempty"`
}

// Trust is how far a version can be relied on.
type Trust string

// Trust levels.
const (
	// Confirmed: an authoritative source states the version (the
	// publisher's image label or tag, an upstream package, the user), and
	// no other source contradicts it. Only confirmed versions can produce
	// affected findings and urgent notifications.
	Confirmed Trust = "confirmed"
	// Reported: the version comes only from a source that cannot be
	// verified, such as an app's unauthenticated version endpoint.
	Reported Trust = "reported"
	// Conflict: sources disagree on the version.
	Conflict Trust = "conflict"
)

// Evidence is one observation of a version.
type Evidence struct {
	// Method is where the value comes from ("image label
	// org.opencontainers.image.version", "tag 1.2.3", "package dpkg x").
	Method string `json:"method"`
	// Raw is the value as observed, Version the canonical form; empty when
	// the value is not a valid version.
	Raw     string `json:"raw"`
	Version string `json:"version,omitempty"`
	// Used marks the observation the version was taken from.
	Used bool `json:"used,omitempty"`
}

// Doubt explains why the version must not produce affected findings; empty
// when it is confirmed or unknown.
func (r Result) Doubt() string {
	if r.Derived && r.Version != "" {
		from := r.DerivedFrom
		if from == "" {
			from = "automatically"
		}
		return "the app was recognised " + from + "; confirm it with the label " + LabelApp + "=" + r.AppID
	}
	switch r.Trust {
	case Reported:
		return "version only reported by " + r.VersionSource + ", not confirmed by another source"
	case Conflict:
		return "sources disagree on the version: " + describeEvidence(r.Evidence)
	}
	return ""
}

func describeEvidence(ev []Evidence) string {
	var parts []string
	for _, e := range ev {
		if e.Version != "" {
			parts = append(parts, e.Method+" says "+e.Version)
		}
	}
	return strings.Join(parts, ", ")
}

// consistent reports whether two canonical versions describe the same
// release: equal, or one is a shorter form of the other ("1.37" and
// "1.37.5", a tag that tracks a minor line).
func consistent(a, b string) bool {
	if a == b {
		return true
	}
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	if len(x) > len(y) {
		x, y = y, x
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// VersionKnown reports whether a version was resolved.
func (r Result) VersionKnown() bool { return r.Version != "" || r.DistroPackage != nil }

var (
	defaultSemverTag = regexp.MustCompile(`^v?(?P<v>\d+(?:\.\d+){2,4}(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?)$`)
	defaultCalverTag = regexp.MustCompile(`^v?(?P<v>\d{4}\.\d{1,2}\.\d+)$`)
	lsioTag          = regexp.MustCompile(`^(?P<v>.+-ls\d+)$`)
)

// Identify identifies w against cat.
func Identify(cat *catalog.Catalog, w inventory.Workload) Result {
	var r Result
	switch w.Kind {
	case inventory.KindContainer:
		r = identifyContainer(cat, w)
	case inventory.KindManual:
		r = identifyManual(cat, w)
	case inventory.KindPackage:
		r = identifyPackage(cat, w)
	case inventory.KindService:
		r = identifyService(cat, w)
	case inventory.KindEndpoint:
		r = identifyEndpoint(cat, w)
	default:
		r = Result{Confidence: None, Note: "unknown workload kind"}
	}
	r.WorkloadID = w.ID
	r.PURL = componentPURL(w)
	if app, ok := cat.App(r.AppID); ok && !strings.HasPrefix(r.Rule, "label "+LabelApp) && w.Container != nil {
		// The publisher's own statement or two lists confirm a derived
		// app; anything less is a report the user settles (ADR 0038).
		// Confirmation is per image: this image may be one a single list
		// reports, or one that only inherited the app's source label. A
		// workload without an image (a manual entry) names the app itself.
		// A generated entry is confirmed the same way for the images it
		// stands in for its derived entry (ReadsAsDerived).
		var repo string
		var d *catalog.Derivation
		if ref, err := imageref.Parse(w.Container.ImageRef); err == nil {
			repo = ref.Repository
			d = app.DerivationFor(repo)
		}
		if app.Origin == catalog.OriginDerived || ReadsAsDerived(app, repo) {
			if d == nil || !d.Confirmed {
				r.Derived = true
				r.DerivedFrom = derivedFrom(d)
			}
		}
	}
	return r
}

// evidenceWords says what kinds of first-party evidence mean.
func evidenceWords(kinds []string) string {
	words := map[string]string{
		"readme": "the project's README names the image",
		"hub":    "the image's Docker Hub page links the project",
		"ghcr":   "the image is in the project's namespace on GitHub's registry",
	}
	var out []string
	for _, k := range kinds {
		if w, ok := words[k]; ok {
			out = append(out, w)
		}
	}
	return strings.Join(out, "; ")
}

// EvidenceWords is evidenceWords for the UI.
func EvidenceWords(kinds []string) string { return evidenceWords(kinds) }

// derivedFrom words the basis of an unconfirmed derivation.
func derivedFrom(d *catalog.Derivation) string {
	if d == nil {
		return "only by a source label this image may have inherited from its base image"
	}
	switch d.Basis {
	case catalog.BasisIndex:
		return "from one statement only (" + strings.Join(d.Evidence, ", ") + ": " + evidenceWords(d.Evidence) + ")"
	case catalog.BasisLists:
		if len(d.Lists) == 1 {
			return "from one app store list (" + d.Lists[0] + ")"
		}
		return "from app store lists (" + strings.Join(d.Lists, ", ") + ")"
	case catalog.BasisGHCR:
		return "from its place on GitHub's registry"
	}
	return "automatically from its source label"
}

// componentPURL identifies the component a workload runs: the image (by
// registry digest when known, else tag) or the native package.
func componentPURL(w inventory.Workload) string {
	switch {
	case w.Container != nil:
		ref, err := imageref.Parse(w.Container.ImageRef)
		if err != nil {
			return ""
		}
		version := ref.Digest
		for _, d := range w.Container.RepoDigests {
			if _, dig, ok := strings.Cut(d, "@"); ok {
				version = dig
				break
			}
		}
		if version == "" {
			version = ref.Tag
		}
		return purl.Docker(ref.Repository, version)
	case w.Package != nil:
		return purl.Package(w.Package.Manager, w.Package.Distro, w.Package.Name, w.Package.Version)
	}
	return ""
}

func identifyContainer(cat *catalog.Catalog, w inventory.Workload) Result {
	c := w.Container
	if c == nil {
		return Result{Confidence: None, Note: "no container data"}
	}
	labels := mergedLabels(c)
	ref, refErr := imageref.Parse(c.ImageRef)

	// 1. Explicit label wins over everything.
	if id := strings.TrimSpace(labels[LabelApp]); id != "" {
		app, ok := cat.App(id)
		if !ok {
			return Result{Confidence: None, Note: "label " + LabelApp + "=" + id + " does not name a catalog app"}
		}
		r := Result{AppID: app.ID, Confidence: Exact, Rule: "label " + LabelApp}
		resolveContainerVersion(&r, AppForImage(app, imageRepository(ref, refErr)), labels, ref, refErr == nil, c)
		return r
	}
	// 2. Image repository.
	if refErr == nil {
		if app, ok := cat.ByImage(ref.Repository); ok {
			r := Result{AppID: app.ID, Confidence: Exact, Rule: "image " + ref.Repository}
			resolveContainerVersion(&r, AppForImage(app, ref.Repository), labels, ref, true, c)
			return r
		}
	}
	// 3. OCI source label of the image.
	if src := strings.TrimSpace(c.ImageLabels[LabelOCISource]); src != "" {
		if app, ok := cat.ByOCISource(src); ok {
			r := Result{AppID: app.ID, Confidence: Strong, Rule: LabelOCISource + " " + src}
			resolveContainerVersion(&r, AppForImage(app, imageRepository(ref, refErr)), labels, ref, refErr == nil, c)
			return r
		}
	}
	// 4. Heuristic: compose service or container name equals an app ID.
	for _, candidate := range []struct{ name, rule string }{
		{c.ComposeService, "compose service name"},
		{w.Name, "container name"},
	} {
		if candidate.name == "" {
			continue
		}
		if app, ok := cat.App(strings.ToLower(candidate.name)); ok {
			// The image is not the app's known image, so its tag says
			// nothing reliable about the app version; resolve only after
			// the user confirms with varde.app.
			return Result{
				AppID: app.ID, Confidence: Weak, Rule: candidate.rule + " " + candidate.name,
				Note: "probably " + app.Name + "; confirm with label " + LabelApp + "=" + app.ID + " and set " + LabelVersion,
			}
		}
	}
	note := "image not in catalog"
	if refErr != nil {
		note = "unparsable image reference"
	}
	return Result{Confidence: None, Note: note}
}

// ReadsAsDerived reports a container image (repository) of a generated
// entry that the generator did not check: one the entry knows through its
// source label, one it took over from the entry derived for its project,
// or one named by the user's varde.app label. The generated entry stands
// in for the derived entry there, so such an image is read as the derived
// entry would read it: its version chain and scheme and its advisory
// sources (AppForImage), confirmed only as the derivation of the image
// says (DerivationFor). Without a repository (a manual entry, a package,
// an unparsable reference) the entry is read as it is.
func ReadsAsDerived(app *catalog.App, repository string) bool {
	if app == nil || app.Origin != catalog.OriginGenerated || repository == "" {
		return false
	}
	return !app.HasImage(repository) || app.JoinedImage(repository)
}

// AppForImage returns app as Varde reads an image repository of it: for
// an image the generator did not check (ReadsAsDerived), a generated
// entry with the derived entry's version (semver, the default chain of
// label and tag pattern) and without its CPE, which C5 checked for the
// entry's own images only, so the image gets the derived entry's advisory
// sources; app itself otherwise. Identification, the registry resolver,
// matching and update suggestions use it, so they all read such an image
// the same way.
func AppForImage(app *catalog.App, repository string) *catalog.App {
	if !ReadsAsDerived(app, repository) {
		return app
	}
	derived := *app
	derived.Version = catalog.VersionSpec{Scheme: version.SemVer}
	derived.Advisories.CPE = nil
	return &derived
}

// imageRepository is the repository of a parsed reference, empty when it
// did not parse.
func imageRepository(ref imageref.Ref, err error) string {
	if err != nil {
		return ""
	}
	return ref.Repository
}

// mergedLabels returns image labels overlaid with container labels. Docker
// already merges them for running containers; this also covers callers
// that pass them separately.
func mergedLabels(c *inventory.Container) map[string]string {
	out := make(map[string]string, len(c.ImageLabels)+len(c.Labels))
	for k, v := range c.ImageLabels {
		out[k] = v
	}
	for k, v := range c.Labels {
		out[k] = v
	}
	return out
}

type step struct {
	label, tag, normaliser string
	re                     *regexp.Regexp
}

// TagVersion returns the canonical version a tag names for the app, or
// false for floating or unrelated tags. The registry resolver uses it to
// pick and order candidate tags.
func TagVersion(app *catalog.App, repository, tag string) (string, bool) {
	if version.IsFloating(tag) {
		return "", false
	}
	raw, ok := tagMatch(app.Version, app.ImageFlavor(repository) == "lsio", tag)
	if !ok {
		return "", false
	}
	return parse(app.Version, raw, "")
}

// TagRelease is the release a tag names without its image variant
// ("1.27.4-alpine" and "4.0.15.2941-ls276" name 1.27.4 and 4.0.15.2941):
// update suggestions keep the variant and compare releases.
func TagRelease(app *catalog.App, repository, tag string) (string, bool) {
	if version.IsFloating(tag) {
		return "", false
	}
	raw, ok := tagMatch(app.Version, app.ImageFlavor(repository) == "lsio", tag)
	if !ok {
		return "", false
	}
	return parse(app.Version, variantBase(raw), "")
}

// variantBase drops an image variant suffix from a version taken from a
// tag ("2.1.2-alpine", "4.0.20.3014-ls4"): publishers tag the same release
// for several bases. Pre-release suffixes ("-rc1", "-beta.2") stay, since
// they name a different version.
func variantBase(v string) string {
	base, suffix, ok := strings.Cut(v, "-")
	if !ok || base == "" {
		return v
	}
	if lsioBuild.MatchString(suffix) {
		return base
	}
	if !variantSuffix.MatchString(suffix) {
		return v
	}
	switch strings.ToLower(suffix) {
	case "alpha", "beta", "rc", "pre", "preview", "dev", "nightly", "snapshot", "next", "canary", "unstable":
		return v
	}
	return base
}

var (
	lsioBuild     = regexp.MustCompile(`^ls\d+$`)
	variantSuffix = regexp.MustCompile(`^[A-Za-z]+(?:[-.][A-Za-z]+)*$`)
)

// tagMatch applies the tag steps of the app's version chain to a tag.
func tagMatch(spec catalog.VersionSpec, lsio bool, tag string) (string, bool) {
	for _, s := range chain(spec, lsio) {
		if s.label != "" || s.re == nil {
			continue
		}
		m := s.re.FindStringSubmatch(tag)
		if m == nil && s.normaliser != "" {
			if n, ok := version.Normalise(s.normaliser, tag); ok {
				m = s.re.FindStringSubmatch(n)
			}
		}
		if m != nil {
			return m[s.re.SubexpIndex("v")], true
		}
	}
	return "", false
}

func resolveContainerVersion(r *Result, app *catalog.App, labels map[string]string, ref imageref.Ref, haveRef bool, c *inventory.Container) {
	spec := app.Version
	var reasons []string

	// Manual override: the user states the version; other sources are
	// recorded but cannot contradict it.
	if v := strings.TrimSpace(labels[LabelVersion]); v != "" {
		if canon, ok := parse(spec, v, ""); ok {
			r.Version, r.VersionRaw, r.VersionSource, r.Trust = canon, v, "label "+LabelVersion, Confirmed
			r.Evidence = append(r.Evidence, Evidence{Method: "label " + LabelVersion, Raw: v, Version: canon, Used: true})
			return
		}
		r.Evidence = append(r.Evidence, Evidence{Method: "label " + LabelVersion, Raw: v})
		reasons = append(reasons, "label "+LabelVersion+"="+v+" is not a valid "+string(spec.Scheme)+" version")
	}
	// devBuild is set when the version comes from the app's manifest in an
	// image built from a development branch.
	devBuild := ""
	// Every source of the chain is read; the first valid one gives the
	// version, the others must agree with it.
	defer func() {
		if r.Version == "" {
			return
		}
		r.Trust = Confirmed
		for _, e := range r.Evidence {
			if e.Version != "" && !consistent(e.Version, r.Version) {
				r.Trust = Conflict
				r.Note = joinNote(r.Note, "sources disagree on the version: "+describeEvidence(r.Evidence)+"; set "+LabelVersion+" to settle it")
				return
			}
		}
		if devBuild != "" {
			// A development build runs code past the release its manifest
			// names; fixes may already be in, so it cannot be affected.
			r.Trust = Reported
			r.Note = joinNote(r.Note, "tag "+devBuild+" follows a development branch; the manifest names the last version, the code may be newer")
		}
	}()

	lsio := haveRef && app.ImageFlavor(ref.Repository) == "lsio"
	for _, s := range chain(spec, lsio) {
		var raw, source string
		switch {
		case s.label != "":
			raw, source = strings.TrimSpace(labels[s.label]), "image label "+s.label
			if raw == "" {
				continue
			}
		case haveRef && ref.Tag != "":
			source = "tag " + ref.Tag
			if version.IsFloating(ref.Tag) {
				reasons = append(reasons, "tag "+ref.Tag+" is floating")
				continue
			}
			m := s.re.FindStringSubmatch(ref.Tag)
			if m == nil && s.normaliser != "" {
				// App patterns describe upstream tags; distributors such
				// as linuxserver.io wrap them ("12.4ubu2604-ls58").
				if n, ok := version.Normalise(s.normaliser, ref.Tag); ok {
					m = s.re.FindStringSubmatch(n)
				}
			}
			if m == nil {
				reasons = append(reasons, "tag "+ref.Tag+" does not match the version pattern")
				continue
			}
			raw = m[s.re.SubexpIndex("v")]
		default:
			continue
		}
		if canon, ok := parse(spec, raw, s.normaliser); ok {
			r.Evidence = append(r.Evidence, Evidence{Method: source, Raw: raw, Version: canon, Used: r.Version == ""})
			if r.Version == "" {
				r.Version, r.VersionRaw, r.VersionSource = canon, raw, source
			}
			continue
		}
		r.Evidence = append(r.Evidence, Evidence{Method: source, Raw: raw})
		reasons = append(reasons, source+" value "+quote(raw)+" is not a valid "+string(spec.Scheme)+" version")
	}
	// The registry says which version tag has the running digest: an
	// observation like the others, from the publisher's own tag.
	if haveRef && c != nil && c.ResolvedTag != "" {
		if raw, ok := tagMatch(spec, lsio, c.ResolvedTag); ok {
			if canon, ok := parse(spec, variantBase(raw), ""); ok {
				source := "registry: tag " + c.ResolvedTag + " points to the running image"
				r.Evidence = append(r.Evidence, Evidence{Method: source, Raw: c.ResolvedTag, Version: canon, Used: r.Version == ""})
				if r.Version == "" {
					r.Version, r.VersionRaw, r.VersionSource = canon, raw, source
				}
			}
		}
	}
	// A package of the app's own project in the image states the installed
	// release, as the publisher's label or tag does. Distribution packages
	// are skipped: backports keep the upstream version (ADR 0008).
	if c != nil {
		for _, p := range c.Packages {
			for _, m := range app.Packages {
				if m.Manager != p.Manager || m.Name != p.Name || !m.Upstream() {
					continue
				}
				source := "package " + p.Manager + " " + p.Name + " in the image"
				if changedInside(c, packageDB[p.Manager]) {
					r.Evidence = append(r.Evidence, Evidence{Method: source + ", database changed inside the container", Raw: p.Version})
					reasons = append(reasons, "the package database was changed inside the container")
					continue
				}
				canon, ok := upstreamVersion(app, m, p.Version)
				if !ok {
					r.Evidence = append(r.Evidence, Evidence{Method: source, Raw: p.Version})
					continue
				}
				r.Evidence = append(r.Evidence, Evidence{Method: source, Raw: p.Version, Version: canon, Used: r.Version == ""})
				if r.Version == "" {
					r.Version, r.VersionRaw, r.VersionSource = canon, p.Version, source
				}
			}
		}
	}
	// The app's own package.json in the image's working directory names
	// the release the image was built from. It must carry the app's name:
	// a base image's or a dependency's manifest says nothing about it.
	if c != nil {
		for _, p := range c.Packages {
			if p.Manager != "npm" || path.Base(p.Path) != "package.json" || !manifestOf(app, p.Name) {
				continue
			}
			source := "manifest " + p.Path
			if changedInside(c, p.Path) {
				r.Evidence = append(r.Evidence, Evidence{Method: source + ", changed inside the container", Raw: p.Version})
				reasons = append(reasons, p.Path+" was changed inside the container")
				continue
			}
			canon, ok := parse(spec, strings.TrimPrefix(p.Version, "v"), "")
			if !ok {
				r.Evidence = append(r.Evidence, Evidence{Method: source, Raw: p.Version})
				reasons = append(reasons, source+" value "+quote(p.Version)+" is not a valid "+string(spec.Scheme)+" version")
				continue
			}
			r.Evidence = append(r.Evidence, Evidence{Method: source, Raw: p.Version, Version: canon, Used: r.Version == ""})
			if r.Version == "" {
				r.Version, r.VersionRaw, r.VersionSource = canon, p.Version, source
				if haveRef && version.IsDevelopment(ref.Tag) {
					devBuild = ref.Tag
				}
			}
		}
	}
	if r.Version != "" {
		return
	}

	if haveRef && ref.Tag == "" && ref.Digest != "" {
		reasons = append(reasons, "pinned by digest only")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no version source available")
	}
	r.Note = joinNote("version unknown: "+strings.Join(reasons, "; "), "set label "+LabelVersion+" to pin it")
}

// chain returns the extraction steps for an app, applying defaults.
func chain(spec catalog.VersionSpec, lsio bool) []step {
	if len(spec.Sources) > 0 {
		out := make([]step, 0, len(spec.Sources))
		for _, s := range spec.Sources {
			st := step{label: s.Label, normaliser: s.Normaliser, re: s.TagRegexp()}
			if lsio && st.normaliser == "" {
				st.normaliser = version.NormaliserLSIO
			}
			out = append(out, st)
		}
		return out
	}
	if lsio {
		return []step{
			{label: labelLSIOBuild, normaliser: version.NormaliserLSIO},
			{tag: "default", re: lsioTag, normaliser: version.NormaliserLSIO},
		}
	}
	tagRE := defaultSemverTag
	if spec.Scheme == version.CalVer {
		tagRE = defaultCalverTag
	}
	return []step{
		{label: LabelOCIVer},
		{tag: "default", re: tagRE},
	}
}

// parse normalises raw and parses it under the app's scheme. Values without
// at least two numeric components are rejected: a bare "2" or "main" never
// identifies a release.
func parse(spec catalog.VersionSpec, raw, normaliser string) (string, bool) {
	s, ok := version.Normalise(normaliser, raw)
	if !ok {
		return "", false
	}
	if p := spec.Normalise.StripPrefix; p != "" {
		s = strings.TrimPrefix(s, p)
	}
	v, err := version.Parse(spec.Scheme, s)
	if err != nil || v.Components() < 2 {
		return "", false
	}
	return v.String(), true
}

func identifyManual(cat *catalog.Catalog, w inventory.Workload) Result {
	m := w.Manual
	if m == nil {
		return Result{Confidence: None, Note: "no manual data"}
	}
	app, ok := cat.App(m.AppID)
	if !ok {
		return Result{Confidence: None, Note: "app " + m.AppID + " is not in the catalog"}
	}
	r := Result{AppID: app.ID, Confidence: Exact, Rule: "manual entry"}
	if canon, ok := parse(app.Version, m.Version, ""); ok {
		r.Version, r.VersionRaw, r.VersionSource, r.Trust = canon, m.Version, "manual entry", Confirmed
		r.Evidence = []Evidence{{Method: "manual entry", Raw: m.Version, Version: canon, Used: true}}
	} else {
		r.Note = "version unknown: " + quote(m.Version) + " is not a valid " + string(app.Version.Scheme) + " version"
	}
	return r
}

func identifyPackage(cat *catalog.Catalog, w inventory.Workload) Result {
	p := w.Package
	if p == nil {
		return Result{Confidence: None, Note: "no package data"}
	}
	if p.System {
		return identifySystemPackage(*p)
	}
	app, m, ok := cat.ByPackage(p.Manager, p.Name)
	if !ok {
		return Result{Confidence: None, Note: "package not in catalog"}
	}
	r := Result{AppID: app.ID, Confidence: Exact, Rule: "package " + p.Manager + " " + p.Name}
	if dp := DistroPackage(m, *p); dp != nil {
		source := "package " + p.Manager + " " + p.Name + " (" + dp.Ecosystem + ")"
		r.DistroPackage, r.VersionRaw, r.VersionSource, r.Trust = dp, p.Version, source, Confirmed
		r.Evidence = []Evidence{{Method: source, Raw: p.Version, Used: true}}
		r.Note = "distribution package: compared with the " + dp.Ecosystem + " security data, which knows its backported fixes"
		return r
	}
	if !m.Upstream() {
		// Distributions backport fixes and keep the upstream version, so
		// comparing it with advisory ranges would raise false alarms.
		r.Note = "version not comparable: " + p.Name + " " + quote(p.Version) + " is a distribution package; distributions backport fixes without changing the version"
		return r
	}
	if canon, ok := upstreamVersion(app, m, p.Version); ok {
		r.Version, r.VersionRaw, r.VersionSource, r.Trust = canon, p.Version, "package version", Confirmed
		r.Evidence = []Evidence{{Method: "package " + p.Manager + " " + p.Name, Raw: p.Version, Version: canon, Used: true}}
		return r
	}
	r.Note = "version unknown: package version " + quote(p.Version) + " not comparable"
	return r
}

// packageDB is the database file of each package manager read from images.
var packageDB = map[string]string{"dpkg": "/var/lib/dpkg/status", "apk": "/lib/apk/db/installed"}

// changedInside reports whether file was changed inside the container: the
// image's copy, which the evidence comes from, does not describe it.
func changedInside(c *inventory.Container, file string) bool {
	for _, f := range c.ChangedFiles {
		if file != "" && f == file {
			return true
		}
	}
	return false
}

// manifestOf reports whether a manifest name ("uptime-kuma",
// "@scope/name") names app: its ID, its name, an alias or the repository of
// its source.
func manifestOf(app *catalog.App, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "@") {
		_, name, _ = strings.Cut(name, "/")
	}
	if name == "" {
		return false
	}
	names := append([]string{app.ID, strings.ReplaceAll(strings.ToLower(app.Name), " ", "-")}, app.Aliases...)
	for _, src := range app.OCISource {
		names = append(names, path.Base(strings.TrimSuffix(strings.TrimSuffix(src, "/"), ".git")))
	}
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// DistroPackage returns the distribution package to check for a package
// of a catalog app: a distribution-versioned package of a release with
// security data whose package manager fits the release; nil otherwise.
func DistroPackage(m catalog.Package, p inventory.Package) *distro.Package {
	if m.Upstream() || p.Version == "" {
		return nil
	}
	eco, manager, ok := distro.Ecosystem(p.Distro)
	if !ok || manager != p.Manager || distro.Foreign(eco, p.Version) {
		return nil
	}
	name := m.SourceName()
	if distro.BinaryNamed(eco) {
		// The RPM distributions' data names the installed binary.
		name = p.Name
	}
	return &distro.Package{Ecosystem: eco, Name: name, Version: p.Version}
}

// DistroPackages lists the distribution packages of catalog apps among ws,
// with the app each belongs to.
func DistroPackages(cat *catalog.Catalog, ws []inventory.Workload) map[string][]distro.Package {
	out := map[string][]distro.Package{}
	for _, w := range ws {
		if w.Kind != inventory.KindPackage || w.Package == nil || w.RemovedAt != nil || w.Package.System {
			continue
		}
		app, m, ok := cat.ByPackage(w.Package.Manager, w.Package.Name)
		if !ok {
			continue
		}
		if dp := DistroPackage(m, *w.Package); dp != nil {
			out[app.ID] = append(out[app.ID], *dp)
		}
	}
	return out
}

// upstreamVersion is the canonical release version of an upstream package.
func upstreamVersion(app *catalog.App, m catalog.Package, pkgVersion string) (string, bool) {
	raw, ok := m.Release(pkgVersion)
	if !ok && m.VersionPattern == "" {
		// Epochs and revisions ("1:2.0.18-1") are not part of the release.
		raw, ok = distroUpstream(pkgVersion), true
	}
	if !ok {
		return "", false
	}
	return parse(app.Version, raw, "")
}

func identifyService(cat *catalog.Catalog, w inventory.Workload) Result {
	s := w.Service
	if s == nil {
		return Result{Confidence: None, Note: "no service data"}
	}
	app, ok := cat.ByService(s.Unit)
	if !ok {
		return Result{Confidence: None, Note: "service not in catalog"}
	}
	r := Result{AppID: app.ID, Confidence: Strong, Rule: "systemd unit " + s.Unit}
	if s.Version != "" {
		if canon, ok := parse(app.Version, s.Version, ""); ok {
			r.Version, r.VersionRaw, r.VersionSource, r.Trust = canon, s.Version, "service", Reported
			r.Evidence = []Evidence{{Method: "systemd unit " + s.Unit, Raw: s.Version, Version: canon, Used: true}}
			return r
		}
	}
	r.Note = "version unknown: a systemd unit carries no version; read the package instead"
	return r
}

// identifyEndpoint: the response proved it comes from the app (catalog
// expect fields), and the version is the one the app reported itself.
func identifyEndpoint(cat *catalog.Catalog, w inventory.Workload) Result {
	e := w.Endpoint
	if e == nil {
		return Result{Confidence: None, Note: "no endpoint data"}
	}
	app, ok := cat.App(e.AppID)
	if !ok {
		return Result{Confidence: None, Note: "app " + e.AppID + " is not in the catalog"}
	}
	r := Result{AppID: app.ID, Confidence: Exact, Rule: "version endpoint " + e.URL}
	if canon, ok := parse(app.Version, e.Version, ""); ok {
		// The response is not authenticated: a device on the LAN can claim
		// any version, so it never produces affected findings on its own.
		r.Version, r.VersionRaw, r.VersionSource, r.Trust = canon, e.Version, "the version endpoint "+e.URL, Reported
		r.Evidence = []Evidence{{Method: "version endpoint " + e.URL, Raw: e.Version, Version: canon, Used: true}}
	} else {
		r.Note = "version unknown: the app reported " + quote(e.Version) + ", not a valid " + string(app.Version.Scheme) + " version"
	}
	return r
}

// distroUpstream strips a Debian/RPM epoch and revision.
func distroUpstream(v string) string {
	if _, rest, ok := strings.Cut(v, ":"); ok {
		v = rest
	}
	if i := strings.LastIndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	return v
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

func quote(s string) string {
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return `"` + s + `"`
}

// identifySystemPackage identifies a system package as itself: it needs no
// catalog entry, its distribution's security data names it (ADR 0032).
func identifySystemPackage(p inventory.Package) Result {
	eco, manager, ok := distro.Ecosystem(p.Distro)
	if !ok || manager != p.Manager || p.Version == "" || distro.Foreign(eco, p.Version) {
		return Result{Confidence: None, Note: "system package without distribution security data"}
	}
	source := "package database (" + eco + ")"
	return Result{
		AppID: distro.SystemAppID(eco, p.Name), Confidence: Exact, Rule: "system package " + p.Name,
		VersionRaw: p.Version, VersionSource: source, Trust: Confirmed,
		Evidence:      []Evidence{{Method: source, Raw: p.Version, Used: true}},
		DistroPackage: &distro.Package{Ecosystem: eco, Name: p.Name, Version: p.Version},
		Note:          "system package: compared with the " + eco + " security data",
	}
}

// IsSystem reports whether a workload is a system package (ADR 0032).
func IsSystem(w inventory.Workload) bool { return w.Package != nil && w.Package.System }

// SystemPackages lists the system packages among ws as distribution
// packages, once per ecosystem, name and version.
func SystemPackages(ws []inventory.Workload) []distro.Package {
	seen := map[distro.Package]bool{}
	var out []distro.Package
	for _, w := range ws {
		if w.RemovedAt != nil || !IsSystem(w) {
			continue
		}
		r := identifySystemPackage(*w.Package)
		if r.DistroPackage == nil || seen[*r.DistroPackage] {
			continue
		}
		seen[*r.DistroPackage] = true
		out = append(out, *r.DistroPackage)
	}
	return out
}

// ImageCheckedPackages are the packages of a container's image checked
// against security data: its distribution's source packages and the
// dependencies of its app, Go modules and npm packages (ADR 0033).
func ImageCheckedPackages(c *inventory.Container) []distro.Package {
	return append(ImageSystemPackages(c), ImageLanguagePackages(c)...)
}

// ImageLanguagePackages are the Go modules and Rust crates of the programs
// a container's image runs, the npm packages of its app's lock file, and
// the Python, PHP, Ruby, .NET and Java packages its apps install.
func ImageLanguagePackages(c *inventory.Container) []distro.Package {
	if c == nil {
		return nil
	}
	seen := map[distro.Package]bool{}
	var out []distro.Package
	for _, p := range c.Packages {
		pkg, ok := languagePackage(p)
		if !ok {
			continue
		}
		if _, ok := distro.Compare(pkg.Ecosystem, pkg.Version, pkg.Version); !ok || seen[pkg] || changedInside(c, p.Path) {
			continue
		}
		seen[pkg] = true
		out = append(out, pkg)
		if len(out) == MaxImagePackages {
			break
		}
	}
	return out
}

// languagePackage is a package of an image read as the language package
// it is; ok is false for system packages and metadata Varde does not check.
func languagePackage(p inventory.Package) (distro.Package, bool) {
	switch {
	case p.Manager == "go" && p.Path != "":
		return distro.Package{Ecosystem: "Go", Name: p.Name, Version: strings.TrimPrefix(p.Version, "v")}, true
	case p.Manager == "npm" && path.Base(p.Path) == "package-lock.json":
		return distro.Package{Ecosystem: "npm", Name: p.Name, Version: p.Version}, true
	case p.Path != "" && languageEcosystem[p.Manager] != "":
		return distro.Package{Ecosystem: languageEcosystem[p.Manager], Name: p.Name, Version: p.Version}, true
	}
	return distro.Package{}, false
}

// ImagePackageNames are the "Ecosystem/name" keys of every package an
// image lists, before the checked lists drop builds from outside the
// distribution, versions that do not compare and packages past a bound. A
// system package counts under its own name and its source's. Only a
// package missing here is missing from the image (remedy.ReleaseFixFor).
func ImagePackageNames(c *inventory.Container) map[string]bool {
	out := map[string]bool{}
	if c == nil {
		return out
	}
	eco, _, system := distro.Ecosystem(c.Distro)
	for _, p := range c.Packages {
		if p.Path == "" {
			if system {
				out[eco+"/"+p.Name] = true
				if p.Source != "" {
					out[eco+"/"+p.Source] = true
				}
			}
			continue
		}
		if pkg, ok := languagePackage(p); ok {
			out[pkg.Ecosystem+"/"+pkg.Name] = true
		}
	}
	return out
}

// languageEcosystem maps the package managers whose metadata Varde reads
// in images to their OSV ecosystems.
var languageEcosystem = map[string]string{
	"pip": "PyPI", "composer": "Packagist", "gem": "RubyGems", "nuget": "NuGet", "maven": "Maven", "cargo": "crates.io",
}

// MaxImagePackages bounds the source packages checked per image, and
// separately its language packages. A list cut at it may lack a package
// the image has (remedy.ReleaseFixFor).
const MaxImagePackages = 5000

// ImageSystemPackages are the source packages of a container's image on a
// release with distribution security data, at the highest version among
// their binary packages (ADR 0033). Builds from outside the distribution
// and app manifests are left out.
func ImageSystemPackages(c *inventory.Container) []distro.Package {
	if c == nil {
		return nil
	}
	var pkgs []distro.Installed
	for _, p := range c.Packages {
		if p.Path == "" {
			pkgs = append(pkgs, distro.Installed{Manager: p.Manager, Name: p.Name, Version: p.Version, Source: p.Source, SourceVersion: p.SourceVersion})
		}
	}
	out := distro.Checked(c.Distro, pkgs, distro.CheckOptions{Image: true})
	if len(out) > MaxImagePackages {
		out = out[:MaxImagePackages]
	}
	return out
}
