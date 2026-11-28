// SPDX-License-Identifier: Apache-2.0

// Package remedy derives the concrete update for a container with affected
// findings: the release tag that fixes them, in the form of the tag the
// container runs, and for Compose services the line to change and the
// commands that apply it (ADR 0029). It only suggests; Varde never changes
// a host.
package remedy

import (
	"regexp"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/version"
)

// Compose labels Docker Compose sets on every container it creates.
const (
	labelProject     = "com.docker.compose.project"
	labelService     = "com.docker.compose.service"
	labelWorkingDir  = "com.docker.compose.project.working_dir"
	labelConfigFiles = "com.docker.compose.project.config_files"
	labelEnvFiles    = "com.docker.compose.project.environment_file"
)

// Suggestion is how to update one container.
type Suggestion struct {
	// Image is the reference to run ("ghcr.io/x/y:v1.2.4"), Tag its tag.
	Image, Tag string
	// Verified is set when the registry lists the tag.
	Verified bool
	// Floating is set when the container runs a floating tag ("latest"):
	// pulling it again may bring the fix; the version must be checked.
	Floating bool
	// Compose is set for containers created by Docker Compose.
	Compose *Compose
}

// Compose names where a Compose service is defined.
type Compose struct {
	Project, Service, Dir string
	Files                 []string
	// EnvFiles are the environment files the project was started with,
	// as Compose records them.
	EnvFiles []string
	// Portainer is the ID of the Portainer stack the service belongs to,
	// "" when Portainer did not deploy it: Portainer keeps a stack's files
	// in its own volume, so the stack is updated in Portainer, not with a
	// command on the host.
	Portainer string
	// partial is set when a recorded path was refused (plainPath): a
	// command without it could start the service differently, so there is
	// none.
	partial bool
}

// Pull is the command that fetches the new image and recreates the
// service, runnable from any directory of the host: it changes to the
// project directory and names the project and its files where they differ
// from what Compose would assume there. The names follow the Compose
// grammar and the paths are plain (checked in compose); everything is
// quoted besides, since the labels come from the image and users paste
// this.
func (c *Compose) Pull() string {
	if c.partial {
		return ""
	}
	return c.inDir(c.command("pull") + " && " + c.command("up -d"))
}

// Rebuild is the command that builds the service's image again, with the
// newest base image, and recreates the service: the fix for an image built
// from a local Dockerfile.
func (c *Compose) Rebuild() string {
	if c.partial {
		return ""
	}
	return c.inDir(c.command("build --pull --no-cache") + " && " + c.command("up -d"))
}

func (c *Compose) inDir(cmd string) string {
	if c.Dir == "" {
		return cmd
	}
	return "cd " + shellQuote(c.Dir) + " && " + cmd
}

// command is one docker compose command for the service.
func (c *Compose) command(verb string) string {
	var b strings.Builder
	b.WriteString("docker compose")
	if c.Dir != "" {
		// From the project directory Compose takes its name for the
		// project and looks for one of the default files.
		if c.Project != defaultProject(c.Dir) {
			b.WriteString(" -p " + shellQuote(c.Project))
		}
		// The files exactly as recorded, also a single default one:
		// without -f Compose would add an override file the project may
		// have been started without.
		files := c.relative(c.Files)
		for _, f := range files {
			b.WriteString(" -f " + shellQuote(f))
		}
		// Compose resolves relative paths from the first file's directory
		// unless told otherwise: a project started with another project
		// directory keeps it.
		if len(files) > 0 && strings.ContainsAny(files[0], "/\\") {
			b.WriteString(" --project-directory " + shellQuote(c.Dir))
		}
		// Variables from another file than .env would be missing, and
		// the service recreated with other values.
		if env := c.relative(c.EnvFiles); len(env) > 1 || len(env) == 1 && env[0] != ".env" {
			for _, f := range env {
				b.WriteString(" --env-file " + shellQuote(f))
			}
		}
	}
	b.WriteString(" " + verb + " " + shellQuote(c.Service))
	return b.String()
}

// relative are paths relative to the project directory when they lie in
// it.
func (c *Compose) relative(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, f := range paths {
		rel := f
		for _, sep := range []string{"/", "\\"} {
			if r, ok := strings.CutPrefix(f, strings.TrimRight(c.Dir, sep)+sep); ok && r != "" {
				rel = r
				break
			}
		}
		out = append(out, rel)
	}
	return out
}

// defaultProject is the project name Compose derives from a directory: its
// base name in lower case, without characters a project name cannot hold.
func defaultProject(dir string) string {
	base := dir
	if i := strings.LastIndexAny(strings.TrimRight(dir, "/\\"), "/\\"); i >= 0 {
		base = strings.TrimRight(dir, "/\\")[i+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// shellQuote quotes s for a POSIX shell; PowerShell reads the same quotes.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// portainerDir is where Portainer keeps the files of a stack.
var portainerDir = regexp.MustCompile(`^/data/compose/(\d{1,9})(?:/.*)?$`)

// Unraid reports whether Unraid's Docker manager created the container:
// it is updated on Unraid's Docker page.
func Unraid(c *inventory.Container) bool {
	return c != nil && c.Labels["net.unraid.docker.managed"] == "dockerman"
}

// Suggest returns the update of container c of app to target (a canonical
// version), using the repository's release tags when known. ok is false
// when nothing concrete can be said.
func Suggest(app *catalog.App, c *inventory.Container, target string, tags []string) (Suggestion, bool) {
	if app == nil || c == nil || target == "" {
		return Suggestion{}, false
	}
	ref, err := imageref.Parse(c.ImageRef)
	if err != nil || ref.Digest != "" && ref.Tag == "" {
		return Suggestion{}, false
	}
	// The app as identify read this image (a generated entry's tag rule
	// only for the images the generator checked).
	app = identify.AppForImage(app, ref.Repository)
	s := Suggestion{Compose: compose(c.Labels)}
	if ref.Tag == "" || version.IsFloating(ref.Tag) {
		s.Floating = true
		return s, true
	}
	running, ok := identify.TagRelease(app, ref.Repository, ref.Tag)
	if !ok {
		return Suggestion{}, false
	}
	prefix, suffix, ok := template(ref.Tag, running)
	if !ok {
		return Suggestion{}, false
	}
	if tag, ok := pick(app, ref.Repository, tags, target, prefix, suffix, strings.Contains(running, "-")); ok {
		s.Tag, s.Verified = tag, true
	} else if !buildNumber.MatchString(suffix) {
		// No tag list: the tag in the running form, not verified. A build
		// number (linuxserver.io "-ls250") cannot be guessed.
		s.Tag = prefix + target + suffix
	} else {
		return Suggestion{}, false
	}
	s.Image = imageName(c.ImageRef) + ":" + s.Tag
	// Tags from a registry and references from a container are untrusted
	// and end up in a line users paste: both must follow the OCI grammar.
	if !ociTag.MatchString(s.Tag) || !ociName.MatchString(imageName(c.ImageRef)) {
		return Suggestion{}, false
	}
	return s, true
}

var (
	ociTag  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	ociName = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
)

// template splits a tag around the version it names ("v1.2.3-alpine" →
// "v", "-alpine").
func template(tag, canonical string) (prefix, suffix string, ok bool) {
	i := strings.Index(tag, canonical)
	if i < 0 {
		return "", "", false
	}
	return tag[:i], tag[i+len(canonical):], true
}

// buildNumber matches suffixes that carry a build of the distributor.
var buildNumber = regexp.MustCompile(`ls\d+`)

// suffixClass makes build numbers comparable: "-ls250" and "-ls251" are
// the same variant.
func suffixClass(s string) string { return buildNumber.ReplaceAllString(s, "ls#") }

// pick returns the lowest release tag at or above target in the running
// form; among builds of that release, the newest. Pre-releases count only
// for a container that runs one.
func pick(app *catalog.App, repository string, tags []string, target, prefix, suffix string, preRelease bool) (string, bool) {
	want, err := version.Parse(app.Version.Scheme, target)
	if err != nil {
		return "", false
	}
	type cand struct {
		tag string
		v   version.Version
	}
	var cs []cand
	for _, t := range tags {
		canon, ok := identify.TagRelease(app, repository, t)
		if !ok {
			continue
		}
		p, s, ok := template(t, canon)
		if !ok || p != prefix || suffixClass(s) != suffixClass(suffix) {
			continue
		}
		// A pre-release is no fix for a stable release.
		if strings.Contains(canon, "-") && !preRelease {
			continue
		}
		v, err := version.Parse(app.Version.Scheme, canon)
		if err != nil {
			continue
		}
		if c, ok := v.Compare(want); !ok || c < 0 {
			continue
		}
		cs = append(cs, cand{t, v})
	}
	if len(cs) == 0 {
		return "", false
	}
	sort.Slice(cs, func(i, j int) bool {
		if c, _ := cs[i].v.Compare(cs[j].v); c != 0 {
			return c < 0
		}
		return buildOf(cs[i].tag) > buildOf(cs[j].tag)
	})
	return cs[0].tag, true
}

var buildDigits = regexp.MustCompile(`ls(\d+)`)

func buildOf(tag string) int {
	m := buildDigits.FindStringSubmatch(tag)
	if m == nil {
		return 0
	}
	n := 0
	for _, r := range m[1] {
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			break
		}
	}
	return n
}

// imageName is the reference without tag or digest, as the user wrote it.
func imageName(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		ref = ref[:i]
	}
	return ref
}

// Compose grammar: project names are lowercase letters, digits, dashes and
// underscores; service names add upper case and dots.
var (
	composeProject = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	composeService = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
)

// ComposeOf names where the Compose service of a container is defined; nil
// for containers not created by Compose.
func ComposeOf(c *inventory.Container) *Compose {
	if c == nil {
		return nil
	}
	return compose(c.Labels)
}

// Floating reports whether a container runs a tag that moves ("latest", no
// tag): pulling it again can bring a newer image without changing the line.
// A reference with a digest never moves, whatever tag stands beside it.
func Floating(c *inventory.Container) bool {
	if c == nil {
		return false
	}
	ref, err := imageref.Parse(c.ImageRef)
	return err == nil && ref.Digest == "" && (ref.Tag == "" || version.IsFloating(ref.Tag))
}

// Pinned reports whether a container is created from a digest: it keeps
// running that image until the digest in its definition is changed.
func Pinned(c *inventory.Container) bool {
	if c == nil {
		return false
	}
	ref, err := imageref.Parse(c.ImageRef)
	return err == nil && ref.Digest != ""
}

// compose reads where a Compose service is defined; nil for containers not
// created by Compose. The labels come from the image as well (an image can
// set any label), so they must follow the Compose grammar; paths are shown
// only when they are plain.
func compose(labels map[string]string) *Compose {
	service, project := labels[labelService], labels[labelProject]
	if !composeService.MatchString(service) || !composeProject.MatchString(project) {
		return nil
	}
	c := &Compose{Project: project, Service: service}
	if d := labels[labelWorkingDir]; plainPath(d) {
		c.Dir = d
	} else if d != "" {
		c.partial = true
	}
	if m := portainerDir.FindStringSubmatch(c.Dir); m != nil {
		c.Portainer = m[1]
	}
	for _, f := range strings.Split(labels[labelConfigFiles], ",") {
		if f = strings.TrimSpace(f); plainPath(f) {
			c.Files = append(c.Files, f)
		} else if f != "" {
			c.partial = true
		}
	}
	for _, f := range strings.Split(labels[labelEnvFiles], ",") {
		if f = strings.TrimSpace(f); plainPath(f) {
			c.EnvFiles = append(c.EnvFiles, f)
		} else if f != "" {
			c.partial = true
		}
	}
	return c
}

// plainPath accepts an absolute Unix or Windows path of printable ASCII
// without shell characters. Anything beyond ASCII is refused: PowerShell
// also ends a quoted string at the typographic quotes (U+2018 to U+201B),
// and bidirectional controls would make the command read differently
// from what runs.
func plainPath(p string) bool {
	if p == "" || len(p) > 512 || (!strings.HasPrefix(p, "/") && !windowsPath.MatchString(p)) {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r >= 0x7f || strings.ContainsRune("`$;&|<>\"'*?!\n", r) && r != '\\' {
			return false
		}
	}
	return true
}

var windowsPath = regexp.MustCompile(`^[A-Za-z]:\\`)

// Newer returns the newest stable release among the repository's release
// tags that is above the running version, "" when there is none or the
// versions cannot be compared. Pre-releases count only for a running
// pre-release.
func Newer(app *catalog.App, repository, running string, tags []string) string {
	if app == nil || repository == "" || running == "" || len(tags) == 0 {
		return ""
	}
	app = identify.AppForImage(app, repository)
	have, err := version.Parse(app.Version.Scheme, running)
	if err != nil {
		return ""
	}
	pre := strings.Contains(running, "-")
	var best version.Version
	for _, t := range tags {
		canon, ok := identify.TagRelease(app, repository, t)
		if !ok || (strings.Contains(canon, "-") && !pre) {
			continue
		}
		v, err := version.Parse(app.Version.Scheme, canon)
		if err != nil {
			continue
		}
		if c, ok := v.Compare(have); !ok || c <= 0 {
			continue
		}
		if best.IsZero() {
			best = v
		} else if c, ok := v.Compare(best); ok && c > 0 {
			best = v
		}
	}
	if best.IsZero() {
		return ""
	}
	return best.String()
}
