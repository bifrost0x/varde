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
}

// Pull is the command that fetches the new image and recreates the service.
// The service name follows the Compose grammar (checked in compose) and is
// quoted besides: the labels come from the image, and users paste this.
func (c *Compose) Pull() string {
	q := "'" + c.Service + "'"
	return "docker compose pull " + q + " && docker compose up -d " + q
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
	if plainPath(labels[labelWorkingDir]) {
		c.Dir = labels[labelWorkingDir]
	}
	for _, f := range strings.Split(labels[labelConfigFiles], ",") {
		if f = strings.TrimSpace(f); plainPath(f) {
			c.Files = append(c.Files, f)
		}
	}
	return c
}

// plainPath accepts an absolute Unix or Windows path without control or
// shell characters.
func plainPath(p string) bool {
	if p == "" || len(p) > 512 || (!strings.HasPrefix(p, "/") && !windowsPath.MatchString(p)) {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || strings.ContainsRune("`$;&|<>\"'*?!\n", r) && r != '\\' {
			return false
		}
	}
	return true
}

var windowsPath = regexp.MustCompile(`^[A-Za-z]:\\`)
