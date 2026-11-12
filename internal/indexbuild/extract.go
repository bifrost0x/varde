// SPDX-License-Identifier: Apache-2.0

// Package indexbuild builds the first-party index (ADR 0038, stage 2b): a
// table of image repositories and the GitHub repositories of their
// projects, in which every row rests on what the project or the registry
// states itself. cmd/indexbuilder runs it; the result is committed as
// index/images.tsv and embedded in the binary.
package indexbuild

import (
	"regexp"
	"strings"

	"github.com/bifrost0x/varde/internal/applists"
)

// maxImagesPerText bounds what one README or Compose file contributes.
const maxImagesPerText = 20

var (
	// pullCmd is "docker pull <image>" (or podman).
	pullCmd = regexp.MustCompile(`(?m)\b(?:docker|podman)\s+pull\s+(\S+)`)
	// runCmd is the arguments of "docker run", with line continuations.
	runCmd = regexp.MustCompile(`(?m)\b(?:docker|podman)\s+run\b((?:[^\n\\]|\\\n|\\.)*)`)
	// composeImage is an "image:" key of a Compose service.
	composeImage = regexp.MustCompile(`(?m)^[ \t]+image:[ \t]*["']?([^"'\s#]+)`)
	// githubLink is a link to a repository in free text.
	githubLink = regexp.MustCompile(`(?i)https?://(?:www\.)?github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}`)
)

// booleanFlags are options of "docker run" that take no value.
var booleanFlags = map[string]bool{
	"-d": true, "--detach": true, "--rm": true, "-i": true, "-t": true, "-it": true, "-ti": true, "-dit": true, "-itd": true,
	"--init": true, "--privileged": true, "-P": true, "--publish-all": true, "--read-only": true, "--interactive": true, "--tty": true,
}

// ImagesIn returns the image repositories a README or Compose file names
// as something to run: the argument of "docker pull", the image of "docker
// run" and the "image:" keys of Compose services. Images mentioned in
// prose, base images of a FROM line, placeholders, and helper or official
// images (a database beside the app) are left out. The result is in order
// of first appearance, without duplicates, and bounded.
func ImagesIn(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var out []string
	seen := map[string]bool{}
	take := func(ref string) {
		if len(out) >= maxImagesPerText || strings.ContainsAny(ref, "<>{}[]()`*") {
			return
		}
		image, ok := applists.NormaliseImage(strings.Trim(ref, `"',;`))
		if !ok || seen[image] || applists.IsHelper(image) || placeholder(image) {
			return
		}
		seen[image] = true
		out = append(out, image)
	}
	type hit struct {
		pos int
		ref string
	}
	var hits []hit
	for _, m := range pullCmd.FindAllStringSubmatchIndex(text, -1) {
		hits = append(hits, hit{m[0], text[m[2]:m[3]]})
	}
	for _, m := range runCmd.FindAllStringSubmatchIndex(text, -1) {
		if ref := runImage(text[m[2]:m[3]]); ref != "" {
			hits = append(hits, hit{m[0], ref})
		}
	}
	for _, m := range composeImage.FindAllStringSubmatchIndex(text, -1) {
		hits = append(hits, hit{m[0], text[m[2]:m[3]]})
	}
	// In order of appearance, so the bound keeps the first ones.
	for i := 1; i < len(hits); i++ {
		for j := i; j > 0 && hits[j].pos < hits[j-1].pos; j-- {
			hits[j], hits[j-1] = hits[j-1], hits[j]
		}
	}
	for _, h := range hits {
		take(h.ref)
	}
	return out
}

// runImage finds the image among the arguments of "docker run": the first
// argument that is neither an option nor the value of one.
func runImage(args string) string {
	fields := strings.Fields(strings.ReplaceAll(args, "\\\n", " "))
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if f == "\\" {
			continue
		}
		if !strings.HasPrefix(f, "-") {
			return f
		}
		if booleanFlags[f] || strings.Contains(f, "=") {
			continue
		}
		i++ // the option's value
	}
	return ""
}

// LinksRepo reports whether a text (the description of an image on Docker
// Hub) links the repository "github.com/<owner>/<name>" itself; a link to
// another repository of the same owner does not count.
func LinksRepo(description, repo string) bool {
	for _, link := range githubLink.FindAllString(description, -1) {
		if got, ok := applists.NormaliseRepo(link); ok && got == repo {
			return true
		}
	}
	return false
}

// placeholderNamespaces stand for "your account" in examples.
var placeholderNamespaces = map[string]bool{
	"owner": true, "my": true, "user": true, "username": true, "yourusername": true, "your-username": true, "yourname": true,
	"youruser": true, "example": true, "myuser": true, "me": true, "org": true, "yourorg": true, "namespace": true,
}

// placeholder reports an image reference of an example, not of a real
// image: a stand-in namespace, or a registry on the reader's own machine.
func placeholder(image string) bool {
	segs := strings.Split(image, "/")
	if strings.HasPrefix(segs[0], "localhost") || strings.HasPrefix(segs[0], "127.") {
		return true
	}
	return len(segs) >= 3 && placeholderNamespaces[segs[1]]
}
