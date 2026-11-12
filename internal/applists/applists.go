// SPDX-License-Identifier: Apache-2.0

// Package applists reads public app store lists and holds the table type
// "image repository to GitHub repository" (ADR 0038). App stores of homelab
// systems publish, per app, the container image and the project it belongs
// to. Only the index builder reads them, once and centrally, as pointers
// to projects worth visiting (cmd/indexbuilder); what a list says is never
// taken as true and never shipped. An installation downloads no list.
package applists

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bifrost0x/varde/internal/imageref"
)

// Pair is one statement of a list: this image belongs to this repository.
type Pair struct {
	// Image is a normalised image repository (NormaliseImage).
	Image string
	// Repo is "github.com/<owner>/<name>" in lower case.
	Repo string
	// List names the list that states the pair.
	List string
}

// Entry is one row of the table.
type Entry struct {
	Image string
	Repo  string
	// Lists are the sorted names of the lists that state the pair.
	Lists []string
}

// Confirmed reports that at least two independent lists state the pair.
// One list alone is a report: its findings do not alert (ADR 0023).
func (e Entry) Confirmed() bool { return len(e.Lists) >= 2 }

// Table maps image repositories to source repositories.
type Table struct {
	entries []Entry // sorted by Image
}

// Len is the number of images in the table; a nil table is empty.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.entries)
}

// Lookup finds an image repository by its exact normalised form. The
// registry host is part of the key, so an image of the same name on another
// registry does not match.
func (t *Table) Lookup(imageRepository string) (Entry, bool) {
	if t == nil {
		return Entry{}, false
	}
	i := sort.Search(len(t.entries), func(i int) bool { return t.entries[i].Image >= imageRepository })
	if i < len(t.entries) && t.entries[i].Image == imageRepository {
		return t.entries[i], true
	}
	return Entry{}, false
}

var (
	repoForm  = regexp.MustCompile(`^github\.com/[a-z0-9-]{1,39}/[a-z0-9._-]{1,100}$`)
	listName  = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	githubURL = regexp.MustCompile(`^https?://(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$`)
)

// NormaliseImage returns the key form of an image reference: the
// repository as the inventory spells it (imageref.NormaliseRepository:
// registry explicit, lower case, Docker Hub official images under
// "library/", linuxserver.io mirrors folded onto lscr.io), without tag or
// digest. It reports false for anything that is not an image reference.
func NormaliseImage(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > 255 || strings.ContainsAny(ref, " \t\r\n$\"'") || strings.Contains(ref, "://") {
		return "", false
	}
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	// A colon in the last path segment starts the tag.
	if slash := strings.LastIndexByte(ref, '/'); strings.IndexByte(ref[slash+1:], ':') >= 0 {
		ref = ref[:slash+1+strings.IndexByte(ref[slash+1:], ':')]
	}
	repo, err := imageref.NormaliseRepository(ref)
	if err != nil {
		return "", false
	}
	return repo, true
}

// normaliseRepo returns "github.com/<owner>/<name>" for the URL of a GitHub
// repository itself. Links into a repository (a directory of a template
// collection, an issue) name something else and are refused.
func normaliseRepo(url string) (string, bool) {
	m := githubURL.FindStringSubmatch(strings.TrimSpace(url))
	if m == nil {
		return "", false
	}
	owner, name := strings.ToLower(m[1]), strings.ToLower(m[2])
	// Not repositories: GitHub's own paths, and names a repository cannot
	// have or that normalise onto another one.
	if reservedOwners[owner] || strings.Trim(name, ".") == "" || strings.HasSuffix(name, ".git") {
		return "", false
	}
	return "github.com/" + owner + "/" + name, true
}

// reservedOwners are first path segments of github.com that are not users
// or organisations.
var reservedOwners = map[string]bool{"orgs": true, "sponsors": true, "users": true, "apps": true, "marketplace": true, "topics": true, "settings": true}

// namedAlike reports whether a repository has the name of an image (their
// last path segments are equal).
func namedAlike(image, repo string) bool {
	return image[strings.LastIndexByte(image, '/')+1:] == repo[strings.LastIndexByte(repo, '/')+1:]
}

// helperNames are images that run beside an app, never the app itself.
var helperNames = map[string]bool{
	"postgres": true, "postgresql": true, "redis": true, "valkey": true, "mariadb": true, "mysql": true,
	"mongo": true, "mongodb": true, "nginx": true, "memcached": true, "busybox": true, "alpine": true,
	"traefik": true, "tor": true, "socat": true,
}

// isBase reports an official Docker Hub image. Lists name them beside the
// project a template belongs to (a database next to an app), so a list
// cannot tie them to a project; the catalog covers the ones that are apps.
func isBase(image string) bool { return strings.HasPrefix(image, "docker.io/library/") }

func isHelper(image string) bool {
	return isBase(image) || helperNames[image[strings.LastIndexByte(image, '/')+1:]]
}

// Build reduces the pairs of all lists to the table. It never guesses: an
// image that a list ties to several repositories, or that lists tie to
// different ones, is dropped, unless the image is on GitHub's registry and
// one of those repositories is its own path. Base and helper images are
// dropped: lists name them beside the project they serve. The second result names every
// dropped image with the reason.
func Build(pairs []Pair) (*Table, map[string]string) {
	// image -> list -> repositories
	byImage := map[string]map[string]map[string]bool{}
	for _, p := range pairs {
		lists := byImage[p.Image]
		if lists == nil {
			lists = map[string]map[string]bool{}
			byImage[p.Image] = lists
		}
		if lists[p.List] == nil {
			lists[p.List] = map[string]bool{}
		}
		lists[p.List][p.Repo] = true
	}
	t := &Table{}
	dropped := map[string]string{}
images:
	for image, lists := range byImage {
		if isBase(image) {
			dropped[image] = "base image"
			continue
		}
		if isHelper(image) {
			dropped[image] = "helper image"
			continue
		}
		names := make([]string, 0, len(lists))
		for l := range lists {
			names = append(names, l)
		}
		sort.Strings(names)
		// repository -> lists that state it
		stated := map[string][]string{}
		for _, l := range names {
			if len(lists[l]) > 1 {
				dropped[image] = "ambiguous in " + l
				continue images
			}
			for r := range lists[l] {
				stated[r] = append(stated[r], l)
			}
		}
		repo := ""
		if len(stated) == 1 {
			for r := range stated {
				repo = r
			}
		} else {
			// Lists disagree: only a repository that is the image path
			// itself (a renamed project's current home) settles it.
			// On GitHub's registry the namespace is the owner's; a Docker
			// Hub namespace is an unrelated account and settles nothing.
			own := ""
			if rest, ok := strings.CutPrefix(image, "ghcr.io/"); ok && strings.Count(rest, "/") == 1 {
				own = "github.com/" + rest
			}
			if _, ok := stated[own]; !ok {
				dropped[image] = "lists disagree"
				continue images
			}
			repo = own
		}
		t.entries = append(t.entries, Entry{Image: image, Repo: repo, Lists: stated[repo]})
	}
	sort.Slice(t.entries, func(i, j int) bool { return t.entries[i].Image < t.entries[j].Image })
	return t, dropped
}

// maxTableBytes bounds a stored table.
const maxTableBytes = 16 << 20

// Marshal writes the table as "image<TAB>repo<TAB>list[,list]" lines sorted
// by image.
func (t *Table) Marshal() []byte {
	var b bytes.Buffer
	if t == nil {
		return nil
	}
	for _, e := range t.entries {
		b.WriteString(e.Image)
		b.WriteByte('\t')
		b.WriteString(e.Repo)
		b.WriteByte('\t')
		b.WriteString(strings.Join(e.Lists, ","))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Unmarshal reads a table written by Marshal and checks every row: keys in
// their normal form, sorted and unique; repositories on github.com; lists
// named, sorted and unique.
func Unmarshal(data []byte) (*Table, error) {
	if len(data) > maxTableBytes {
		return nil, errors.New("app list table larger than allowed")
	}
	t := &Table{}
	if len(data) == 0 {
		return t, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, errors.New("app list table: last line is incomplete")
	}
	prev := ""
	for n, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("app list table line %d: want 3 fields, got %d", n+1, len(f))
		}
		if norm, ok := NormaliseImage(f[0]); !ok || norm != f[0] {
			return nil, fmt.Errorf("app list table line %d: image %q is not in its normal form", n+1, f[0])
		}
		if f[0] <= prev {
			return nil, fmt.Errorf("app list table line %d: images are not sorted and unique", n+1)
		}
		prev = f[0]
		if !repoForm.MatchString(f[1]) {
			return nil, fmt.Errorf("app list table line %d: %q is not a GitHub repository", n+1, f[1])
		}
		lists := strings.Split(f[2], ",")
		for i, l := range lists {
			if !listName.MatchString(l) || (i > 0 && l <= lists[i-1]) {
				return nil, fmt.Errorf("app list table line %d: lists %q are not named, sorted and unique", n+1, f[2])
			}
		}
		t.entries = append(t.entries, Entry{Image: f[0], Repo: f[1], Lists: lists})
	}
	return t, nil
}

// IsHelper reports an image that runs beside an app and is never the app
// itself: official Docker Hub images and common databases and proxies.
func IsHelper(image string) bool { return isHelper(image) }

// NormaliseRepo returns "github.com/<owner>/<name>" (lower case) for the
// URL of a GitHub repository itself; links into a repository and GitHub's
// own paths are refused.
func NormaliseRepo(url string) (string, bool) { return normaliseRepo(url) }

// Entries returns the rows of the table in order; a nil table has none.
func (t *Table) Entries() []Entry {
	if t == nil {
		return nil
	}
	return append([]Entry(nil), t.entries...)
}

// NamedLike reports whether an image is named like a repository
// ("github.com/<owner>/<name>"): its last path segment is the repository's
// name or extends it with "-" ("immich-server" for "immich"). The other
// direction does not count: "headscale-admin" is not headscale.
func NamedLike(image, repo string) bool {
	name := image[strings.LastIndexByte(image, '/')+1:]
	repoName := repo[strings.LastIndexByte(repo, '/')+1:]
	return name == repoName || strings.HasPrefix(name, repoName+"-")
}

// OwnedBy reports whether an image is in the namespace of a repository's
// owner, ignoring punctuation and case ("josh-gaby" and "joshgaby").
func OwnedBy(image, repo string) bool {
	segs := strings.Split(image, "/")
	r := strings.Split(repo, "/")
	if len(segs) < 3 || len(r) != 3 {
		return false
	}
	return alnum(segs[1]) != "" && alnum(segs[1]) == alnum(r[1])
}

// alnum keeps the letters and digits of s, in lower case.
func alnum(s string) string {
	return strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			return c
		case c >= 'A' && c <= 'Z':
			return c + 'a' - 'A'
		}
		return -1
	}, s)
}
