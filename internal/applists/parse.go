// SPDX-License-Identifier: Apache-2.0

package applists

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Bounds of what a list may contain.
const (
	// maxApps is the most apps one list may name.
	maxApps = 20000
	// maxMember is the largest file read from an archive.
	maxMember = 4 << 20
	// maxArchive is the most an archive may unpack to in total.
	maxArchive = 256 << 20
)

// rawString reads a JSON value that should be a string; anything else
// (null, a number, a list) is empty. Lists are written by many hands.
func rawString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// ParseUnraid reads the application feed of Unraid's Community
// Applications: a JSON document whose "applist" names, per template, the
// image ("Repository") and the project ("Project", else "GitHub"). It
// streams the list; plugins and templates without an image or without a
// GitHub repository yield nothing.
func ParseUnraid(r io.Reader) ([]Pair, error) {
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("unraid list: not a JSON object: %w", orUnexpected(err))
	}
	var pairs []Pair
	found := false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("unraid list: %w", err)
		}
		if key != "applist" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("unraid list: %w", err)
			}
			continue
		}
		found = true
		if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
			return nil, fmt.Errorf("unraid list: applist is not a list: %w", orUnexpected(err))
		}
		for n := 0; dec.More(); n++ {
			if n >= maxApps {
				return nil, fmt.Errorf("unraid list: more than %d apps", maxApps)
			}
			var app struct {
				Repository, Project, GitHub, Plugin, PluginURL json.RawMessage
			}
			if err := dec.Decode(&app); err != nil {
				return nil, fmt.Errorf("unraid list: app %d: %w", n+1, err)
			}
			if rawString(app.Plugin) != "" || rawString(app.PluginURL) != "" {
				continue
			}
			image, ok := NormaliseImage(rawString(app.Repository))
			if !ok {
				continue
			}
			repo, ok := normaliseRepo(rawString(app.Project))
			if !ok {
				// "GitHub" is often the repository of the template, not of
				// the app: it counts only when it has the image's name.
				if repo, ok = normaliseRepo(rawString(app.GitHub)); !ok || !namedAlike(image, repo) {
					continue
				}
			}
			pairs = append(pairs, Pair{Image: image, Repo: repo, List: "unraid"})
		}
		if _, err := dec.Token(); err != nil {
			return nil, fmt.Errorf("unraid list: %w", err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("unraid list: %w", err)
	}
	if !found {
		return nil, errors.New("unraid list: no applist")
	}
	return pairs, nil
}

func orUnexpected(err error) error {
	if err == nil {
		return errors.New("unexpected content")
	}
	return err
}

var (
	umbrelRepo  = regexp.MustCompile(`(?m)^repo:[ \t]*["']?([^"'\s#]+)`)
	composeLine = regexp.MustCompile(`(?m)^[ \t]+image:[ \t]*["']?([^"'\s#]+)`)
)

// ParseUmbrel reads the archive of Umbrel's app store repository (gzip
// tar): each app directory holds umbrel-app.yml with "repo:", the project's
// repository, and docker-compose.yml with the images. An app yields a pair
// only when it has exactly one image that is not a helper, so a database
// beside the app is never taken for it.
func ParseUmbrel(r io.Reader) ([]Pair, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("umbrel list: not a gzip archive: %w", err)
	}
	defer func() { _ = gz.Close() }()
	// What an app directory states; file bodies are not kept.
	type app struct {
		repo   string
		images map[string]bool
	}
	apps := map[string]*app{}
	// The archive is bounded as a whole: a small download must not unpack
	// to more than this.
	unpacked := &io.LimitedReader{R: gz, N: maxArchive + 1}
	tr := tar.NewReader(unpacked)
	for {
		h, err := tr.Next()
		if unpacked.N <= 0 {
			return nil, fmt.Errorf("umbrel list: unpacks to more than %d MiB", maxArchive>>20)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("umbrel list: %w", err)
		}
		// <root>/<app>/<file>
		parts := strings.Split(strings.Trim(h.Name, "/"), "/")
		if h.Typeflag != tar.TypeReg || len(parts) != 3 || (parts[2] != "umbrel-app.yml" && parts[2] != "docker-compose.yml") {
			continue
		}
		if h.Size > maxMember {
			return nil, fmt.Errorf("umbrel list: %s is larger than allowed", h.Name)
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxMember+1))
		if err != nil {
			return nil, fmt.Errorf("umbrel list: %s: %w", h.Name, err)
		}
		a := apps[parts[1]]
		if a == nil {
			if len(apps) >= maxApps {
				return nil, fmt.Errorf("umbrel list: more than %d apps", maxApps)
			}
			a = &app{images: map[string]bool{}}
			apps[parts[1]] = a
		}
		if parts[2] == "umbrel-app.yml" {
			if m := umbrelRepo.FindSubmatch(body); m != nil {
				a.repo, _ = normaliseRepo(string(m[1]))
			}
			continue
		}
		for _, im := range composeLine.FindAllSubmatch(body, -1) {
			if image, ok := NormaliseImage(string(im[1])); ok && !isHelper(image) {
				a.images[image] = true
			}
		}
	}
	var pairs []Pair
	for _, a := range apps {
		if a.repo == "" || len(a.images) != 1 {
			continue
		}
		for image := range a.images {
			pairs = append(pairs, Pair{Image: image, Repo: a.repo, List: "umbrel"})
		}
	}
	return pairs, nil
}
