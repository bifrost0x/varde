// SPDX-License-Identifier: Apache-2.0

package paths

import (
	_ "embed"
	"fmt"
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed components.yaml
var componentsYAML []byte

// components is the data of components.yaml.
type componentData struct {
	Programs  map[string][]string `yaml:"programs"`
	Wrappers  []string            `yaml:"wrappers"`
	Libraries []string            `yaml:"libraries"`
}

var components = func() componentData {
	var d componentData
	if err := yaml.Unmarshal(componentsYAML, &d); err != nil {
		// The file is part of the binary; a broken one is a build defect.
		panic(fmt.Sprintf("paths: components.yaml: %v", err))
	}
	return d
}()

// Reach says how a package of a container image relates to what the
// container serves.
type Reach string

const (
	// Served means the package is the program the container runs, or a library
	// such a program commonly loads, and the container is reachable.
	Served Reach = "served"
	// InImage means the package is in the image, and nothing Varde knows ties
	// it to what the container exposes. Also the answer when Varde lacks
	// the data to decide.
	InImage Reach = "in image"
)

// Component is what Varde knows about one image package of a container.
type Component struct {
	Reach Reach
	// Program is the program the container runs, when known.
	Program string
	// Role is "the program" or "a library", for Served.
	Role string
}

// Program returns the program a container runs from its command (the
// entrypoint followed by its arguments): the first argument that is not a
// wrapper, a flag or a shell script. Empty when it cannot tell.
func Program(command []string) string {
	for _, arg := range command {
		if arg == "" || arg == "--" || strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.ContainsAny(arg, " \t;|&") {
			// An inline shell script ("sh -c 'exec httpd ...'"): its
			// first word that is not a wrapper.
			return Program(strings.Fields(strings.NewReplacer(";", " ", "&", " ", "|", " ").Replace(arg)))
		}
		base := path.Base(arg)
		if slices.Contains(components.Wrappers, base) || strings.HasSuffix(base, ".sh") {
			continue
		}
		return base
	}
	return ""
}

// CommandPrefix is the part of a command Program reads: the wrappers and
// entrypoint scripts before the program, and the program itself, without
// any flag or argument. It is what an inventory keeps of a command, since
// arguments may carry credentials ("--requirepass secret"). An inline
// shell script is reduced to its words up to the program.
func CommandPrefix(command []string) []string {
	var out []string
	for _, arg := range command {
		if arg == "" || arg == "--" || strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.ContainsAny(arg, " 	;|&") {
			words := strings.Fields(strings.NewReplacer(";", " ", "&", " ", "|", " ").Replace(arg))
			return append(out, CommandPrefix(words)...)
		}
		out = append(out, arg)
		base := path.Base(arg)
		if !slices.Contains(components.Wrappers, base) && !strings.HasSuffix(base, ".sh") {
			return out
		}
	}
	// No program found: only wrappers and scripts, which name no secret.
	return out
}

// ComponentOf says whether the image package pkg (a source package name)
// is reachable through what the container exposes: exposed reports whether
// anything outside the host reaches the container (published port, proxy
// route), command is what the container runs. Without a command Varde
// cannot tie a package to a listening process and answers InImage.
func ComponentOf(pkg string, command []string, exposed bool) Component {
	prog := Program(command)
	c := Component{Reach: InImage, Program: prog}
	if !exposed || prog == "" {
		return c
	}
	for _, owner := range components.Programs[prog] {
		if matches(pkg, owner) {
			c.Reach, c.Role = Served, "the program"
			return c
		}
	}
	if matches(pkg, prog) {
		c.Reach, c.Role = Served, "the program"
		return c
	}
	// A library counts only beside a program Varde knows serves the
	// network: a CLI tool's image is no reason to call its TLS reachable.
	if _, known := components.Programs[prog]; known {
		for _, lib := range components.Libraries {
			if matches(pkg, lib) {
				c.Reach, c.Role = Served, "a library"
				return c
			}
		}
	}
	return c
}

// matches reports whether a package is name or a versioned form of it
// ("python3.11" for python3, "postgresql-16" for postgresql).
func matches(pkg, name string) bool {
	if pkg == name {
		return true
	}
	rest, ok := strings.CutPrefix(pkg, name)
	if !ok || rest == "" {
		return false
	}
	if digit(rest[0]) {
		return true
	}
	return (rest[0] == '.' || rest[0] == '-') && len(rest) > 1 && digit(rest[1])
}

func digit(b byte) bool { return b >= '0' && b <= '9' }
