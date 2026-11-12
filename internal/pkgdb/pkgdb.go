// SPDX-License-Identifier: Apache-2.0

// Package pkgdb reads operating system package databases (dpkg status,
// apk installed) and os-release, from containers, LXC guests or hosts. The
// input is untrusted: only known fields are read, sizes are bounded by the
// caller, and a dpkg package counts only when its status says installed.
package pkgdb

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/bifrost0x/varde/internal/inventory"
)

// Parser accumulates packages from the lines of dpkg status and apk
// installed databases, which can be fed one after the other.
type Parser struct {
	packages []inventory.Package
	dpkg     struct{ name, version, status, source, sourceVersion string }
	apk      struct{ name, version, origin string }
}

// Line feeds one line.
func (p *Parser) Line(line string) {
	switch {
	case line == "":
		p.flush()
	case strings.HasPrefix(line, "Package: "):
		p.flush()
		p.dpkg.name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
	case strings.HasPrefix(line, "Status: "):
		p.dpkg.status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
	case strings.HasPrefix(line, "Version: "):
		p.dpkg.version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
	case strings.HasPrefix(line, "Source: "):
		// "Source: openssl" or "Source: openssl (3.0.11-1)" when the
		// source version differs.
		src, ver, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "Source: ")), " ")
		p.dpkg.source = src
		if v, ok := strings.CutPrefix(strings.TrimSpace(ver), "("); ok {
			p.dpkg.sourceVersion = strings.TrimSuffix(v, ")")
		}
	case strings.HasPrefix(line, "P:"):
		p.flush()
		p.apk.name = strings.TrimSpace(line[2:])
	case strings.HasPrefix(line, "V:") && p.apk.name != "":
		p.apk.version = strings.TrimSpace(line[2:])
	case strings.HasPrefix(line, "o:") && p.apk.name != "":
		p.apk.origin = strings.TrimSpace(line[2:])
	}
}

// flush ends the record being read: dpkg records and apk records end at a
// blank line or with the next record.
func (p *Parser) flush() {
	if p.dpkg.name != "" && strings.HasSuffix(p.dpkg.status, " installed") {
		p.add("dpkg", p.dpkg.name, p.dpkg.version, p.dpkg.source)
		if v := p.dpkg.sourceVersion; v != "" && v != p.dpkg.version && len(v) <= 128 && len(p.packages) > 0 {
			p.packages[len(p.packages)-1].SourceVersion = v
		}
	}
	p.dpkg.name, p.dpkg.version, p.dpkg.status, p.dpkg.source, p.dpkg.sourceVersion = "", "", "", "", ""
	if p.apk.name != "" && p.apk.version != "" {
		p.add("apk", p.apk.name, p.apk.version, p.apk.origin)
	}
	p.apk.name, p.apk.version, p.apk.origin = "", "", ""
}

func (p *Parser) add(manager, name, ver, source string) {
	if name == "" || ver == "" || len(name) > 256 || len(ver) > 128 {
		// Nothing added: the caller must not touch the previous package.
		p.dpkg.sourceVersion = ""
		return
	}
	if source == name || len(source) > 256 {
		source = ""
	}
	p.packages = append(p.packages, inventory.Package{Manager: manager, Name: name, Version: ver, Source: source})
}

// Packages ends the input and returns the packages, tagged with distro.
func (p *Parser) Packages(distro string) []inventory.Package {
	p.flush()
	out := p.packages
	for i := range out {
		out[i].Distro = distro
	}
	return out
}

// Feed feeds every line of a file.
func (p *Parser) Feed(b []byte) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		p.Line(strings.TrimRight(sc.Text(), "\r"))
	}
	p.flush()
}

// OSRelease is what os-release says.
type OSRelease struct {
	ID, VersionID, Name string
}

var distroID = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

// Distro is "<ID>-<VERSION_ID>" ("debian-13"), empty when ID is invalid.
func (o OSRelease) Distro() string {
	if !distroID.MatchString(o.ID) {
		return ""
	}
	if distroID.MatchString(o.VersionID) {
		return o.ID + "-" + o.VersionID
	}
	return o.ID
}

// String is the readable name ("Debian GNU/Linux 13").
func (o OSRelease) String() string { return strings.TrimSpace(o.Name + " " + o.VersionID) }

// ParseOSRelease reads ID, VERSION_ID and NAME.
func ParseOSRelease(b []byte) OSRelease {
	var o OSRelease
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			o.ID = v
		case "VERSION_ID":
			o.VersionID = v
		case "NAME":
			o.Name = v
		}
	}
	return o
}

// ParseNPMManifest reads name and version of a package.json. Scoped names
// ("@scope/name") keep the scope; the identification compares the part
// after it.
func ParseNPMManifest(b []byte) (inventory.Package, bool) {
	var m struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if len(b) > 1<<20 || json.Unmarshal(b, &m) != nil {
		return inventory.Package{}, false
	}
	m.Name, m.Version = strings.TrimSpace(m.Name), strings.TrimSpace(m.Version)
	if m.Name == "" || m.Version == "" || len(m.Name) > 214 || len(m.Version) > 64 {
		return inventory.Package{}, false
	}
	return inventory.Package{Manager: "npm", Name: m.Name, Version: m.Version}, true
}
