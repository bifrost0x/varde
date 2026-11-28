// SPDX-License-Identifier: Apache-2.0

// Package vulndb turns complete public vulnerability datasets into OSV
// records for the packages Varde checks (ADR 0047): the Debian security
// tracker, Canonical's package OVAL for Ubuntu, the secdb files of Alpine,
// Wolfi and Chainguard, and osv.dev's bulk exports of language and RPM
// ecosystems. Every installation downloads the same files whole, so a
// download tells nobody which packages run; matching stays local.
//
// A downloaded file is normalised once into a compact cache file
// (Normalize); the records of the packages present are then selected from
// that file whenever the inventory changes (Select), without a request.
package vulndb

import (
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/distro"
)

// Format is the file format of a dataset.
type Format int

// Formats of the datasets.
const (
	FormatDebian     Format = iota + 1 // security-tracker.debian.org JSON
	FormatUbuntuOVAL                   // Canonical's package OVAL, bzip2
	FormatSecDB                        // Alpine, Wolfi and Chainguard secdb JSON
	FormatOSVZip                       // osv.dev bulk export of one ecosystem
	FormatUbuntuCVE                    // Canonical's CVE OVAL, bzip2: ratings, no packages
)

// Dataset is one downloadable file of security data.
type Dataset struct {
	// Key names the dataset in the source state and the cache
	// ("debian", "ubuntu:noble", "alpine:v3.22:main", "osv:PyPI").
	Key string
	// Title names it for people.
	Title string
	URL   string
	// Host is the host the file comes from, for the egress allowlist.
	Host   string
	Format Format
	// Ecosystem is the ecosystem the file's records belong to, for
	// formats that do not name it (Ubuntu OVAL, secdb).
	Ecosystem string
	// Prefix starts the IDs of records made from this dataset, for
	// formats whose entries are not OSV records ("UBUNTU-").
	Prefix string
	// MaxBytes bounds the download (after transfer decoding).
	MaxBytes int64
}

// Download hosts, listed in the documentation of the egress allowlist.
const (
	debianHost     = "security-tracker.debian.org"
	ubuntuHost     = "security-metadata.canonical.com"
	alpineHost     = "secdb.alpinelinux.org"
	wolfiHost      = "packages.wolfi.dev"
	chainguardHost = "packages.cgr.dev"
	osvHost        = "osv-vulnerabilities.storage.googleapis.com"
)

// Hosts are every host a dataset can come from.
var Hosts = []string{debianHost, ubuntuHost, alpineHost, wolfiHost, chainguardHost, osvHost}

// debianReleases maps the codenames of the security tracker to release
// numbers. Releases past their long-term support leave the tracker.
var debianReleases = map[string]string{
	"bookworm": "12",
	"trixie":   "13",
	"forky":    "14",
	"duke":     "15",
}

// ubuntuReleases maps Ubuntu versions to the codenames Canonical's OVAL
// files are named by.
var ubuntuReleases = map[string]string{
	"14.04": "trusty",
	"16.04": "xenial",
	"18.04": "bionic",
	"20.04": "focal",
	"22.04": "jammy",
	"24.04": "noble",
	"24.10": "oracular",
	"25.04": "plucky",
	"25.10": "questing",
	"26.04": "resolute",
}

// osvZipEcosystems are the ecosystems read from osv.dev's bulk export,
// keyed by the family of a package's ecosystem. npm is missing on purpose:
// its export holds hundreds of thousands of malware reports and is larger
// than an installation should download every day.
var osvZipEcosystems = map[string]string{
	"Go":          "Go",
	"PyPI":        "PyPI",
	"Maven":       "Maven",
	"crates.io":   "crates.io",
	"RubyGems":    "RubyGems",
	"Packagist":   "Packagist",
	"NuGet":       "NuGet",
	"AlmaLinux":   "AlmaLinux",
	"Rocky Linux": "Rocky Linux",
	"openSUSE":    "openSUSE",
	"Red Hat":     "Red Hat",
}

var (
	alpineEcosystem = regexp.MustCompile(`^Alpine:v(\d+\.\d+)$`)
	ubuntuEcosystem = regexp.MustCompile(`^Ubuntu:(\d{2}\.\d{2})(:LTS)?$`)
)

// Datasets returns the datasets that hold the records of a package
// ecosystem ("Debian:12", "Alpine:v3.22", "PyPI"), none when no complete
// dataset covers it.
func Datasets(ecosystem string) []Dataset {
	fam, rest, _ := strings.Cut(ecosystem, ":")
	switch fam {
	case "Debian":
		for _, n := range debianReleases {
			if n == rest {
				return []Dataset{{Key: "debian", Title: "Debian security tracker", Host: debianHost, Format: FormatDebian,
					URL: "https://" + debianHost + "/tracker/data/json", MaxBytes: 512 << 20}}
			}
		}
	case "Ubuntu":
		m := ubuntuEcosystem.FindStringSubmatch(ecosystem)
		if m == nil {
			return nil
		}
		code, ok := ubuntuReleases[m[1]]
		if !ok {
			return nil
		}
		return []Dataset{{Key: "ubuntu:" + code, Title: "Ubuntu OVAL (" + m[1] + ")", Host: ubuntuHost, Format: FormatUbuntuOVAL,
			URL: "https://" + ubuntuHost + "/oval/com.ubuntu." + code + ".pkg.oval.xml.bz2", Ecosystem: ecosystem, Prefix: "UBUNTU-", MaxBytes: 64 << 20}}
	case "Alpine":
		m := alpineEcosystem.FindStringSubmatch(ecosystem)
		if m == nil {
			return nil
		}
		var out []Dataset
		for _, repo := range []string{"main", "community"} {
			out = append(out, Dataset{Key: "alpine:v" + m[1] + ":" + repo, Title: "Alpine secdb (v" + m[1] + " " + repo + ")", Host: alpineHost,
				Format: FormatSecDB, URL: "https://" + alpineHost + "/v" + m[1] + "/" + repo + ".json", Ecosystem: ecosystem, Prefix: "ALPINE-", MaxBytes: 32 << 20})
		}
		return out
	case "Wolfi":
		if rest == "" {
			return []Dataset{{Key: "wolfi", Title: "Wolfi security data", Host: wolfiHost, Format: FormatSecDB,
				URL: "https://" + wolfiHost + "/os/security.json", Ecosystem: "Wolfi", Prefix: "WOLFI-", MaxBytes: 128 << 20}}
		}
	case "Chainguard":
		if rest == "" {
			return []Dataset{{Key: "chainguard", Title: "Chainguard security data", Host: chainguardHost, Format: FormatSecDB,
				URL: "https://" + chainguardHost + "/chainguard/security.json", Ecosystem: "Chainguard", Prefix: "CHAINGUARD-", MaxBytes: 256 << 20}}
		}
	}
	if eco, ok := osvZipEcosystems[fam]; ok {
		return []Dataset{{Key: "osv:" + eco, Title: "osv.dev export (" + eco + ")", Host: osvHost, Format: FormatOSVZip,
			URL: "https://" + osvHost + "/" + url.PathEscape(eco) + "/all.zip", MaxBytes: 256 << 20}}
	}
	return nil
}

// cveRelease is the Ubuntu release whose CVE data rates the CVEs of every
// package: the newest long-term support release tracks nearly every CVE of
// the open source software distributions ship, each with the NVD's CVSS
// score and a description.
const cveRelease = "noble"

// CVEDataset is the dataset that rates CVEs for records whose own source
// states no severity (Debian, Alpine, Wolfi, Chainguard).
func CVEDataset() Dataset {
	return Dataset{Key: "cve:ubuntu-" + cveRelease, Title: "CVE ratings (Ubuntu CVE tracker)", Host: ubuntuHost, Format: FormatUbuntuCVE,
		URL: "https://" + ubuntuHost + "/oval/com.ubuntu." + cveRelease + ".cve.oval.xml.bz2", MaxBytes: 128 << 20}
}

// Title names the dataset of a key for people ("debian" gives "Debian
// security tracker"); the key itself when it is not one Varde makes.
func Title(key string) string {
	switch {
	case key == "debian":
		return "Debian security tracker"
	case key == "wolfi":
		return "Wolfi security data"
	case key == "chainguard":
		return "Chainguard security data"
	case key == CVEDataset().Key:
		return CVEDataset().Title
	}
	if code, ok := strings.CutPrefix(key, "ubuntu:"); ok {
		for v, c := range ubuntuReleases {
			if c == code {
				return "Ubuntu OVAL (" + v + ")"
			}
		}
	}
	if rest, ok := strings.CutPrefix(key, "alpine:"); ok {
		rel, repo, _ := strings.Cut(rest, ":")
		return "Alpine secdb (" + rel + " " + repo + ")"
	}
	if eco, ok := strings.CutPrefix(key, "osv:"); ok {
		return "osv.dev export (" + eco + ")"
	}
	return key
}

// Covered reports whether a complete dataset covers an ecosystem.
func Covered(ecosystem string) bool { return len(Datasets(ecosystem)) > 0 }

// Handles reports whether the datasets cover a package: its ecosystem is
// covered, and it is not an Ubuntu kernel, whose records compare the
// running kernel and are left out of Canonical's package data here.
func Handles(p distro.Package) bool {
	if !Covered(p.Ecosystem) {
		return false
	}
	fam, _, _ := strings.Cut(p.Ecosystem, ":")
	return fam != "Ubuntu" || !distro.Kernel(p.Ecosystem, p.Name)
}

// Record is one vulnerability record as the cache keeps it.
type Record struct {
	Vuln advisory.Vulnerability `json:"v"`
	// CVSS is the highest base score the record states, 0 when none.
	CVSS float64 `json:"c,omitempty"`
	// Severity is the rating of the record's publisher ("high"), empty
	// when it has none.
	Severity string `json:"s,omitempty"`
}

// Key is the key a package is found under: its ecosystem and its name in
// the ecosystem's canonical spelling, lower-cased where the ecosystem
// ignores case.
func Key(ecosystem, name string) string {
	return strings.ToLower(ecosystem) + "/" + CanonicalName(ecosystem, name)
}

var pep503 = regexp.MustCompile(`[-_.]+`)

// CanonicalName spells a package name the way its ecosystem compares
// names: Python names per PEP 503, NuGet, Packagist and crates.io names
// without case.
func CanonicalName(ecosystem, name string) string {
	fam, _, _ := strings.Cut(ecosystem, ":")
	switch fam {
	case "PyPI":
		return pep503.ReplaceAllString(strings.ToLower(name), "-")
	case "NuGet", "Packagist":
		return strings.ToLower(name)
	case "crates.io":
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	}
	return name
}

// Wanted are the packages whose records are selected, by the keys their
// records name: every ecosystem whose records apply to a package's
// release (distro.Variants) leads to it.
type Wanted struct {
	byKey map[string][]wantedPkg
	// apps are the ecosystems of the packages of each app ID.
	apps map[string]map[string]bool
}

type wantedPkg struct {
	appID, ecosystem, name string
}

// Want indexes pkgs for Select: the system packages of hosts and the
// packages of images, each under its own app ID (distro.SystemAppID), and
// byApp, the distribution packages of catalog apps, under the app's ID.
func Want(pkgs []distro.Package, byApp map[string][]distro.Package, now time.Time) *Wanted {
	w := &Wanted{byKey: map[string][]wantedPkg{}, apps: map[string]map[string]bool{}}
	seen := map[wantedPkg]bool{}
	add := func(app string, p distro.Package) {
		if p.Name == "" || !Handles(p) {
			return
		}
		wp := wantedPkg{appID: app, ecosystem: p.Ecosystem, name: p.Name}
		if seen[wp] {
			return
		}
		seen[wp] = true
		if w.apps[app] == nil {
			w.apps[app] = map[string]bool{}
		}
		w.apps[app][p.Ecosystem] = true
		for _, v := range distro.Variants(p.Ecosystem, now) {
			k := Key(v, p.Name)
			w.byKey[k] = append(w.byKey[k], wp)
		}
	}
	for _, p := range pkgs {
		add(distro.SystemAppID(p.Ecosystem, p.Name), p)
	}
	for app, ps := range byApp {
		for _, p := range ps {
			add(app, p)
		}
	}
	return w
}

// Ecosystems lists the ecosystems of the wanted packages.
func (w *Wanted) Ecosystems() []string {
	set := map[string]bool{}
	for _, ecos := range w.apps {
		for e := range ecos {
			set[e] = true
		}
	}
	out := make([]string, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	return out
}

// Apps maps the app IDs of the wanted packages to the ecosystems of their
// packages.
func (w *Wanted) Apps() map[string]map[string]bool { return w.apps }

// Len is the number of keys wanted.
func (w *Wanted) Len() int { return len(w.byKey) }

// truncate bounds upstream text without cutting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// summary is the start of a description, cut at a word. Descriptions often
// open with what the software is ("Vim is an open source, command line
// text editor."), so the first sentence alone says too little.
func summary(desc string) string {
	desc = strings.Join(strings.Fields(desc), " ")
	const n = 220
	if len(desc) <= n {
		return desc
	}
	cut := strings.LastIndex(desc[:n], " ")
	if cut < n/2 {
		return truncate(desc, n)
	}
	return desc[:cut] + "…"
}

// validID accepts the identifier forms records use.
func validID(id string) bool {
	if id == "" || len(id) > 96 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}
