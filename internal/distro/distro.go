// SPDX-License-Identifier: Apache-2.0

// Package distro maps operating system releases to the ecosystems of
// distribution security data (OSV: "Debian:12", "Ubuntu:24.04:LTS",
// "Alpine:v3.22") and compares package versions in their native order
// (ADR 0028).
package distro

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/version"
)

// Package is a distribution package checked against distribution security
// data: the ecosystem of its release, its source package name and the
// installed version as the package manager reports it.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

var (
	almaRelease     = regexp.MustCompile(`^almalinux-(\d{1,2})(?:\.\d+)*$`)
	rockyRelease    = regexp.MustCompile(`^rocky-(\d{1,2})(?:\.\d+)*$`)
	leapRelease     = regexp.MustCompile(`^opensuse-leap-(\d{2}\.\d)$`)
	debianRelease   = regexp.MustCompile(`^debian-(\d{1,3})$`)
	raspbianRelease = regexp.MustCompile(`^raspbian-(\d{1,3})$`)
	ubuntuRelease   = regexp.MustCompile(`^ubuntu-(\d{2})\.(\d{2})$`)
	alpineRelease   = regexp.MustCompile(`^alpine-(\d+)\.(\d+)(?:\.\d+)?$`)
	rhelRelease     = regexp.MustCompile(`^rhel-(\d{1,2})(?:\.\d+)*$`)
	// Wolfi, Chainguard and openSUSE Tumbleweed roll; os-release names a
	// date or nothing. An image is fixed content, so its packages still
	// have a defined state.
	wolfiRelease      = regexp.MustCompile(`^wolfi(?:-\d{8})?$`)
	chainguardRelease = regexp.MustCompile(`^chainguard(?:-\d{8})?$`)
	tumbleweedRelease = regexp.MustCompile(`^opensuse-tumbleweed(?:-\d{8})?$`)
)

// Ecosystem returns the OSV ecosystem of a release as Varde records it
// ("debian-12", "ubuntu-24.04", "alpine-3.22.1") and the package manager
// whose versions it uses. Releases without a stable number (Debian testing,
// Alpine edge) have no ecosystem: their packages change daily.
func Ecosystem(release string) (ecosystem, manager string, ok bool) {
	release = strings.ToLower(strings.TrimSpace(release))
	if m := debianRelease.FindStringSubmatch(release); m != nil {
		return "Debian:" + m[1], "dpkg", true
	}
	// Raspberry Pi OS (32-bit) rebuilds Debian; its versions extend
	// Debian's ("+rpi1", "+rpt1"), so Debian's data applies.
	if m := raspbianRelease.FindStringSubmatch(release); m != nil {
		return "Debian:" + m[1], "dpkg", true
	}
	if m := ubuntuRelease.FindStringSubmatch(release); m != nil {
		eco := "Ubuntu:" + m[1] + "." + m[2]
		// Long-term support releases are the April releases of even years.
		if y, _ := strconv.Atoi(m[1]); y%2 == 0 && m[2] == "04" {
			eco += ":LTS"
		}
		return eco, "dpkg", true
	}
	if m := alpineRelease.FindStringSubmatch(release); m != nil {
		return "Alpine:v" + m[1] + "." + m[2], "apk", true
	}
	// RPM distributions with security data on osv.dev. RHEL's data is split
	// by repository, which the package list does not tell; Fedora has none.
	if m := almaRelease.FindStringSubmatch(release); m != nil {
		return "AlmaLinux:" + m[1], "rpm", true
	}
	if m := rockyRelease.FindStringSubmatch(release); m != nil {
		return "Rocky Linux:" + m[1], "rpm", true
	}
	if m := leapRelease.FindStringSubmatch(release); m != nil {
		return "openSUSE:Leap " + m[1], "rpm", true
	}
	if tumbleweedRelease.MatchString(release) {
		return "openSUSE:Tumbleweed", "rpm", true
	}
	// Red Hat Enterprise Linux and its UBI images: osv.dev keeps the data
	// per repository (Variants).
	if m := rhelRelease.FindStringSubmatch(release); m != nil {
		return "Red Hat:enterprise_linux:" + m[1], "rpm", true
	}
	if wolfiRelease.MatchString(release) {
		return "Wolfi", "apk", true
	}
	if chainguardRelease.MatchString(release) {
		return "Chainguard", "apk", true
	}
	return "", "", false
}

// Compare compares two package versions of an ecosystem; ok is false for
// unknown ecosystems and invalid versions.
func Compare(ecosystem, a, b string) (int, bool) {
	switch family(ecosystem) {
	case "Debian", "Ubuntu":
		if a == "" || b == "" {
			return 0, false
		}
		return version.CompareDpkg(a, b), true
	case "Alpine", "Wolfi", "Chainguard":
		return version.CompareAPK(a, b)
	case "AlmaLinux", "Rocky Linux", "openSUSE", "Red Hat":
		if a == "" || b == "" {
			return 0, false
		}
		// Package lists read with older inventory key lines carry no
		// epoch; the epoch is then left out on both sides. Within one
		// release a package keeps its epoch, so this orders correctly.
		if !strings.Contains(a, ":") || !strings.Contains(b, ":") {
			a, b = dropEpoch(a), dropEpoch(b)
		}
		return version.CompareRPM(a, b), true
	case "Go", "npm":
		x, err := version.Parse(version.SemVer, a)
		if err != nil {
			return 0, false
		}
		y, err := version.Parse(version.SemVer, b)
		if err != nil {
			return 0, false
		}
		return x.Compare(y)
	case "PyPI":
		return version.ComparePEP440(a, b)
	case "Maven":
		return version.CompareMaven(a, b)
	case "RubyGems":
		return version.CompareRubyGems(a, b)
	case "NuGet":
		return version.CompareNuGet(a, b)
	case "Packagist":
		return version.CompareComposer(a, b)
	case "crates.io":
		return version.CompareCargo(a, b)
	}
	return 0, false
}

// Language reports whether an ecosystem holds the dependencies of apps (Go
// modules, npm, PyPI, Maven, RubyGems, NuGet, Packagist and crates.io
// packages) rather than distribution packages: their records are the
// advisories themselves, compared in the ecosystem's own version scheme.
func Language(ecosystem string) bool {
	switch ecosystem {
	case "Go", "npm", "PyPI", "Maven", "RubyGems", "NuGet", "Packagist", "crates.io":
		return true
	}
	return false
}

func dropEpoch(v string) string {
	if _, rest, ok := strings.Cut(v, ":"); ok {
		return rest
	}
	return v
}

// Supported reports whether ecosystem is one Varde compares.
func Supported(ecosystem string) bool {
	switch family(ecosystem) {
	case "Debian", "Ubuntu", "Alpine", "Wolfi", "Chainguard", "AlmaLinux", "Rocky Linux", "openSUSE", "Red Hat":
		return true
	}
	return Language(ecosystem)
}

// Notices reports whether the ecosystem publishes its data only as notices
// covering several CVEs (ALSA, RLSA, SUSE-SU); they are kept and expanded
// per CVE when matched.
func Notices(ecosystem string) bool {
	switch family(ecosystem) {
	case "AlmaLinux", "Rocky Linux", "openSUSE", "Red Hat":
		return true
	}
	return false
}

// ubuntuStandardEnd is when an Ubuntu LTS release left standard support.
// After it, osv.dev records new fixes under "Ubuntu:Pro:<release>:LTS"
// (Expanded Security Maintenance) and no longer under the release itself.
var ubuntuStandardEnd = map[string]time.Time{
	"14.04": time.Date(2019, 4, 30, 0, 0, 0, 0, time.UTC),
	"16.04": time.Date(2021, 4, 30, 0, 0, 0, 0, time.UTC),
	"18.04": time.Date(2023, 5, 31, 0, 0, 0, 0, time.UTC),
	"20.04": time.Date(2025, 5, 31, 0, 0, 0, 0, time.UTC),
	"22.04": time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
	"24.04": time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC),
}

// Variants are the ecosystems whose records apply to packages of an
// ecosystem: itself, and for an Ubuntu LTS release past standard support
// also its Pro ecosystem. A fix only in Pro is still a fix to report: the
// package is affected until Pro (or a newer release) is installed.
func Variants(ecosystem string, now time.Time) []string {
	if family(ecosystem) == "Red Hat" && strings.Count(ecosystem, ":") == 2 {
		// A package list does not say which repository a package came
		// from; a package is in one of them.
		return []string{ecosystem + "::baseos", ecosystem + "::appstream", ecosystem + "::crb"}
	}
	out := []string{ecosystem}
	if rel, ok := strings.CutPrefix(ecosystem, "Ubuntu:"); ok {
		if rel, ok = strings.CutSuffix(rel, ":LTS"); ok {
			if end, known := ubuntuStandardEnd[rel]; known && now.After(end) {
				out = append(out, "Ubuntu:Pro:"+rel+":LTS")
			}
		}
	}
	return out
}

// SameRelease reports whether a record's ecosystem applies to a package's.
func SameRelease(record, pkg string, now time.Time) bool {
	for _, v := range Variants(pkg, now) {
		if strings.EqualFold(record, v) {
			return true
		}
	}
	return false
}

func family(ecosystem string) string {
	f, _, _ := strings.Cut(ecosystem, ":")
	return f
}

// foreignBuild matches versions of packages built for a release outside its
// archive: vendor repositories name the codename ("1.28.0-1~bookworm",
// "2.1.0-1~noble"), backports carry "~bpo12+1". Distribution security data
// does not cover them.
var foreignBuild = regexp.MustCompile(`~(bpo\d|(buster|bullseye|bookworm|trixie|forky|focal|jammy|noble|oracular|plucky|questing|resolute)\b)`)

// Foreign reports whether a Debian or Ubuntu package version comes from
// outside the distribution's archive.
func Foreign(ecosystem, version string) bool {
	switch family(ecosystem) {
	case "Debian", "Ubuntu":
		return foreignBuild.MatchString(version)
	case "AlmaLinux", "Rocky Linux", "Red Hat":
		// Distribution builds name the enterprise release ("el9", "el9_4",
		// "module+el9.2.0", "module_el9.7.0"); vendor builds such as nginx.org add their own
		// tag (".el9.ngx").
		return !elRelease.MatchString(version) || strings.HasSuffix(version, ".ngx")
	}
	return false
}

var elRelease = regexp.MustCompile(`[._+]el\d+`)

// RecordPrefixes are the OSV ID prefixes of per-CVE distribution records.
// Notices (DSA, DLA, USN) list several CVEs and would merge their findings;
// the per-CVE records carry the same fixed versions.
var RecordPrefixes = []string{"DEBIAN-CVE-", "UBUNTU-CVE-", "ALPINE-CVE-"}

// KeepRecords picks the records of one package to use from the IDs osv.dev
// returned for it. Distributions with per-CVE records are read through
// those: their notices (DSA, DLA, USN) list several CVEs and would merge
// findings. A release osv.dev covers by notices only, such as a Debian
// release in long-term support, keeps its notices: rather one finding per
// notice than none.
func KeepRecords(ecosystem string, ids map[string]time.Time) map[string]time.Time {
	if Notices(ecosystem) || Language(ecosystem) {
		return ids
	}
	out := map[string]time.Time{}
	for id, m := range ids {
		if PerCVE(id) {
			out[id] = m
		}
	}
	if len(out) > 0 {
		return out
	}
	return ids
}

// PerCVE reports whether id is a per-CVE distribution record.
func PerCVE(id string) bool {
	for _, p := range RecordPrefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// SystemPrefix starts the app ID of a system package: an operating system
// package checked against its distribution's security data without a
// catalog entry (ADR 0032).
const SystemPrefix = "os:"

// SystemAppID is the app ID findings and stored records of a system package
// use: "os:Debian:13/openssl". App dependencies use it too:
// "os:Go/golang.org/x/net", "os:npm/@scope/name".
func SystemAppID(ecosystem, name string) string { return SystemPrefix + ecosystem + "/" + name }

// ParseSystemAppID splits a system package's app ID; ok is false for other
// app IDs.
func ParseSystemAppID(id string) (ecosystem, name string, ok bool) {
	rest, ok := strings.CutPrefix(id, SystemPrefix)
	if !ok {
		return "", "", false
	}
	// Ecosystems have no slash; Go module and npm package names may.
	i := strings.Index(rest, "/")
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// SystemName is the readable name of a system package's app ID: "glibc
// (Debian 12 package)"; ok is false for other app IDs.
func SystemName(id string) (string, bool) {
	eco, name, ok := ParseSystemAppID(id)
	if !ok {
		return "", false
	}
	switch eco {
	case "Go":
		if name == "stdlib" {
			return "Go standard library", true
		}
		return name + " (Go module)", true
	case "npm":
		return name + " (npm package)", true
	case "PyPI":
		return name + " (Python package)", true
	case "Maven":
		return name + " (Java library)", true
	case "RubyGems":
		return name + " (Ruby gem)", true
	case "NuGet":
		return name + " (.NET package)", true
	case "Packagist":
		return name + " (PHP package)", true
	case "crates.io":
		return name + " (Rust crate)", true
	}
	return name + " (" + strings.ReplaceAll(eco, ":", " ") + " package)", true
}
