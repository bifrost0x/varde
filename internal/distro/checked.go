// SPDX-License-Identifier: Apache-2.0

package distro

import (
	"strings"
)

// Installed is a package as a package database lists it.
type Installed struct {
	Manager, Name, Version string
	// Source and SourceVersion name the source package it was built from
	// and that package's version, when the database says.
	Source, SourceVersion string
}

// CheckOptions describe where a package list comes from.
type CheckOptions struct {
	// Kernel is the running kernel release (uname -r) of a host.
	Kernel string
	// Image marks the packages of a container image: a container runs its
	// host's kernel, so kernel packages in it are not checked.
	Image bool
}

// maxChecked bounds the packages checked per system.
const maxChecked = 5000

// Checked returns the packages of a system to check against its
// distribution's security data, in the names and versions that data uses:
//
//   - Debian, Ubuntu and Alpine name source packages; their version is the
//     source version where the database gives one (a binNMU or a package
//     built from a differently versioned source), else the highest version
//     among the binaries.
//   - AlmaLinux, Rocky Linux and openSUSE name binary packages.
//   - Kernels are checked as the distribution's kernel source ("linux" for
//     linux-signed-amd64), at the version of the running kernel; headers,
//     tools and linux-libc-dev, which come into many images as build
//     dependencies, are not the running kernel and are left out.
//
// Builds from outside the distribution are left out.
func Checked(release string, pkgs []Installed, opt CheckOptions) []Package {
	eco, manager, ok := Ecosystem(release)
	if !ok {
		return nil
	}
	binary := binaryNamed(eco)
	type pick struct {
		pkg     Package
		running bool
	}
	best := map[string]pick{}
	var order []string
	for _, p := range pkgs {
		if p.Manager != manager || p.Version == "" || Foreign(eco, p.Version) {
			continue
		}
		name, ver := p.Source, p.Version
		if name == "" || binary {
			name = p.Name
		}
		if !binary && p.SourceVersion != "" {
			ver = p.SourceVersion
		}
		running := false
		if k, isKernel := kernelSource(eco, p.Name, name); isKernel {
			if opt.Image || k == "" {
				continue
			}
			name = k
			running = runningKernel(eco, p, opt.Kernel)
		}
		prev, seen := best[name]
		if !seen {
			order = append(order, name)
		}
		switch {
		case !seen, running && !prev.running:
			best[name] = pick{Package{Ecosystem: eco, Name: name, Version: ver}, running}
		case prev.running && !running:
		default:
			if c, ok := Compare(eco, ver, prev.pkg.Version); ok && c > 0 {
				best[name] = pick{Package{Ecosystem: eco, Name: name, Version: ver}, running}
			}
		}
	}
	if len(order) > maxChecked {
		order = order[:maxChecked]
	}
	out := make([]Package, 0, len(order))
	for _, n := range order {
		out = append(out, best[n].pkg)
	}
	return out
}

// BinaryNamed reports whether an ecosystem's security data names binary
// packages: the RPM distributions' notices list the binaries they update.
func BinaryNamed(ecosystem string) bool { return binaryNamed(ecosystem) }

func binaryNamed(ecosystem string) bool {
	switch family(ecosystem) {
	case "AlmaLinux", "Rocky Linux", "openSUSE", "Red Hat":
		return true
	}
	return false
}

// kernelSource reports whether a package belongs to a kernel and returns
// the name the security data uses for it, empty for kernel packages that
// are not the kernel itself (headers, tools, metapackages).
func kernelSource(ecosystem, binary, source string) (string, bool) {
	switch family(ecosystem) {
	case "Debian", "Ubuntu":
		if source != "linux" && !strings.HasPrefix(source, "linux-") {
			return "", false
		}
		if !debianKernelSource(source) {
			return "", false
		}
		if !strings.HasPrefix(binary, "linux-image-") && !strings.HasPrefix(binary, "linux-modules-") {
			return "", true
		}
		if strings.HasPrefix(source, "linux-meta") {
			// Metapackages carry their own version scheme.
			return "", true
		}
		// The signed kernel is built from the kernel's source of the same
		// version: "linux-signed-amd64" and "linux-signed" are "linux",
		// "linux-signed-hwe-6.8" is "linux-hwe-6.8".
		if s, ok := strings.CutPrefix(source, "linux-signed"); ok {
			switch s = strings.TrimPrefix(s, "-"); s {
			case "", "amd64", "arm64", "i386", "armhf", "ppc64el", "s390x", "generic":
				return "linux", true
			default:
				return "linux-" + s, true
			}
		}
		return source, true
	case "Alpine", "Wolfi", "Chainguard":
		if strings.HasPrefix(binary, "linux-") && !strings.HasPrefix(binary, "linux-headers") && !strings.HasPrefix(binary, "linux-firmware") && !strings.HasPrefix(binary, "linux-tools") {
			return binary, true
		}
	case "AlmaLinux", "Rocky Linux", "openSUSE", "Red Hat":
		if binary == "kernel" || strings.HasPrefix(binary, "kernel-") {
			if strings.HasPrefix(binary, "kernel-headers") || strings.HasPrefix(binary, "kernel-devel") || strings.HasPrefix(binary, "kernel-tools") || binary == "kernel-firmware" {
				return "", true
			}
			return binary, true
		}
	}
	return "", false
}

// debianKernelSource reports whether a Debian or Ubuntu source package is a
// kernel rather than firmware, a helper or a library of the same prefix.
func debianKernelSource(source string) bool {
	switch {
	case source == "linux", strings.HasPrefix(source, "linux-signed"), strings.HasPrefix(source, "linux-meta"):
		return true
	case strings.HasPrefix(source, "linux-firmware"), strings.HasPrefix(source, "linux-base"), strings.HasPrefix(source, "linux-atm"),
		strings.HasPrefix(source, "linux-tools"), strings.HasPrefix(source, "linux-sound"), source == "linux-ftpd", source == "linux-minidisc":
		return false
	}
	// Ubuntu's flavours: linux-hwe-6.8, linux-aws, linux-azure, linux-raspi,
	// linux-lowlatency, linux-oem-6.5 and others.
	for _, f := range []string{"linux-hwe", "linux-lts", "linux-aws", "linux-azure", "linux-gcp", "linux-gke", "linux-oracle", "linux-raspi", "linux-lowlatency", "linux-oem", "linux-ibm", "linux-kvm", "linux-nvidia", "linux-realtime", "linux-intel"} {
		if strings.HasPrefix(source, f) {
			return true
		}
	}
	return false
}

// runningKernel reports whether a kernel package is the one running: its
// name ends in the release (Debian, Ubuntu) or its version starts it (RPM).
func runningKernel(ecosystem string, p Installed, running string) bool {
	if running == "" {
		return false
	}
	switch family(ecosystem) {
	case "Debian", "Ubuntu":
		return strings.HasSuffix(p.Name, "-"+running) || strings.HasSuffix(strings.TrimSuffix(p.Name, "-signed"), "-"+running)
	case "AlmaLinux", "Rocky Linux", "openSUSE", "Red Hat":
		return strings.HasPrefix(running, dropEpoch(p.Version))
	case "Alpine", "Wolfi", "Chainguard":
		v, _, _ := strings.Cut(p.Version, "-r")
		return strings.HasPrefix(running, v)
	}
	return false
}

// IsKernel reports whether a checked package (as Checked names it) is a
// kernel: Debian's and Ubuntu's kernel sources and flavours, the RPM
// distributions' kernel binaries, Alpine's kernels and Proxmox's.
func IsKernel(name string) bool {
	switch {
	case name == "kernel", strings.HasPrefix(name, "kernel-"):
		return true
	case strings.HasPrefix(name, "proxmox-kernel-"), strings.HasPrefix(name, "pve-kernel-"), strings.HasPrefix(name, "linux-image-"):
		return true
	case name == "linux-lts", name == "linux-virt", name == "linux-rpi", name == "linux-edge":
		return true
	}
	return debianKernelSource(name) && !strings.HasPrefix(name, "linux-meta")
}
