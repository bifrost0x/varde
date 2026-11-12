// SPDX-License-Identifier: Apache-2.0

package distro

import (
	"testing"
	"time"
)

func checkedMap(pkgs []Package) map[string]string {
	out := map[string]string{}
	for _, p := range pkgs {
		out[p.Name] = p.Version
	}
	return out
}

// AlmaLinux and Rocky Linux publish binary names: krb5-libs, not krb5.
func TestCheckedRPMBinaryNames(t *testing.T) {
	got := checkedMap(Checked("almalinux-9.4", []Installed{
		{Manager: "rpm", Name: "krb5-libs", Version: "0:1.21.1-1.el9", Source: "krb5"},
		{Manager: "rpm", Name: "python3-libs", Version: "0:3.9.18-1.el9", Source: "python3.9"},
		{Manager: "rpm", Name: "nginx", Version: "1:1.26.1-1.el9.ngx", Source: "nginx"},
	}, CheckOptions{}))
	if got["krb5-libs"] != "0:1.21.1-1.el9" || got["python3-libs"] == "" || got["krb5"] != "" {
		t.Fatalf("checked: %v", got)
	}
	if _, ok := got["nginx"]; ok {
		t.Fatal("a vendor build was checked")
	}
}

// Debian's signed kernel is checked as "linux" at the running kernel's
// version; headers and linux-libc-dev are not the kernel.
func TestCheckedDebianKernel(t *testing.T) {
	pkgs := []Installed{
		{Manager: "dpkg", Name: "linux-image-6.1.0-18-amd64", Version: "6.1.76-1", Source: "linux-signed-amd64"},
		{Manager: "dpkg", Name: "linux-image-6.1.0-28-amd64", Version: "6.1.119-1", Source: "linux-signed-amd64"},
		{Manager: "dpkg", Name: "linux-headers-6.1.0-28-common", Version: "6.1.119-1", Source: "linux"},
		{Manager: "dpkg", Name: "linux-libc-dev", Version: "6.1.119-1", Source: "linux"},
		{Manager: "dpkg", Name: "linux-image-amd64", Version: "6.1.119-1", Source: "linux-signed-amd64"},
		{Manager: "dpkg", Name: "firmware-linux-free", Version: "20200122-1", Source: "linux-firmware-free"},
	}
	got := checkedMap(Checked("debian-12", pkgs, CheckOptions{Kernel: "6.1.0-18-amd64"}))
	if got["linux"] != "6.1.76-1" {
		t.Fatalf("running kernel: %v", got)
	}
	if _, ok := got["linux-signed-amd64"]; ok {
		t.Fatal("the signed source name was checked")
	}
	if got["linux-firmware-free"] == "" {
		t.Fatal("firmware is not a kernel and is checked")
	}
	// Without the running kernel: the newest.
	if got := checkedMap(Checked("debian-12", pkgs, CheckOptions{})); got["linux"] != "6.1.119-1" {
		t.Fatalf("newest kernel: %v", got)
	}
	// In an image: no kernel at all.
	if got := checkedMap(Checked("debian-12", pkgs, CheckOptions{Image: true})); got["linux"] != "" {
		t.Fatalf("kernel checked in an image: %v", got)
	}
}

func TestCheckedUbuntuHWE(t *testing.T) {
	got := checkedMap(Checked("ubuntu-22.04", []Installed{
		{Manager: "dpkg", Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45~22.04.1", Source: "linux-signed-hwe-6.8"},
	}, CheckOptions{Kernel: "6.8.0-45-generic"}))
	if got["linux-hwe-6.8"] != "6.8.0-45.45~22.04.1" {
		t.Fatalf("hwe kernel: %v", got)
	}
	if !IsKernel("linux-hwe-6.8") || !IsKernel("linux") || !IsKernel("kernel-core") || IsKernel("linux-firmware") || IsKernel("openssl") {
		t.Fatal("IsKernel")
	}
}

// A binNMU's source version decides, not the binary's.
func TestCheckedSourceVersion(t *testing.T) {
	got := checkedMap(Checked("debian-12", []Installed{
		{Manager: "dpkg", Name: "libpython3-stdlib", Version: "3.11.2-1+b1", Source: "python3-defaults", SourceVersion: "3.11.2-1"},
		{Manager: "dpkg", Name: "python3", Version: "3.11.2-1+b1", Source: "python3-defaults", SourceVersion: "3.11.2-1"},
	}, CheckOptions{}))
	if got["python3-defaults"] != "3.11.2-1" {
		t.Fatalf("source version: %v", got)
	}
}

func TestRaspbianAndUbuntuPro(t *testing.T) {
	if eco, mgr, ok := Ecosystem("raspbian-11"); !ok || eco != "Debian:11" || mgr != "dpkg" {
		t.Fatalf("raspbian: %s %s %v", eco, mgr, ok)
	}
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	if v := Variants("Ubuntu:20.04:LTS", now); len(v) != 2 || v[1] != "Ubuntu:Pro:20.04:LTS" {
		t.Fatalf("20.04: %v", v)
	}
	if v := Variants("Ubuntu:24.04:LTS", now); len(v) != 1 {
		t.Fatalf("24.04 is in standard support: %v", v)
	}
	if !SameRelease("Ubuntu:Pro:20.04:LTS", "Ubuntu:20.04:LTS", now) || SameRelease("Ubuntu:Pro:22.04:LTS", "Ubuntu:22.04:LTS", now) {
		t.Fatal("SameRelease")
	}
}
