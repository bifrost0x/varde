// SPDX-License-Identifier: Apache-2.0

package purl

import "testing"

func TestBuild(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		// Examples from the PURL specification.
		{Docker("docker.io/library/cassandra", "latest"), "pkg:docker/cassandra@latest"},
		{Docker("docker.io/smartentry/debian", "dc437cc87d10"), "pkg:docker/smartentry/debian@dc437cc87d10"},
		{Docker("gcr.io/customer/dockerimage", "sha256:244fd47e07d10"), "pkg:docker/customer/dockerimage@sha256%3A244fd47e07d10?repository_url=gcr.io"},
		{Package("dpkg", "debian-13", "curl", "8.14.1-2"), "pkg:deb/debian/curl@8.14.1-2?distro=debian-13"},
		{Package("rpm", "fedora-42", "setup", "2.15.0-13.fc42"), "pkg:rpm/fedora/setup@2.15.0-13.fc42?distro=fedora-42"},
		{Package("apk", "alpine-3.22", "musl", "1.2.5-r10"), "pkg:apk/alpine/musl@1.2.5-r10?distro=alpine-3.22"},
		{Package("dpkg", "debian-13", "pve-manager", "1:9.2.26"), "pkg:deb/debian/pve-manager@1%3A9.2.26?distro=debian-13"},
		{Package("pip", "", "x", "1"), ""},
		{Docker("nginx", "1"), ""},
	} {
		if c.got != c.want {
			t.Errorf("got %s, want %s", c.got, c.want)
		}
	}
}
