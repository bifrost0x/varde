// SPDX-License-Identifier: Apache-2.0

package registry

import "testing"

// A registry names its token service; Varde follows it only on the
// registry's own host or domain, or to a known token service.
func TestRealmAllowed(t *testing.T) {
	for _, c := range []struct {
		registry, realm string
		ok              bool
	}{
		{"registry-1.docker.io", "auth.docker.io", true},
		{"ghcr.io", "ghcr.io", true},
		{"lscr.io", "ghcr.io", true},
		{"quay.io", "quay.io", true},
		{"registry.example.com:5000", "registry.example.com", true},
		{"evil.example", "10.0.0.1", false},
		{"evil.example", "internal.lan", false},
		{"evil.example", "metadata.google.internal", false},
		{"10.0.0.5:5000", "10.0.0.6", false},
		{"10.0.0.5:5000", "10.0.0.5", true},
		{"ghcr.io", "auth.docker.io", false},
	} {
		if got := realmAllowed(c.registry, c.realm); got != c.ok {
			t.Errorf("%s -> %s: %v, want %v", c.registry, c.realm, got, c.ok)
		}
	}
}
