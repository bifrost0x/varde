// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"strings"
	"testing"
)

func withProbe(extra string) string {
	return strings.Replace(validEntry, "  scheme: semver", "  scheme: semver\n  probe:\n    http:\n      path: /api/version\n      json_pointer: /version"+extra, 1)
}

func withPackage(line string) string {
	return strings.Replace(validEntry, "oci_source:", "packages:\n  - "+line+"\noci_source:", 1)
}

func TestProbeAndPackageRejects(t *testing.T) {
	cases := map[string]string{
		// A version without proof of the product could come from anything
		// on the port.
		"probe without expect":     withProbe(""),
		"probe empty expect value": withProbe("\n      expect: {/name: ''}"),
		"probe expect no pointer":  withProbe("\n      expect: {name: Immich}"),
		"probe pattern no group":   withProbe("\n      expect: {/name: Immich}\n      version_pattern: '^(\\d+)$'"),
		"probe check path escapes": withProbe("\n      expect: {/name: Immich}\n      check_path: //evil/x"),
		"probe path traversal":     strings.Replace(withProbe("\n      expect: {/name: Immich}"), "path: /api/version", "path: /api/../admin", 1),
		"package bad versioning":   withPackage("{manager: dpkg, name: immich, versioning: latest}"),
		"package pattern no group": withPackage(`{manager: dpkg, name: immich, versioning: upstream, version_pattern: '^\d+'}`),
		"service pattern":          strings.Replace(validEntry, "oci_source:", "services:\n  - {unit: 'immich*.service'}\noci_source:", 1),
	}
	for name, doc := range cases {
		if _, err := Parse(name, []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProbeAndPackageParse(t *testing.T) {
	doc := withProbe("\n      version_pattern: '^(?P<v>\\d+\\.\\d+\\.\\d+)'\n      expect: {/name: Immich}")
	doc = strings.Replace(doc, "oci_source:", "packages:\n  - {manager: dpkg, name: immich-server}\n  - {manager: rpm, name: immich, versioning: upstream}\noci_source:", 1)
	app, err := Parse("immich.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if app.Version.Probe.HTTP.Pattern() == nil || !app.Packages[1].Upstream() {
		t.Errorf("parsed %+v", app)
	}
	// Distribution packages are the default: never compared with ranges.
	if app.Packages[0].Upstream() || app.Packages[0].Versioning != VersioningDistro {
		t.Errorf("default versioning %q", app.Packages[0].Versioning)
	}
}

func TestPackageBelongsToOneApp(t *testing.T) {
	a := withPackage("{manager: dpkg, name: shared}")
	b := strings.Replace(entry("other", "ghcr.io/x/other"), "oci_source:", "packages:\n  - {manager: dpkg, name: shared}\noci_source:", 1)
	appA, errA := Parse("a.yaml", []byte(a))
	appB, errB := Parse("b.yaml", []byte(b))
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if _, err := newCatalog(map[string]*App{appA.ID: appA, appB.ID: appB}); err == nil || !strings.Contains(err.Error(), "package dpkg shared") {
		t.Errorf("duplicate package accepted: %v", err)
	}
}
