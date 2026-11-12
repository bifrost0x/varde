// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The builders run in the project's build, never in an installation: the
// server must not contain the code that fetches pages and repositories.
func TestServerDoesNotContainTheBuilders(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list is not available: %v", err)
	}
	deps := string(out)
	if !strings.Contains(deps, "github.com/bifrost0x/varde/internal/feed") {
		t.Fatalf("unexpected dependency list:\n%.400s", deps)
	}
	for _, forbidden := range []string{"/internal/pkgbuild", "/internal/indexbuild", "/cmd/packagebuilder", "/cmd/indexbuilder"} {
		for _, dep := range strings.Split(deps, "\n") {
			if strings.HasSuffix(dep, forbidden) {
				t.Errorf("the server depends on %s", dep)
			}
		}
	}
}
