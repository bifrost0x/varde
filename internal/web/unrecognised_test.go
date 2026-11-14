// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
)

// The list names public repositories once each, sorted, and nothing that
// identifies the installation.
func TestUnrecognisedList(t *testing.T) {
	text, listed, withheld := unrecognisedList([]gap{
		{Workload: "paperless-prod", Image: "ghcr.io/acme/tool:1.2.3", Repository: "ghcr.io/acme/tool", Host: "nas.home.arpa"},
		{Workload: "tool-2", Image: "ghcr.io/acme/tool:1.2.4", Repository: "ghcr.io/acme/tool"},
		{Workload: "x", Image: "someone/app:latest", Repository: "docker.io/someone/app"},
		{Workload: "internal", Image: "registry.corp.example/team/secret-app:7", Repository: "registry.corp.example/team/secret-app"},
		{Workload: "no-repo"},
	})
	if listed != 2 || withheld != 1 {
		t.Fatalf("listed %d, withheld %d", listed, withheld)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		if !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if strings.Join(lines, ",") != "docker.io/someone/app,ghcr.io/acme/tool" {
		t.Errorf("lines = %v", lines)
	}
	for _, leak := range []string{"1.2.3", "latest", "paperless-prod", "nas.home.arpa", "corp.example", "secret-app"} {
		if strings.Contains(text, leak) {
			t.Errorf("the list contains %q", leak)
		}
	}
}

func TestUnrecognisedDownload(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.do(t, "GET", "/systems/gaps/unrecognised.txt", nil, nil); resp.StatusCode == 200 {
		t.Fatal("served without a sign-in")
	}
	h.signIn(t)
	resp, body := h.do(t, "GET", "/systems/gaps/unrecognised.txt", nil, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "# Images Varde does not recognise") {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}
