// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/fleet"
)

func withAgentBinaries(t *testing.T) func(*Deps) {
	return func(d *Deps) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "varde-linux-amd64"), []byte("agent"), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := fleet.LoadBinaries(dir)
		if err != nil {
			t.Fatal(err)
		}
		d.AgentBinaries, d.AgentCAPin, d.AgentListenAddr = b, strings.Repeat("ab", 32), ":8443"
	}
}

func TestAgentInstallPage(t *testing.T) {
	// Without binaries the page says why and offers no form.
	h := newHarness(t, withNetwork(t), func(d *Deps) { d.AgentCAPin, d.AgentListenAddr = strings.Repeat("ab", 32), ":8443" })
	h.signIn(t)
	_, body := h.do(t, "GET", "/connections/agents/install", nil, nil)
	if !strings.Contains(body, "ships no agent binaries") || strings.Contains(body, `name="password"`) {
		t.Fatal("install offered without agent binaries")
	}
	if _, body := h.do(t, "GET", "/connections/agents", nil, nil); strings.Contains(body, "/connections/agents/install") {
		t.Error("agents page links an installation that cannot work")
	}

	h = newHarness(t, withNetwork(t), withAgentBinaries(t))
	csrf := h.signIn(t)
	resp, body := h.do(t, "GET", "/connections/agents/install?address=192.168.1.30&address=192.168.1.31&address=x;rm", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, ">192.168.1.30\n192.168.1.31</textarea>") || strings.Contains(body, "x;rm") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("form: %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	if _, body := h.do(t, "GET", "/connections/agents", nil, nil); !strings.Contains(body, "/connections/agents/install") {
		t.Error("agents page does not offer the installation")
	}
	post := func(form url.Values) (*http.Response, string) {
		form.Set("csrf", csrf)
		return h.do(t, "POST", "/connections/agents/install", form, nil)
	}
	// Outside the allowed ranges nothing is contacted; the host cannot be
	// selected.
	resp, body = post(url.Values{"step": {"address"}, "addresses": {"10.9.9.9\n10.9.9.10"}, "port": {"22"}, "user": {"root"}})
	if resp.StatusCode != http.StatusOK || strings.Count(body, "outside the network ranges") != 2 || strings.Contains(body, `name="host"`) {
		t.Fatalf("out of scope: %d", resp.StatusCode)
	}
	// Installing without a selected, confirmed host does nothing.
	resp, body = post(url.Values{"step": {"install"}, "addresses": {"10.9.9.9"}, "port": {"22"}, "user": {"root"}, "confirm": {"yes"},
		"server_url": {"https://varde.lan:8443"}, "password": {"x"}, "host": {"10.9.9.9"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Select at least one host") {
		t.Fatalf("install without a reachable host: %d", resp.StatusCode)
	}
	if resp, _ := post(url.Values{"step": {"address"}, "addresses": {strings.Repeat("10.0.0.1\n", 21)}, "port": {"22"}, "user": {"root"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("too many hosts: %d", resp.StatusCode)
	}
	if resp, _ := post(url.Values{"step": {"address"}, "addresses": {"not;an address"}, "port": {"22"}, "user": {"root"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad address: %d", resp.StatusCode)
	}
	// Without the CSRF token nothing happens.
	if resp, _ := h.do(t, "POST", "/connections/agents/install", url.Values{"step": {"address"}, "addresses": {"192.168.1.30"}}, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", resp.StatusCode)
	}
}

func TestAgentURL(t *testing.T) {
	for in, ok := range map[string]bool{
		"https://varde.lan:8443":   true,
		"https://192.168.1.5:8443": true,
		"https://[fd00::5]:8443/":  true,
		"http://varde.lan:8443":    false,
		"https://varde.lan/x":      false,
		"https://u:p@varde.lan":    false,
		"https://varde.lan:8443?a": false,
		"https://varde.lan\nX=1":   false,
		"https://varde.lan$(id)":   false,
		"":                         false,
	} {
		if validAgentURL(in) != ok {
			t.Errorf("validAgentURL(%q) = %v", in, !ok)
		}
	}
	a := &app{d: Deps{AgentListenAddr: ":9443"}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "varde.lan:18080"
	if got := a.defaultAgentURL(r); got != "https://varde.lan:9443" {
		t.Errorf("default URL %q", got)
	}
	r.Host = "[fd00::5]:8080"
	if got := a.defaultAgentURL(r); got != "https://[fd00::5]:9443" {
		t.Errorf("default URL %q", got)
	}
}

func TestLoopbackURL(t *testing.T) {
	for in, want := range map[string]bool{
		"https://localhost:8443": true, "https://127.0.0.1:8443": true, "https://[::1]:8443": true, "https://varde.localhost:8443": true,
		"https://192.168.1.10:8443": false, "https://varde.lan:8443": false,
	} {
		if got := loopbackURL(in); got != want {
			t.Errorf("%s: got %v", in, got)
		}
	}
}
