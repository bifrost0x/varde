// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/uplink"
)

type fakeUplink struct {
	mu        sync.Mutex
	status    uplink.Status
	enableErr error
	enabled   [][]byte
	disabled  int
	removed   int
	by        string
	// deadline of the context the last Enable ran with.
	deadline    time.Time
	hasDeadline bool
}

func (f *fakeUplink) Status() uplink.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeUplink) Enable(ctx context.Context, input []byte, by string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadline, f.hasDeadline = ctx.Deadline()
	f.enabled = append(f.enabled, input)
	f.by = by
	if f.enableErr == nil {
		f.status.State = uplink.Active
	}
	return f.enableErr
}

func (f *fakeUplink) Disable(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disabled++
	f.status.State = uplink.Off
	return nil
}

func (f *fakeUplink) Remove(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed++
	f.status = uplink.Status{State: uplink.Off}
	return nil
}

func withUplink(f *fakeUplink) func(*Deps) { return func(d *Deps) { d.Uplink = f } }

func TestUplinkSectionStates(t *testing.T) {
	until := time.Date(2027, 11, 25, 0, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		status  uplink.Status
		want    []string
		wantNot []string
	}{
		"unavailable": {uplink.Status{State: uplink.Unavailable},
			[]string{"not available in this build", "works completely without it"}, []string{`action="/settings/uplink"`}},
		"unavailable with reason": {uplink.Status{State: uplink.Unavailable, Reason: "development root refused"},
			[]string{"development root refused"}, []string{`action="/settings/uplink"`}},
		"off": {uplink.Status{State: uplink.Off},
			[]string{"asks the public sources itself", `action="/settings/uplink"`, `name="license"`, "Switch on"}, []string{"Switch off", "Remove license"}},
		"off with stored license": {uplink.Status{State: uplink.Off, LicenseID: "lic_abcdefghijklmnop", ExpiresAt: until},
			[]string{"lic_abcdefghijklmnop", "Switch on", "Remove license"}, []string{"Switch off"}},
		"active": {uplink.Status{State: uplink.Active, LicenseID: "lic_abcdefghijklmnop", ExpiresAt: until},
			[]string{"Active", "lic_abcdefghijklmnop", "2027-11-25", "Switch off"}, []string{"Development trust root"}},
		"active development": {uplink.Status{State: uplink.Active, LicenseID: "lic_abcdefghijklmnop", ExpiresAt: until, Development: true},
			[]string{"Development trust root: for tests only."}, nil},
		"expired": {uplink.Status{State: uplink.Expired, LicenseID: "lic_abcdefghijklmnop", ExpiresAt: until, Reason: "The license expired on 2027-11-25."},
			[]string{"The license expired on 2027-11-25.", "back on the public sources", `name="license"`, "Switch on"}, []string{"Switch off"}},
		"error": {uplink.Status{State: uplink.Failed, Reason: "The stored license cannot be read."},
			[]string{"The stored license cannot be read.", `name="license"`}, nil},
		"locked": {uplink.Status{State: uplink.Unavailable, Locked: true},
			[]string{"Set by VARDE_MODE in the environment."}, []string{`action="/settings/uplink"`, "not available in this build"}},
	} {
		h := newHarness(t, withUplink(&fakeUplink{status: tc.status}))
		h.signIn(t)
		_, body := h.do(t, "GET", "/settings", nil, nil)
		i := strings.Index(body, `id="uplink"`)
		if i < 0 {
			t.Fatalf("%s: no uplink section", name)
		}
		section := body[i:]
		if j := strings.Index(section, "</section>"); j > 0 {
			section = section[:j]
		}
		for _, w := range tc.want {
			if !strings.Contains(section, w) {
				t.Errorf("%s: section lacks %q", name, w)
			}
		}
		for _, w := range tc.wantNot {
			if strings.Contains(section, w) {
				t.Errorf("%s: section must not contain %q", name, w)
			}
		}
	}
	// Without a manager the page says the same as an unavailable uplink.
	h := newHarness(t)
	h.signIn(t)
	if _, body := h.do(t, "GET", "/settings", nil, nil); !strings.Contains(body, "not available in this build") {
		t.Error("no uplink section without a manager")
	}
}

func TestUplinkSwitch(t *testing.T) {
	f := &fakeUplink{status: uplink.Status{State: uplink.Off}}
	h := newHarness(t, withUplink(f))
	csrf := h.signIn(t)
	const license = `{"signed":{"license":"lic_secretsecretsecret"},"signature":"c2ln"}`

	resp, _ := h.do(t, "POST", "/settings/uplink", url.Values{"csrf": {csrf}, "license": {license}}, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings?ok=uplink#uplink" {
		t.Fatalf("enable: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if len(f.enabled) != 1 || string(f.enabled[0]) != license || f.by == "" {
		t.Fatalf("Enable got %q by %q", f.enabled, f.by)
	}

	// A refused license: the reason is shown, the license is not echoed.
	f.enableErr = errors.New("signature threshold not met")
	resp, body := h.do(t, "POST", "/settings/uplink", url.Values{"csrf": {csrf}, "license": {license}}, nil)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Not switched on: signature threshold not met") {
		t.Errorf("refused: %d", resp.StatusCode)
	}
	if strings.Contains(body, "lic_secretsecretsecret") {
		t.Error("the entered license is echoed back")
	}

	// Oversized input never reaches the manager.
	n := len(f.enabled)
	resp, _ = h.do(t, "POST", "/settings/uplink", url.Values{"csrf": {csrf}, "license": {strings.Repeat("A", 20<<10)}}, nil)
	if resp.StatusCode != http.StatusBadRequest || len(f.enabled) != n {
		t.Errorf("oversized: %d, manager called %v", resp.StatusCode, len(f.enabled) != n)
	}

	resp, _ = h.do(t, "POST", "/settings/uplink/disable", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusSeeOther || f.disabled != 1 {
		t.Errorf("disable: %d, calls %d", resp.StatusCode, f.disabled)
	}
	resp, _ = h.do(t, "POST", "/settings/uplink/remove", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusSeeOther || f.removed != 1 {
		t.Errorf("remove: %d, calls %d", resp.StatusCode, f.removed)
	}

	// Without the CSRF token nothing happens.
	resp, _ = h.do(t, "POST", "/settings/uplink/disable", url.Values{}, nil)
	if resp.StatusCode == http.StatusSeeOther || f.disabled != 1 {
		t.Errorf("no csrf: %d, calls %d", resp.StatusCode, f.disabled)
	}

	log, _ := h.store.AuditLog(t.Context(), 20)
	seen := map[string]bool{}
	for _, e := range log {
		seen[e.Action] = true
		if strings.Contains(e.Detail, "lic_secret") || strings.Contains(e.Detail, "signature") && e.Action == "uplink.enable" {
			t.Errorf("audit entry leaks the license: %+v", e)
		}
	}
	for _, a := range []string{"uplink.enable", "uplink.disable", "uplink.remove"} {
		if !seen[a] {
			t.Errorf("no audit entry %s", a)
		}
	}
}

func TestUplinkLocked(t *testing.T) {
	f := &fakeUplink{status: uplink.Status{State: uplink.Unavailable, Locked: true}, enableErr: uplink.ErrLocked}
	h := newHarness(t, withUplink(f))
	csrf := h.signIn(t)
	resp, _ := h.do(t, "POST", "/settings/uplink", url.Values{"csrf": {csrf}, "license": {"x"}}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("locked enable: %d", resp.StatusCode)
	}
}

// The pages name the mode that applies now, not the one at start.
func TestModeFollowsUplink(t *testing.T) {
	f := &fakeUplink{status: uplink.Status{State: uplink.Off}}
	a := &app{d: Deps{Mode: "direct", Uplink: f}}
	if a.mode() != "direct" {
		t.Errorf("off: %q", a.mode())
	}
	f.status.State = uplink.Active
	if a.mode() != "hybrid" {
		t.Errorf("active: %q", a.mode())
	}
}

// The switch-on runs inside the request; it must end before the server's
// write timeout cuts the answer off, and say so when the feed is slow.
func TestUplinkSwitchOnIsBounded(t *testing.T) {
	f := &fakeUplink{status: uplink.Status{State: uplink.Off}, enableErr: context.DeadlineExceeded}
	h := newHarness(t, withUplink(f))
	csrf := h.signIn(t)
	start := time.Now()
	resp, body := h.do(t, "POST", "/settings/uplink", url.Values{"csrf": {csrf}, "license": {"x"}}, nil)
	if !f.hasDeadline || f.deadline.Sub(start) > 26*time.Second || f.deadline.Sub(start) < 10*time.Second {
		t.Fatalf("Enable ran with deadline %v (set %v)", f.deadline.Sub(start), f.hasDeadline)
	}
	if resp.StatusCode != http.StatusGatewayTimeout || !strings.Contains(body, "did not answer in time") {
		t.Errorf("slow feed: %d", resp.StatusCode)
	}
}

func TestUplinkNoticeLink(t *testing.T) {
	if got := noticeLink(store.NoticeUplink); got != "/settings#uplink" {
		t.Errorf("link = %q", got)
	}
}
