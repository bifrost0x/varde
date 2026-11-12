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

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/datapkg"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/settings"
	"github.com/bifrost0x/varde/internal/store"
)

type fakePackage struct {
	mu          sync.Mutex
	status      datapkg.Status
	res         feed.Result
	err         error
	calls       int
	hasDeadline bool
	noSource    bool
}

func (f *fakePackage) Status(context.Context) datapkg.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakePackage) UpdateNow(ctx context.Context) (feed.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	_, f.hasDeadline = ctx.Deadline()
	return f.res, f.err
}

func (f *fakePackage) NoSource(*catalog.App) bool { return f.noSource }

func (f *fakePackage) Available() bool { return f.status.Available }

// A page that only names the mode must not ask for the full status: that
// reads the database and the installed manifest on every render.
func TestModeDoesNotReadTheStatus(t *testing.T) {
	f := &countingPackage{fakePackage: fakePackage{status: datapkg.Status{Available: true}}}
	a := &app{d: Deps{Mode: "direct", Package: f}}
	if a.mode() != "package" || f.statusCalls != 0 {
		t.Errorf("mode %q, Status called %d times", a.mode(), f.statusCalls)
	}
}

type countingPackage struct {
	fakePackage
	statusCalls int
}

func (c *countingPackage) Status(ctx context.Context) datapkg.Status {
	c.statusCalls++
	return c.fakePackage.Status(ctx)
}

// Distribution packages are not in the data package: the guide's step for
// them is done only when their check is switched on.
func TestGuidePackageStepNeedsItsSwitch(t *testing.T) {
	deps := testDeps(t, withPackage(&fakePackage{status: datapkg.Status{Available: true}}))
	a := &app{d: deps}
	if a.packagesChecked() {
		t.Fatal("the package check counts as done although it is switched off")
	}
	if err := deps.Settings.Update(t.Context(), map[string]string{settings.KeyDirectOSV: "true"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !a.packagesChecked() {
		t.Error("the package check is not done after it was switched on")
	}
	// The static feed modes bring the data with the feed.
	deps.Package, deps.Mode = nil, "feed"
	if err := deps.Settings.Update(t.Context(), map[string]string{settings.KeyDirectOSV: "false"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if b := (&app{d: deps}); !b.packagesChecked() {
		t.Error("feed mode: the step is offered again")
	}
}

func withPackage(f *fakePackage) func(*Deps) { return func(d *Deps) { d.Package = f } }

func packageSection(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `id="package"`)
	if i < 0 {
		t.Fatal("no data package section")
	}
	section := body[i:]
	if j := strings.Index(section, "</section>"); j > 0 {
		section = section[:j]
	}
	return section
}

func TestPackageSectionStates(t *testing.T) {
	built := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	checked := time.Date(2026, 11, 11, 4, 0, 0, 0, time.UTC)
	installed := datapkg.Status{Available: true, Channel: feed.ChannelPackage, Sequence: 1762743600, BuiltAt: built, CheckedAt: checked, VerifiedAt: checked}
	failed, tooOld, viaUplink := installed, installed, installed
	failed.LastError = "https://mirror.example: connection refused"
	tooOld.LastError, tooOld.TooOld = "manifest: schema 2", true
	viaUplink.Channel = feed.ChannelUplink
	for name, tc := range map[string]struct {
		status  datapkg.Status
		want    []string
		wantNot []string
	}{
		"unavailable": {datapkg.Status{Reason: "This build has no trust root for it yet."},
			[]string{"The data package is not available in this installation: This build has no trust root for it yet.", "Varde asks the public sources itself."},
			[]string{`action="/settings/package/update"`, `name="DIRECT_QUERIES"`}},
		"nothing installed": {datapkg.Status{Available: true},
			[]string{"one signed package the project builds once a day", "No package installed yet. Varde fetches it with the next check.", `action="/settings/package/update"`, "Update now", `name="DIRECT_QUERIES"`},
			[]string{"In use:"}},
		"installed": {installed,
			[]string{"In use: package 1762743600, built", "last checked", "Update now", "Also ask public sources directly", "api.github.com"},
			[]string{"The last check failed", "too old"}},
		"failed": {failed,
			[]string{"The last check failed: https://mirror.example: connection refused. The package above stays in use.", "In use: package 1762743600"}, nil},
		"too old": {tooOld,
			[]string{"This Varde version is too old for the current data package. Update Varde; until then the package above stays in use."},
			[]string{"The last check failed"}},
		"uplink in its place": {viaUplink,
			[]string{"The uplink is switched on and takes the place of the data package."}, []string{"In use: package"}},
	} {
		h := newHarness(t, withPackage(&fakePackage{status: tc.status}))
		h.signIn(t)
		_, body := h.do(t, "GET", "/settings", nil, nil)
		section := packageSection(t, body)
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
	// Without a manager the page says the package is not available.
	h := newHarness(t)
	h.signIn(t)
	_, body := h.do(t, "GET", "/settings", nil, nil)
	if s := packageSection(t, body); !strings.Contains(s, "not available in this installation") || strings.Contains(s, "Update now") {
		t.Error("section without a manager")
	}
}

func TestPackageUpdateNow(t *testing.T) {
	f := &fakePackage{status: datapkg.Status{Available: true}, res: feed.Result{Applied: true, Sequence: 7}}
	h := newHarness(t, withPackage(f))
	csrf := h.signIn(t)

	resp, _ := h.do(t, "POST", "/settings/package/update", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings?ok=package#package" {
		t.Fatalf("applied: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if f.calls != 1 || !f.hasDeadline {
		t.Fatalf("calls %d, deadline %v", f.calls, f.hasDeadline)
	}
	_, body := h.do(t, "GET", "/settings?ok=package", nil, nil)
	if !strings.Contains(body, "Data package updated.") {
		t.Error("no flash after an update")
	}

	f.res = feed.Result{Unchanged: true, Sequence: 7}
	resp, _ = h.do(t, "POST", "/settings/package/update", url.Values{"csrf": {csrf}}, nil)
	if resp.Header.Get("Location") != "/settings?ok=package-current#package" {
		t.Fatalf("unchanged: %q", resp.Header.Get("Location"))
	}
	_, body = h.do(t, "GET", "/settings?ok=package-current", nil, nil)
	if !strings.Contains(body, "The data package is already current.") {
		t.Error("no flash for an unchanged package")
	}

	f.err = errors.New("manifest: signature threshold not met")
	resp, body = h.do(t, "POST", "/settings/package/update", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "Not updated: manifest: signature threshold not met") {
		t.Errorf("refused: %d", resp.StatusCode)
	}
	f.err = context.DeadlineExceeded
	resp, body = h.do(t, "POST", "/settings/package/update", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusGatewayTimeout || !strings.Contains(body, "Not updated: the package mirror did not answer in time.") {
		t.Errorf("timeout: %d", resp.StatusCode)
	}
	f.err = datapkg.ErrUnavailable
	resp, _ = h.do(t, "POST", "/settings/package/update", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("unavailable: %d", resp.StatusCode)
	}

	// Without the CSRF token, or with GET, nothing happens.
	n := f.calls
	resp, _ = h.do(t, "POST", "/settings/package/update", url.Values{}, nil)
	if resp.StatusCode == http.StatusSeeOther || f.calls != n {
		t.Errorf("no csrf: %d, calls %d", resp.StatusCode, f.calls-n)
	}
	resp, _ = h.do(t, "GET", "/settings/package/update", nil, nil)
	if (resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound) || f.calls != n {
		t.Errorf("GET: %d, calls %d", resp.StatusCode, f.calls-n)
	}

	log, _ := h.store.AuditLog(t.Context(), 20)
	seen := false
	for _, e := range log {
		seen = seen || e.Action == "package.update"
	}
	if !seen {
		t.Error("no audit entry package.update")
	}

	// Without a manager the route answers, and says why.
	h = newHarness(t)
	csrf = h.signIn(t)
	resp, _ = h.do(t, "POST", "/settings/package/update", url.Values{"csrf": {csrf}}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("no manager: %d", resp.StatusCode)
	}
}

func TestDirectQueriesSwitchSaves(t *testing.T) {
	h := newHarness(t, withPackage(&fakePackage{status: datapkg.Status{Available: true}}))
	csrf := h.signIn(t)
	resp, _ := h.do(t, "POST", "/settings", url.Values{"csrf": {csrf}, settings.KeyDirectQueries: {"false", "true"}}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	_, body := h.do(t, "GET", "/settings", nil, nil)
	if s := packageSection(t, body); !strings.Contains(s, `name="DIRECT_QUERIES" value="true" checked`) {
		t.Error("switch not shown as on")
	}
}

func TestModeNamesThePackage(t *testing.T) {
	a := &app{d: Deps{Mode: "direct", Package: &fakePackage{status: datapkg.Status{Available: true}}}}
	if a.mode() != "package" {
		t.Errorf("package available: %q", a.mode())
	}
	a = &app{d: Deps{Mode: "direct", Package: &fakePackage{}}}
	if a.mode() != "direct" {
		t.Errorf("package unavailable: %q", a.mode())
	}
}

// An app nothing is asked about is listed as such, never as covered.
func TestNoAdvisorySourceIsShown(t *testing.T) {
	seed := func(h *harness) {
		ctx := t.Context()
		now := time.Now()
		_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
		_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
			{Kind: inventory.KindContainer, RuntimeID: "c1", Name: "immich", Container: &inventory.Container{ImageRef: "ghcr.io/immich-app/immich-server:v1.120.0"}},
		}, now)
		ws, err := h.store.Workloads(ctx, store.WorkloadFilter{})
		if err != nil || len(ws) != 1 {
			t.Fatalf("workloads: %v, %v", ws, err)
		}
		if err := h.store.ReplaceIdentifications(ctx, []identify.Result{{WorkloadID: ws[0].ID, AppID: "immich", Confidence: identify.Exact, Version: "1.120.0"}}, now); err != nil {
			t.Fatal(err)
		}
	}
	h := newHarness(t, withPackage(&fakePackage{status: datapkg.Status{Available: true}, noSource: true}))
	h.signIn(t)
	seed(h)
	_, body := h.do(t, "GET", "/systems/gaps", nil, nil)
	if !strings.Contains(body, "Apps with no advisory source") || !strings.Contains(body, "no advisory source</span>") || !strings.Contains(body, "Immich") {
		t.Error("an app without any advisory source is not listed")
	}
	// The overview must not call it checked either.
	if _, body := h.do(t, "GET", "/", nil, nil); strings.Contains(body, "All clear") {
		t.Error("the overview says all clear although no app was checked")
	}
	h = newHarness(t, withPackage(&fakePackage{status: datapkg.Status{Available: true}}))
	h.signIn(t)
	seed(h)
	if _, body := h.do(t, "GET", "/systems/gaps", nil, nil); strings.Contains(body, "Apps with no advisory source") {
		t.Error("section shown although every app has a source")
	}
}
