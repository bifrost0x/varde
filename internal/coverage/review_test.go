// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"testing"
	"testing/fstest"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
)

// identifyAll derives as the analysis does and identifies every workload.
func identifyAll(t *testing.T, lookup ImageLookup, ws []inventory.Workload) map[string]identify.Result {
	t.Helper()
	base, err := catalog.Load(fstest.MapFS{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := base.WithDerived(DeriveApps(base, lookup, ws))
	if err != nil {
		t.Fatalf("derived entries rejected: %v", err)
	}
	out := map[string]identify.Result{}
	for _, w := range ws {
		out[w.ID] = identify.Identify(cat, w)
	}
	return out
}

func reversed(ws []inventory.Workload) []inventory.Workload {
	out := make([]inventory.Workload, len(ws))
	for i, w := range ws {
		out[len(ws)-1-i] = w
	}
	return out
}

// Confirmation belongs to the image, not to the app: an image one list
// knows stays unconfirmed although another image of the same project is
// confirmed, in any order of the containers.
func TestConfirmationIsPerImage(t *testing.T) {
	lookup := listLookup(map[string]struct {
		repo  string
		lists []string
	}{
		"ghcr.io/plankanban/planka":  {"github.com/plankanban/planka", []string{"umbrel", "unraid"}},
		"docker.io/meltyshev/planka": {"github.com/plankanban/planka", []string{"unraid"}},
		"docker.io/rspamd/rspamd":    {"github.com/marcelverdult/imap-spamfilter", []string{"unraid"}},
	})
	ws := []inventory.Workload{
		cw("both", "ghcr.io/plankanban/planka:2.0.0", nil),
		cw("one", "meltyshev/planka:1.9.0", nil),
		cw("labelled", "ghcr.io/marcelverdult/imap-spamfilter:1.0.0", map[string]string{identify.LabelOCISource: "https://github.com/marcelverdult/imap-spamfilter"}),
		cw("beside", "rspamd/rspamd:3.9.0", nil),
	}
	for name, order := range map[string][]inventory.Workload{"given": ws, "reversed": reversed(ws)} {
		got := identifyAll(t, lookup, order)
		if r := got["both"]; r.AppID != "gh-plankanban-planka" || r.Derived {
			t.Errorf("%s: two lists: %+v", name, r)
		}
		if r := got["one"]; r.AppID != "gh-plankanban-planka" || !r.Derived {
			t.Errorf("%s: one list beside a confirmed image of the project must stay unconfirmed: app %s, derived %v", name, r.AppID, r.Derived)
		}
		if r := got["labelled"]; r.AppID != "gh-marcelverdult-imap-spamfilter" || r.Derived {
			t.Errorf("%s: source label: %+v", name, r)
		}
		if r := got["beside"]; r.AppID != "" && !r.Derived {
			t.Errorf("%s: an image a template lists beside its project became a confirmed %s", name, r.AppID)
		}
	}
}

// The path on GitHub's registry is a guess, not the publisher's word: a
// list that knows better decides, a list that agrees confirms, and alone
// the guess does not alert.
func TestGHCRGuess(t *testing.T) {
	lookup := listLookup(map[string]struct {
		repo  string
		lists []string
	}{
		"ghcr.io/hargata/lubelogger": {"github.com/hargata/lubelog", []string{"umbrel", "unraid"}},
		"ghcr.io/o/agrees":           {"github.com/o/agrees", []string{"unraid"}},
	})
	ws := []inventory.Workload{
		cw("renamed", "ghcr.io/hargata/lubelogger:v1", nil),
		cw("agrees", "ghcr.io/o/agrees:1.0.0", nil),
		cw("alone", "ghcr.io/gethomepage/homepage:v0.9.10", nil),
	}
	got := identifyAll(t, lookup, ws)
	if r := got["renamed"]; r.AppID != "gh-hargata-lubelog" || r.Derived {
		t.Errorf("lists know the repository: %+v", r)
	}
	if r := got["agrees"]; r.AppID != "gh-o-agrees" || r.Derived {
		t.Errorf("registry path and one list agree: %+v", r)
	}
	if r := got["alone"]; r.AppID != "gh-gethomepage-homepage" || !r.Derived {
		t.Errorf("registry path alone must not alert: app %s, derived %v", r.AppID, r.Derived)
	}
	// Without the lists the guess is all there is.
	if r := identifyAll(t, nil, ws)["renamed"]; r.AppID != "gh-hargata-lubelogger" || !r.Derived {
		t.Errorf("without lists: %+v", r)
	}
}

// Whatever the containers look like, the derived entries are accepted:
// one bad pair must not cost every derived app.
func TestDerivedEntriesNeverCollide(t *testing.T) {
	lookup := listLookup(map[string]struct {
		repo  string
		lists []string
	}{
		"docker.io/x/one": {"github.com/foo-bar/baz", []string{"unraid"}},
		"docker.io/x/two": {"github.com/foo/bar-baz", []string{"unraid"}},
	})
	ws := []inventory.Workload{
		// The same image once without and once with an upstream label.
		cw("plain", "ghcr.io/retropex/datum-gateway:1", nil),
		cw("upstream", "ghcr.io/retropex/datum-gateway:2", map[string]string{identify.LabelOCISource: "https://github.com/ocean-xyz/datum_gateway"}),
		// Two projects whose derived IDs would be the same.
		cw("one", "x/one:1", nil),
		cw("two", "x/two:1", nil),
	}
	for name, order := range map[string][]inventory.Workload{"given": ws, "reversed": reversed(ws)} {
		got := identifyAll(t, lookup, order)
		if got["plain"].AppID != got["upstream"].AppID {
			t.Errorf("%s: one image, two apps: %s and %s", name, got["plain"].AppID, got["upstream"].AppID)
		}
		if a, b := got["one"].AppID, got["two"].AppID; a != "" && a == b {
			t.Errorf("%s: two projects merged into %s", name, a)
		}
	}
}

// A source label inherited from a base image matches an app another
// container derived; that match must not be confirmed for this image, and a
// label that disagrees with the lists suppresses them whatever it names.
func TestInheritedLabelIsNotConfirmed(t *testing.T) {
	label := map[string]string{identify.LabelOCISource: "https://github.com/foo/app"}
	lookup := listLookup(map[string]struct {
		repo  string
		lists []string
	}{
		"docker.io/o/elsewhere": {"github.com/o/project", []string{"umbrel", "unraid"}},
	})
	ws := []inventory.Workload{
		cw("own", "ghcr.io/foo/app:1.2.3", label),
		cw("inherits", "registry.lan/me/unrelated:7.0.0", label),
		cw("gitlab", "o/elsewhere:1", map[string]string{identify.LabelOCISource: "https://gitlab.com/o/other"}),
	}
	got := identifyAll(t, lookup, ws)
	if r := got["own"]; r.AppID != "gh-foo-app" || r.Derived {
		t.Errorf("own image: %+v", r)
	}
	if r := got["inherits"]; r.AppID != "" && !r.Derived {
		t.Errorf("an unrelated image with an inherited label is a confirmed %s at %s", r.AppID, r.Version)
	}
	if r := got["gitlab"]; r.AppID != "" {
		t.Errorf("a label naming another place did not suppress the lists: %s", r.AppID)
	}
}

// Two tags of one image repository, only one with the source label: the
// repository is the app's image, so both containers are recognised.
func TestUnlabelledSiblingIsRecognised(t *testing.T) {
	ws := []inventory.Workload{
		cw("labelled", "grafana/grafana:13.3.0", map[string]string{identify.LabelOCISource: "https://github.com/grafana/grafana"}),
		cw("plain", "grafana/grafana:12.0.0", nil),
	}
	for name, order := range map[string][]inventory.Workload{"given": ws, "reversed": reversed(ws)} {
		got := identifyAll(t, nil, order)
		for _, id := range []string{"labelled", "plain"} {
			if r := got[id]; r.AppID != "gh-grafana-grafana" || r.Derived {
				t.Errorf("%s: %s: app %q, derived %v", name, id, r.AppID, r.Derived)
			}
		}
	}
}

// A source label with a path into the repository names that repository.
func TestLabelWithPathAgreesWithLists(t *testing.T) {
	lookup := listLookup(map[string]struct {
		repo  string
		lists []string
	}{
		"docker.io/x/image": {"github.com/o/project", []string{"umbrel", "unraid"}},
	})
	for _, label := range []string{"https://github.com/o/project/tree/main", "https://github.com/O/Project/commit/abc123", "https://github.com/o/project.git", "https://github.com/o/project/"} {
		got := identifyAll(t, lookup, []inventory.Workload{cw("c", "x/image:1.0.0", map[string]string{identify.LabelOCISource: label})})
		if r := got["c"]; r.AppID != "gh-o-project" || r.Derived {
			t.Errorf("label %q: app %q, derived %v", label, r.AppID, r.Derived)
		}
	}
}

// A manual entry names the app itself; there is no image to confirm.
func TestManualEntryOfDerivedAppIsExplicit(t *testing.T) {
	base, _ := catalog.Load(fstest.MapFS{}, nil)
	ws := []inventory.Workload{cw("c", "ghcr.io/gethomepage/homepage:v1", nil)}
	cat, err := base.WithDerived(DeriveApps(base, nil, ws))
	if err != nil {
		t.Fatal(err)
	}
	manual := inventory.Workload{ID: "m", Kind: inventory.KindManual, Name: "homepage on the NAS",
		Manual: &inventory.Manual{AppID: "gh-gethomepage-homepage", Version: "1.2.3"}}
	if r := identify.Identify(cat, manual); r.AppID != "gh-gethomepage-homepage" || r.Derived || r.Doubt() != "" {
		t.Errorf("manual entry: %+v doubt %q", r, r.Doubt())
	}
}
