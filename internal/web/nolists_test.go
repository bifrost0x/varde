// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// An installation downloads nothing to recognise apps: there is no switch
// for app store lists, and no setting of that name is accepted.
func TestNoAppListsSwitch(t *testing.T) {
	h := newHarness(t)
	csrf := h.signIn(t)
	_, body := h.do(t, "GET", "/settings", nil, nil)
	for _, gone := range []string{"APP_LISTS", "app store lists", "Umbrel", "Unraid"} {
		if strings.Contains(body, gone) {
			t.Errorf("settings page still mentions %q", gone)
		}
	}
	resp, _ := h.do(t, "POST", "/settings", url.Values{"csrf": {csrf}, "APP_LISTS": {"true"}}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("posting an unknown key: %d", resp.StatusCode)
	}
	if v, _ := h.store.Settings(t.Context()); v["APP_LISTS"] != "" {
		t.Errorf("APP_LISTS stored: %q", v["APP_LISTS"])
	}
}
