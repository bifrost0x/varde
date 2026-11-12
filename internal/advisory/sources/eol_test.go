// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"net/http"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

func TestEOLRefresh(t *testing.T) {
	u := newUpstream(t, func(_ *upstream, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/products/nginx":
			_, _ = w.Write([]byte(`{"result":{"name":"nginx","releases":[
				{"name":"1.31","isEol":false,"eolFrom":null,"latest":{"name":"1.31.8"}},
				{"name":"1.29","isEol":true,"eolFrom":"2026-05-13","latest":{"name":"1.29.8"}},
				{"name":"","isEol":true},
				{"name":"1.1","isEol":true,"eolFrom":"not a date"}]}}`))
		case "/api/v1/products/other":
			// An answer that does not name the product asked for.
			_, _ = w.Write([]byte(`{"result":{"name":"nginx","releases":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := newStore(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	e := &EOL{Deps: deps(u, s, &now), EOLStore: s, BaseURL: u.srv.URL}
	nginx := appWith("nginx", catalog.Advisories{})
	nginx.EOL = "nginx"
	other := appWith("other", catalog.Advisories{})
	other.EOL = "other"
	none := appWith("none", catalog.Advisories{})
	res, err := e.Refresh(t.Context(), []*catalog.App{nginx, other, none})
	if err != nil || res.Updated != 1 || res.Requests != 2 || res.Skipped != 1 {
		t.Fatalf("refresh: %+v %v", res, err)
	}
	got, _ := s.EOL(t.Context())
	rel := got["nginx"]
	if len(rel) != 3 || rel[1] != (store.EOLRelease{Name: "1.29", IsEOL: true, EOLFrom: "2026-05-13", Latest: "1.29.8"}) || rel[2].EOLFrom != "" {
		t.Fatalf("stored: %+v", rel)
	}
	if _, ok := got["other"]; ok {
		t.Error("answer for another product stored")
	}
	// Daily: not asked again the same day.
	if res, _ := e.Refresh(t.Context(), []*catalog.App{nginx}); res.Requests != 0 {
		t.Errorf("asked again: %+v", res)
	}
	for v, want := range map[string]string{"1.29.8": "1.29", "1.31.0": "1.31", "1.3.1": "", "1.29": "1.29"} {
		line, ok := EOLLine(rel, v)
		if ok != (want != "") || line.Name != want {
			t.Errorf("%s: %+v %v, want %q", v, line, ok, want)
		}
	}
}
