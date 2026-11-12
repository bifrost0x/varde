// SPDX-License-Identifier: Apache-2.0

package web

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/identify"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pipeline"
)

// The inventory says what an automatic recognition rests on and whether it
// alerts. Everything here works without any download: the table of images
// ships with Varde.
func TestInventoryShowsDerivationBasis(t *testing.T) {
	var p *pipeline.Pipeline
	h := newHarness(t, func(d *Deps) {
		p = pipeline.New(d.Catalog.Current(), d.Store, slog.New(slog.DiscardHandler), pipeline.Options{})
		p.ImageIndex = func(image string) (string, []string, bool, bool) {
			switch image {
			case "docker.io/linkding/linkding":
				return "github.com/sissbruecker/linkding", []string{"hub", "readme"}, true, true
			case "docker.io/vabene1111/recipes":
				return "github.com/tandoorrecipes/recipes", []string{"readme"}, false, true
			}
			return "", nil, false, false
		}
		d.Catalog = p.Catalog()
	})
	h.signIn(t)
	ctx, now := t.Context(), time.Now()
	_ = h.store.UpsertHost(ctx, inventory.Host{ID: "local", Name: "nas", Kind: inventory.HostDocker, Source: inventory.SourceLocal, LastContact: now})
	c := func(id, ref string, labels map[string]string) inventory.Workload {
		return inventory.Workload{Kind: inventory.KindContainer, RuntimeID: id, Name: id, Container: &inventory.Container{ImageRef: ref, ImageLabels: labels}}
	}
	_, _ = h.store.ApplySnapshot(ctx, "local", inventory.KindContainer, []inventory.Workload{
		c("linkding", "linkding/linkding:1.36.0", nil),
		c("tandoor", "vabene1111/recipes:1.5.19", nil),
		c("homepage", "ghcr.io/gethomepage/homepage:v0.9.10", nil),
		c("grafana", "grafana/grafana:13.3.0", map[string]string{identify.LabelOCISource: "https://github.com/grafana/grafana"}),
		c("nobody", "nobody/nothing:1", nil),
	}, now)
	if _, err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	_, body := h.do(t, "GET", "/systems/apps", nil, nil)
	row := func(name string) string {
		i := strings.Index(body, ">"+name+"<")
		if i < 0 {
			t.Fatalf("no row for %s", name)
		}
		rest := body[i:]
		if j := strings.Index(rest, "</tr>"); j > 0 {
			rest = rest[:j]
		}
		return rest
	}
	// Two statements of the project: recognised and alerting.
	if r := row("linkding"); !strings.Contains(r, "recognised automatically") || !strings.Contains(r, "Stated by the project itself") ||
		!strings.Contains(r, "Docker Hub page links the project") || strings.Contains(r, "to get alerts") {
		t.Errorf("two kinds of evidence: %s", r)
	}
	// One statement: recognised, the user confirms to get alerts.
	if r := row("tandoor"); !strings.Contains(r, "recognised automatically") || !strings.Contains(r, "README names the image") ||
		!strings.Contains(r, "varde.app=gh-tandoorrecipes-recipes") || !strings.Contains(r, "to get alerts") {
		t.Errorf("one kind of evidence: %s", r)
	}
	// The registry path is a guess: recognised, but it does not alert.
	if r := row("homepage"); !strings.Contains(r, "recognised automatically") || !strings.Contains(r, "GitHub") || !strings.Contains(r, "to get alerts") {
		t.Errorf("ghcr app: %s", r)
	}
	if r := row("grafana"); !strings.Contains(r, "recognised automatically") || !strings.Contains(r, "source label") || strings.Contains(r, "to get alerts") {
		t.Errorf("label app: %s", r)
	}
	if r := row("nobody"); !strings.Contains(r, "not in catalog") || strings.Contains(r, "switch them on") {
		t.Errorf("unknown image: %s", r)
	}
}
