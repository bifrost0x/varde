// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/imageref"
	"github.com/bifrost0x/varde/internal/inventory"
)

// TestLiveResolve asks the real registries for the corpus images whose
// version nothing states and writes the answers to VARDE_LIVE_REGISTRY_OUT.
// It only runs with VARDE_LIVE_REGISTRY=1; it refreshes the corpus, it is not
// part of CI.
func TestLiveResolve(t *testing.T) {
	if os.Getenv("VARDE_LIVE_REGISTRY") != "1" {
		t.Skip("set VARDE_LIVE_REGISTRY=1 to query the real registries")
	}
	cat, err := catalog.Load(catalogdata.FS(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../eval/testdata/corpus/containers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Image  string            `yaml:"image"`
			Digest string            `yaml:"digest"`
			Labels map[string]string `yaml:"image_labels"`
			Truth  struct {
				App     string `yaml:"app"`
				Version string `yaml:"version"`
			} `yaml:"truth"`
		} `yaml:"cases"`
	}
	if err := yaml.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	var ws []inventory.Workload
	for _, cs := range corpus.Cases {
		ws = append(ws, inventory.Workload{Kind: inventory.KindContainer, Container: &inventory.Container{ImageRef: cs.Image, ImageLabels: cs.Labels}})
	}
	if cat, err = cat.WithDerived(coverage.DeriveApps(cat, nil, ws)); err != nil {
		t.Fatal(err)
	}
	if only := os.Getenv("VARDE_LIVE_REGISTRY_ONLY"); only != "" {
		var keep []struct {
			Image  string            `yaml:"image"`
			Digest string            `yaml:"digest"`
			Labels map[string]string `yaml:"image_labels"`
			Truth  struct {
				App     string `yaml:"app"`
				Version string `yaml:"version"`
			} `yaml:"truth"`
		}
		for _, cs := range corpus.Cases {
			if cs.Image == only {
				keep = append(keep, cs)
			}
		}
		corpus.Cases = keep
	}
	c := New(httpx.New(httpx.Options{Timeout: 30 * time.Second}))
	out := map[string]string{}
	for _, cs := range corpus.Cases {
		app, ok := cat.App(cs.Truth.App)
		if !ok {
			continue
		}
		ref, err := imageref.Parse(cs.Image)
		if err != nil {
			t.Fatal(err)
		}
		keep, less := TagOrder(app, ref.Repository)
		tag, err := c.Resolve(t.Context(), ref.Repository, cs.Digest, keep, less, TagLimit)
		switch {
		case err != nil:
			t.Logf("%s: %v", cs.Image, err)
			out[cs.Image] = "error: " + strings.SplitN(err.Error(), "\n", 2)[0]
		default:
			t.Logf("%s: %q (truth %q)", cs.Image, tag, cs.Truth.Version)
			out[cs.Image] = tag
		}
	}
	if p := os.Getenv("VARDE_LIVE_REGISTRY_OUT"); p != "" {
		b, _ := json.MarshalIndent(out, "", " ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
