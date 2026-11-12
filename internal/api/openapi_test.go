// SPDX-License-Identifier: Apache-2.0

package api

import (
	"os"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestOpenAPIInSync keeps docs/api/openapi.yaml and the route table equal.
func TestOpenAPIInSync(t *testing.T) {
	b, err := os.ReadFile("../../docs/api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string                    `yaml:"openapi"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Fatalf("openapi %q", doc.OpenAPI)
	}
	var spec, code []string
	for path, ops := range doc.Paths {
		for method := range ops {
			if method == "parameters" {
				continue
			}
			spec = append(spec, strings.ToUpper(method)+" "+path)
		}
	}
	for _, r := range Routes() {
		code = append(code, r.Method+" /"+r.Path)
	}
	sort.Strings(spec)
	sort.Strings(code)
	if strings.Join(spec, "\n") != strings.Join(code, "\n") {
		t.Errorf("spec and routes differ\nspec:\n%s\n\nroutes:\n%s", strings.Join(spec, "\n"), strings.Join(code, "\n"))
	}
}
