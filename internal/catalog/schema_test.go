// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestSchemaInSync keeps catalog/schema.json aligned with the Go types:
// every YAML field must appear in the schema and vice versa.
func TestSchemaInSync(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "catalog", "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schema.json: %v", err)
	}
	check := func(path string, typ reflect.Type, node map[string]any) {
		t.Helper()
		props, _ := node["properties"].(map[string]any)
		var inSchema, inGo []string
		for k := range props {
			inSchema = append(inSchema, k)
		}
		for i := 0; i < typ.NumField(); i++ {
			tag := strings.Split(typ.Field(i).Tag.Get("yaml"), ",")[0]
			if tag != "" && tag != "-" {
				inGo = append(inGo, tag)
			}
		}
		sort.Strings(inSchema)
		sort.Strings(inGo)
		if !reflect.DeepEqual(inSchema, inGo) {
			t.Errorf("%s: schema %v, Go %v", path, inSchema, inGo)
		}
	}
	props := schema["properties"].(map[string]any)
	check("entry", reflect.TypeOf(App{}), schema)
	check("version", reflect.TypeOf(VersionSpec{}), props["version"].(map[string]any))
	check("advisories", reflect.TypeOf(Advisories{}), props["advisories"].(map[string]any))
	check("exposure_hints", reflect.TypeOf(ExposureHints{}), props["exposure_hints"].(map[string]any))
	sources := props["version"].(map[string]any)["properties"].(map[string]any)["sources"].(map[string]any)["items"].(map[string]any)
	check("version.sources[]", reflect.TypeOf(VersionSource{}), sources)
	images := props["images"].(map[string]any)["items"].(map[string]any)
	check("images[]", reflect.TypeOf(Image{}), images)
}
