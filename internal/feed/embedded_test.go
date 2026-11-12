// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"testing"
	"testing/fstest"
	"time"
)

func TestRootFrom(t *testing.T) {
	if got := rootFrom(fstest.MapFS{}); got != nil {
		t.Fatalf("root from an empty directory: %q", got)
	}
	fsys := fstest.MapFS{"roots/production.json": {Data: []byte(`{"signed":1}`)}}
	if got := string(rootFrom(fsys)); got != `{"signed":1}` {
		t.Fatalf("root = %q", got)
	}
}

// An embedded root must be a production root that parses: a development
// root in a release build would accept development keys everywhere.
func TestEmbeddedRootIsProduction(t *testing.T) {
	data := EmbeddedRoot()
	if data == nil {
		t.Skip("no root embedded yet")
	}
	root, err := VerifyRoot(data, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if root.KeyCount(RoleFeed, time.Now()) < root.Thresholds.Feed || root.Thresholds.Feed < 1 {
		t.Fatalf("embedded root has %d feed keys for a threshold of %d", root.KeyCount(RoleFeed, time.Now()), root.Thresholds.Feed)
	}
	if root.Environment != EnvProduction {
		t.Fatalf("embedded root is %q, want production", root.Environment)
	}
}
