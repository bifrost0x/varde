// SPDX-License-Identifier: Apache-2.0

package index

import (
	"testing"

	"github.com/bifrost0x/varde/internal/applists"
)

// The embedded table is checked at build time, not in the field.
func TestEmbeddedTableIsValid(t *testing.T) {
	tab, err := Table()
	if err != nil {
		t.Fatalf("index/images.tsv: %v", err)
	}
	t.Logf("%d images", tab.Len())
}

// Check refuses rows that would alert without the evidence the index
// promises: a hand-edited or faulty table must not ship.
func TestCheck(t *testing.T) {
	good := "docker.io/a/b\tgithub.com/a/b\treadme\n" +
		"docker.io/c/d\tgithub.com/x/d\thub,readme\n" +
		"ghcr.io/o/app-server\tgithub.com/o/app\tghcr,readme\n"
	tab, err := applists.Unmarshal([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(tab); err != nil {
		t.Errorf("good table refused: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown kind":                "docker.io/a/b\tgithub.com/a/b\treadme,unraid\n",
		"registry namespace alone":    "ghcr.io/o/app\tgithub.com/o/app\tghcr\n",
		"namespace for another owner": "ghcr.io/o/app\tgithub.com/x/app\tghcr,readme\n",
		"namespace for another name":  "ghcr.io/o/sidecar\tgithub.com/o/app\tghcr,readme\n",
		"helper image":                "docker.io/library/postgres\tgithub.com/o/app\thub,readme\n",
	} {
		tab, err := applists.Unmarshal([]byte(bad))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := Check(tab); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
