// SPDX-License-Identifier: Apache-2.0

package applists

import (
	"os"
	"testing"
)

// TestRealLists reduces real downloads when APPLISTS_REAL_DIR points to
// them (unraid.json, umbrel.tar.gz); it is a manual check, skipped otherwise.
func TestRealLists(t *testing.T) {
	dir := os.Getenv("APPLISTS_REAL_DIR")
	if dir == "" {
		t.Skip("APPLISTS_REAL_DIR not set")
	}
	var all []Pair
	for name, parse := range map[string]func(f *os.File) ([]Pair, error){
		"unraid.json":   func(f *os.File) ([]Pair, error) { return ParseUnraid(f) },
		"umbrel.tar.gz": func(f *os.File) ([]Pair, error) { return ParseUmbrel(f) },
	} {
		f, err := os.Open(dir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		pairs, err := parse(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: %d pairs", name, len(pairs))
		all = append(all, pairs...)
	}
	tab, dropped := Build(all)
	confirmed := 0
	for _, e := range tab.entries {
		if e.Confirmed() {
			confirmed++
		}
	}
	reasons := map[string]int{}
	for _, r := range dropped {
		reasons[r]++
	}
	t.Logf("table: %d images, %d confirmed, %d bytes; dropped: %v", tab.Len(), confirmed, len(tab.Marshal()), reasons)
	if _, err := Unmarshal(tab.Marshal()); err != nil {
		t.Fatal(err)
	}
}
