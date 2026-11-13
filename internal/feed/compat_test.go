// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
)

// republish rewrites the published manifest after change and signs it again.
func (f *fixture) republish(change func(m *Manifest)) {
	f.t.Helper()
	path := filepath.Join(f.pub, "v1", "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		f.t.Fatal(err)
	}
	change(&m)
	if data, err = json.Marshal(m); err != nil {
		f.t.Fatal(err)
	}
	sig, err := json.Marshal(struct {
		Signatures []Signature `json:"signatures"`
	}{sign(data, []ed25519.PrivateKey{f.feedKey})})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", sig, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func futureBlob(name string) Blob {
	return Blob{Name: name, MediaType: "application/vnd.varde.future.v1", Compression: "none",
		SHA256: strings.Repeat("ab", 32), Size: 10, UncompressedSize: 10}
}

// A blob this version does not know is skipped: an addition to the
// package must not break installations that are older than it.
func TestUnknownBlobSkipped(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 2)
	f.republish(func(m *Manifest) { m.Blobs = append(m.Blobs, futureBlob("extras/future")) })
	res, err := f.update()
	if err != nil || !res.Applied {
		t.Fatalf("update: %+v, %v", res, err)
	}
	if n := f.feedAdvisories(); n != 2 {
		t.Fatalf("advisories = %d, want 2", n)
	}
}

func TestUnknownBlobNameMustBeWellFormed(t *testing.T) {
	for _, name := range []string{"../x", "Extras/X", "a//b", "/a", "a/", strings.Repeat("a", 97)} {
		f := newFixture(t)
		f.publish(5, 1)
		f.republish(func(m *Manifest) { m.Blobs = append(m.Blobs, futureBlob(name)) })
		if _, err := f.update(); err == nil || !strings.Contains(err.Error(), "blob name") {
			t.Errorf("%q: err = %v, want an invalid blob name", name, err)
		}
	}
}

func TestNewerSchemaIsTooOld(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 1)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	f.publish(6, 2)
	f.republish(func(m *Manifest) { m.SchemaVersion = SpecVersion + 1 })
	_, err := f.update()
	if !errors.Is(err, ErrTooOld) || !strings.Contains(err.Error(), "this Varde version is too old for the current data package") {
		t.Fatalf("err = %v, want ErrTooOld", err)
	}
	if n := f.feedAdvisories(); n != 1 {
		t.Fatalf("advisories = %d, want the previous 1", n)
	}
}

// The settings page learns from the recorded error that Varde is too old.
// That must survive however long the rest of the message is (several
// mirrors, long URLs): the record is cut at 500 characters.
func TestTooOldSurvivesTruncation(t *testing.T) {
	f := newFixture(t)
	f.publish(5, 1)
	f.republish(func(m *Manifest) { m.SchemaVersion = SpecVersion + 1 })
	long, err := NewFetcher("file:///nonexistent/"+strings.Repeat("a-very-long-mirror-path/", 30), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.client.Mirrors = []Fetcher{long, f.client.Mirrors[0]}
	src := &Source{Client: f.client, Store: f.st}
	if _, err := src.Check(context.Background()); !errors.Is(err, ErrTooOld) {
		t.Fatalf("err = %v", err)
	}
	st, err := f.st.SourceState(context.Background(), "feed", "manifest")
	if err != nil || !strings.Contains(st.LastError, ErrTooOld.Error()) {
		t.Fatalf("recorded error lost the reason: %q, %v", st.LastError, err)
	}
}

// oldKnownName is the blob list of the versions released before the
// generated and releases blobs, copied unchanged.
var oldKnownName = regexp.MustCompile(`^(catalog|index|advisories/[a-z0-9-]{1,64}|enrichment/(kev|epss))$`)

// generatedTestEntry is a machine-made catalog entry.
func generatedTestEntry(id, image string) catalog.Entry {
	return catalog.Entry{Name: id + ".yaml", Data: "id: " + id + "\nname: " + id + "\nhomepage: https://github.com/x/" + id +
		"\nimages: [{match: " + image + "}]\nversion: {scheme: semver}\nadvisories: {coverage: partial, github_repos: [x/" + id +
		"]}\nmaintainers_of_entry: [generator]\nverified: 2026-11-12\n"}
}

// An installation released before the new blobs reads a package that
// carries them: the manifest verifies, the new blobs are skipped, and the
// catalog, the index and the advisories load as before.
func TestOldReaderSkipsNewBlobs(t *testing.T) {
	f := newFixture(t)
	f.publishLayered(5, []catalog.Entry{generatedTestEntry("gh-a-b", "ghcr.io/a/b")}, []ReleaseLine{testRelease("immich", "amd64")})
	names := map[string]bool{}
	data, err := os.ReadFile(filepath.Join(f.pub, "v1", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, b := range m.Blobs {
		names[b.Name] = true
	}
	if !names["generated"] || !names["releases"] || !names["catalog"] || !names["index"] {
		t.Fatalf("blobs = %v", names)
	}

	current := knownName
	knownName = oldKnownName
	t.Cleanup(func() { knownName = current })
	res, err := f.update()
	if err != nil || !res.Applied {
		t.Fatalf("old reader: %+v, %v", res, err)
	}
	cat := f.client.Catalog.Current()
	if a, ok := cat.App("immich"); !ok || a.Origin != catalog.OriginFeed {
		t.Fatal("old reader lost the reviewed catalog")
	}
	if _, ok := cat.App("gh-a-b"); ok {
		t.Fatal("old reader read the generated blob")
	}
	if _, ok := f.client.Index().Lookup("ghcr.io/a/b"); !ok {
		t.Fatal("old reader lost the index")
	}
	if n := f.feedAdvisories(); n != 1 {
		t.Fatalf("old reader: advisories = %d, want 1", n)
	}
	if f.storedReleases("immich") != nil {
		t.Fatal("old reader read the releases blob")
	}
}

// The catalog blob keeps the limit older installations enforce; the
// generated entries go into their own blob, however many there are.
func TestCatalogBlobStaysUnder2000(t *testing.T) {
	f := newFixture(t)
	gen := make([]catalog.Entry, 0, 2100)
	for i := range 2100 {
		id := fmt.Sprintf("gh-gen-%04d", i)
		gen = append(gen, generatedTestEntry(id, "docker.io/gen/"+id))
	}
	f.publishLayered(5, gen, nil)
	data, err := os.ReadFile(filepath.Join(f.pub, "v1", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, b := range m.Blobs {
		if b.Name != "catalog" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(f.pub, "v1", "blobs", "sha256", b.SHA256))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := unpack(b, raw)
		if err != nil {
			t.Fatal(err)
		}
		var doc catalogDoc
		if err := json.Unmarshal(plain, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Entries) != 1 {
			t.Fatalf("catalog blob has %d entries", len(doc.Entries))
		}
	}
	current := knownName
	knownName = oldKnownName
	t.Cleanup(func() { knownName = current })
	if _, err := f.update(); err != nil {
		t.Fatalf("old reader: %v", err)
	}
	knownName = current
	f.publishLayered(6, gen, nil)
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	if n := f.client.Catalog.Current().Len(); n != 2101 {
		t.Fatalf("apps = %d, want 2101", n)
	}
	// The builder refuses a catalog blob older installations would refuse.
	many := make([]catalog.Entry, 2001)
	if _, err := WriteSnapshot(t.TempDir(), Snapshot{Sequence: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour), Catalog: many}, f.feedKey); err == nil {
		t.Fatal("catalog blob with 2001 entries written")
	}
}
