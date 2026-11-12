// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
