// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/store"
)

func testTags(image string, read time.Time, tags ...string) TagLine {
	return TagLine{AppID: "immich", Image: image, Read: read, Tags: tags}
}

func TestTagsRoundTrip(t *testing.T) {
	read := time.Date(2026, 11, 12, 4, 0, 0, 0, time.UTC)
	in := []TagLine{
		testTags("ghcr.io/immich-app/immich-server", read, "v2.1.0", "v2.0.1", "v2.0.0"),
		testTags("docker.io/altran1502/immich-server", read, "v2.1.0"),
	}
	data, err := marshalTags(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := parseTags(data)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted by image, tags in the builder's order.
	if len(out) != 2 || out[0].Image != "docker.io/altran1502/immich-server" || strings.Join(out[1].Tags, ",") != "v2.1.0,v2.0.1,v2.0.0" || !out[1].Read.Equal(read) {
		t.Fatalf("round trip = %+v", out)
	}

	for name, bad := range map[string]TagLine{
		"no tags":        testTags("ghcr.io/a/b", read),
		"repeated tag":   testTags("ghcr.io/a/b", read, "1.0.0", "1.0.0"),
		"not a tag":      testTags("ghcr.io/a/b", read, "1.0.0; rm -rf /"),
		"not normalised": testTags("a/b", read, "1.0.0"),
		"no read time":   testTags("ghcr.io/a/b", time.Time{}, "1.0.0"),
		"too many tags":  testTags("ghcr.io/a/b", read, make([]string, MaxTagsPerLine+1)...),
	} {
		if _, err := marshalTags([]TagLine{bad}); err == nil {
			t.Errorf("%s: builder wrote the line", name)
		}
	}
	if _, err := marshalTags([]TagLine{in[0], in[0]}); err == nil {
		t.Error("an image listed twice was written")
	}
	if _, err := parseTags([]byte(`{"app_id":"immich","image":"ghcr.io/a/b","read":"2026-11-12T04:00:00Z","tags":["1.0.0"],"secret":1}` + "\n")); err == nil {
		t.Error("unknown field accepted")
	}
}

func (f *fixture) publishTags(seq int64, tags []TagLine) {
	f.t.Helper()
	_, err := WriteSnapshot(f.pub, Snapshot{Channel: f.channel, Sequence: seq, CreatedAt: f.now, ExpiresAt: f.now.Add(7 * 24 * time.Hour),
		CatalogVersion: "test", Catalog: []catalog.Entry{{Name: "immich.yaml", Data: immichEntry}}, Tags: tags, Shards: 4}, f.feedKey)
	if err != nil {
		f.t.Fatal(err)
	}
}

// The tags of a package reach the table update suggestions read, beside
// what the installation read from a registry itself: the fresher stands,
// and they stay when the package is left.
func TestTagsReachTheStore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const image, own = "ghcr.io/immich-app/immich-server", "docker.io/library/own"
	// The installation read both repositories itself: one long ago, one
	// after the package was built.
	for _, r := range []store.RepositoryTags{
		{Repository: image, Tags: []string{"v1.0.0"}, Checked: f.now.Add(-72 * time.Hour)},
		{Repository: own, Tags: []string{"9.9.9"}, Checked: f.now.Add(time.Hour)},
	} {
		if err := f.st.RecordRepositoryTags(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	f.publishTags(5, []TagLine{testTags(image, f.now, "v2.1.0", "v2.0.0"), testTags(own, f.now, "1.0.0")})
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	known, err := f.st.RepositoryTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(known[image].Tags, ","); got != "v2.1.0,v2.0.0" || !known[image].Checked.Equal(f.now) {
		t.Errorf("package tags = %q at %s", got, known[image].Checked)
	}
	if got := strings.Join(known[own].Tags, ","); got != "9.9.9" {
		t.Errorf("a fresher local read was replaced: %q", got)
	}

	base, _ := catalog.Build(nil, catalog.OriginBuiltin, nil)
	if err := f.client.Deactivate(ctx, base); err != nil {
		t.Fatal(err)
	}
	if known, _ = f.st.RepositoryTags(ctx); len(known[image].Tags) != 2 {
		t.Error("tags dropped with the package")
	}
}
