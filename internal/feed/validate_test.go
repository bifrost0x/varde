// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/store"
)

func TestParseRootRejects(t *testing.T) {
	k, _ := NewKey()
	pk := pub(k)
	id := KeyID(pk)
	good := func(mut func(m map[string]any)) []byte {
		signed := map[string]any{"type": "root", "spec_version": 1, "version": 1, "expires": "2030-01-01T00:00:00Z",
			"environment": "production", "keys": map[string]any{id: map[string]any{"public": base64.StdEncoding.EncodeToString(pk), "role": "root"}},
			"thresholds": map[string]any{"root": 1, "feed": 0}}
		mut(signed)
		raw, _ := json.Marshal(signed)
		env, _ := json.Marshal(map[string]any{"signed": json.RawMessage(raw), "signatures": []any{}})
		return env
	}
	for name, mut := range map[string]func(map[string]any){
		"wrong type":     func(m map[string]any) { m["type"] = "manifest" },
		"spec":           func(m map[string]any) { m["spec_version"] = 2 },
		"environment":    func(m map[string]any) { m["environment"] = "staging" },
		"zero threshold": func(map[string]any) {},
		"unknown field":  func(m map[string]any) { m["extra"] = true; m["thresholds"] = map[string]any{"root": 1, "feed": 1} },
		"key id mismatch": func(m map[string]any) {
			m["keys"] = map[string]any{strings.Repeat("0", 64): map[string]any{"public": base64.StdEncoding.EncodeToString(pk), "role": "root"}}
		},
		"bad key": func(m map[string]any) {
			m["keys"] = map[string]any{id: map[string]any{"public": "AAAA", "role": "root"}}
		},
		"unknown role": func(m map[string]any) {
			m["keys"] = map[string]any{id: map[string]any{"public": base64.StdEncoding.EncodeToString(pk), "role": "admin"}}
		},
		"too few keys": func(m map[string]any) { m["thresholds"] = map[string]any{"root": 2, "feed": 1} },
	} {
		if _, _, err := ParseRoot(good(mut)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := ParseRoot([]byte(`{"signed":{}} trailing`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestVerifyManifestStructure(t *testing.T) {
	f := newFixture(t)
	root, _ := f.client.trusted()
	sign := func(m map[string]any) ([]byte, []byte) {
		data, _ := json.Marshal(m)
		sig, _ := json.Marshal(map[string]any{"signatures": sign(data, []ed25519.PrivateKey{f.feedKey})})
		return data, sig
	}
	blob := func(name, media string) map[string]any {
		return map[string]any{"name": name, "media_type": media, "compression": "zstd", "sha256": strings.Repeat("a", 64), "size": 10, "uncompressed_size": 20}
	}
	base := func() map[string]any {
		return map[string]any{"type": "manifest", "schema_version": 1, "sequence": 1, "created_at": f.now, "expires_at": f.now.Add(time.Hour),
			"catalog_version": "x", "blobs": []any{blob("catalog", MediaCatalog)}}
	}
	d, sg := sign(base())
	if _, err := VerifyManifest(root, d, sg, f.now, DefaultMaxUnpacked); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	for name, mut := range map[string]func(map[string]any){
		"no catalog": func(m map[string]any) { m["blobs"] = []any{blob("advisories/shard-00", MediaAdvisories)} },
		"duplicate": func(m map[string]any) {
			m["blobs"] = []any{blob("catalog", MediaCatalog), blob("catalog", MediaCatalog)}
		},
		"bad name": func(m map[string]any) {
			m["blobs"] = []any{blob("catalog", MediaCatalog), blob("../x", MediaAdvisories)}
		},
		"media type":    func(m map[string]any) { m["blobs"] = []any{blob("catalog", MediaAdvisories)} },
		"expires first": func(m map[string]any) { m["expires_at"] = f.now.Add(-time.Hour) },
		"sequence zero": func(m map[string]any) { m["sequence"] = 0 },
		"no blobs":      func(m map[string]any) { m["blobs"] = []any{} },
		"compression": func(m map[string]any) {
			b := blob("catalog", MediaCatalog)
			b["compression"] = "gzip"
			m["blobs"] = []any{b}
		},
		"bad hash": func(m map[string]any) { b := blob("catalog", MediaCatalog); b["sha256"] = "xyz"; m["blobs"] = []any{b} },
		"size overflow": func(m map[string]any) {
			b1, b2 := blob("catalog", MediaCatalog), blob("advisories/shard-00", MediaAdvisories)
			b1["uncompressed_size"], b2["uncompressed_size"] = int64(1)<<62, int64(1)<<62
			m["blobs"] = []any{b1, b2}
		},
		"oversized blob": func(m map[string]any) {
			b := blob("catalog", MediaCatalog)
			b["size"] = maxBlobBytes + 1
			m["blobs"] = []any{b}
		},
		"none size": func(m map[string]any) {
			b := blob("catalog", MediaCatalog)
			b["compression"] = "none"
			m["blobs"] = []any{b}
		},
		"unknown field":   func(m map[string]any) { m["extra"] = 1 },
		"wrong type name": func(m map[string]any) { m["type"] = "root" },
	} {
		m := base()
		mut(m)
		d, sg := sign(m)
		if _, err := VerifyManifest(root, d, sg, f.now, DefaultMaxUnpacked); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestContentValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		blob Blob
		data string
	}{
		"catalog schema": {Blob{Name: "catalog"}, `{"schema_version":2,"entries":[]}`},
		"kev cve":        {Blob{Name: "enrichment/kev"}, `[{"cve":"CVE-1","date_added":"x"}]`},
		"epss range":     {Blob{Name: "enrichment/epss"}, `[{"cve":"CVE-2026-1234","score":2,"percentile":0.5,"date":"x"}]`},
		"advisory app":   {Blob{Name: "advisories/shard-00"}, `{"app_id":"Bad App","osv":{"id":"X"}}`},
		"advisory cvss":  {Blob{Name: "advisories/shard-00"}, `{"app_id":"immich","cvss":11,"osv":{"id":"X"}}`},
		"advisory field": {Blob{Name: "advisories/shard-00"}, `{"app_id":"immich","osv":{"id":"X"},"evil":1}`},
		"unknown blob":   {Blob{Name: "other"}, `{}`},
	} {
		if err := (&Content{}).parse(tc.blob, []byte(tc.data)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	var c Content
	if err := c.parse(Blob{Name: "advisories/shard-00"}, []byte("\n{\"app_id\":\"immich\",\"severity\":\"HIGH\",\"osv\":{\"id\":\"GHSA-x\"}}\n\n")); err != nil || len(c.Advisories) != 1 || c.Advisories[0].SeverityLabel != "high" {
		t.Fatalf("valid shard: %v %+v", err, c.Advisories)
	}
}

func TestSourceStaleNotices(t *testing.T) {
	f := newFixture(t)
	src := &Source{Client: f.client, Store: f.st, StaleAfter: 72 * time.Hour}
	ctx := context.Background()
	notice := func() string {
		ns, _ := f.st.ActiveNotices(ctx)
		for _, n := range ns {
			if n.Kind == store.NoticeFeedStale {
				return n.Title
			}
		}
		return ""
	}
	// Nothing published yet: error and "no feed" notice.
	if _, err := src.Refresh(ctx, nil); err == nil || !strings.Contains(notice(), "No advisory feed") {
		t.Fatalf("no feed: %v %q", err, notice())
	}
	f.publish(1, 1)
	res, err := src.Refresh(ctx, nil)
	if err != nil || !res.Changed() || notice() != "" {
		t.Fatalf("fresh feed: %+v %v %q", res, err, notice())
	}
	st, _ := f.st.SourceState(ctx, "feed", "manifest")
	if st.LastError != "" || st.LastSuccess.IsZero() {
		t.Fatalf("source state: %+v", st)
	}
	// The mirror disappears: after three days a notice, after expiry another.
	f.client.Mirrors = nil
	f.now = f.now.Add(4 * 24 * time.Hour)
	if _, err := src.Refresh(ctx, nil); err == nil || !strings.Contains(notice(), "not updated") {
		t.Fatalf("stale: %v %q", err, notice())
	}
	f.now = f.now.Add(4 * 24 * time.Hour)
	if _, _ = src.Refresh(ctx, nil); !strings.Contains(notice(), "expired") {
		t.Fatalf("expired: %q", notice())
	}
	if src.Name() != "feed" {
		t.Fatal("name")
	}
}

// rootDoc builds an unsigned root envelope from keys given as role -> key.
func rootDoc(t *testing.T, mut func(signed map[string]any), keys map[string]ed25519.PublicKey) []byte {
	t.Helper()
	ks := map[string]any{}
	for role, k := range keys {
		ks[KeyID(k)] = map[string]any{"public": base64.StdEncoding.EncodeToString(k), "role": role}
	}
	signed := map[string]any{"type": "root", "spec_version": 1, "version": 1, "expires": "2030-01-01T00:00:00Z",
		"environment": "production", "keys": ks, "thresholds": map[string]any{"root": 1, "feed": 1}}
	if mut != nil {
		mut(signed)
	}
	raw, _ := json.Marshal(signed)
	env, _ := json.Marshal(map[string]any{"signed": json.RawMessage(raw), "signatures": []any{}})
	return env
}

func TestRootUnknownRoleIgnored(t *testing.T) {
	rk, _ := NewKey()
	fk, _ := NewKey()
	xk, _ := NewKey()
	root, _, err := ParseRoot(rootDoc(t, nil, map[string]ed25519.PublicKey{"root": pub(rk), "feed": pub(fk), "future": pub(xk)}))
	if err != nil {
		t.Fatalf("root with an unknown role refused: %v", err)
	}
	msg := []byte("manifest")
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	if n := root.countValid(RoleFeed, msg, sign(msg, []ed25519.PrivateKey{xk}), now); n != 0 {
		t.Errorf("unknown-role key counted as feed key: %d", n)
	}
	if n := root.countValid(RoleRoot, msg, sign(msg, []ed25519.PrivateKey{xk}), now); n != 0 {
		t.Errorf("unknown-role key counted as root key: %d", n)
	}
	// Unknown-role keys do not help to reach a threshold.
	if _, _, err := ParseRoot(rootDoc(t, nil, map[string]ed25519.PublicKey{"root": pub(rk), "future": pub(xk)})); err == nil {
		t.Error("root without a feed key accepted because of an unknown-role key")
	}
	// A role must still be a plain word.
	if _, _, err := ParseRoot(rootDoc(t, nil, map[string]ed25519.PublicKey{"root": pub(rk), "feed": pub(fk), "Bad Role": pub(xk)})); err == nil {
		t.Error("malformed role accepted")
	}
}

func TestRootUnknownFieldRejected(t *testing.T) {
	rk, _ := NewKey()
	fk, _ := NewKey()
	doc := rootDoc(t, func(m map[string]any) { m["extra"] = true }, map[string]ed25519.PublicKey{"root": pub(rk), "feed": pub(fk)})
	if _, _, err := ParseRoot(doc); err == nil {
		t.Error("root with an unknown field accepted")
	}
}

func TestRootLicenseRole(t *testing.T) {
	rk, _ := NewKey()
	fk, _ := NewKey()
	lk, _ := NewKey()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	data, err := SignRoot(RootSpec{Version: 1, Expires: now.Add(time.Hour), Environment: EnvDevelopment,
		RootKeys: []ed25519.PublicKey{pub(rk)}, FeedKeys: []ed25519.PublicKey{pub(fk)}, LicenseKeys: []ed25519.PublicKey{pub(lk)},
		RootThreshold: 1, FeedThreshold: 1}, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := ParseRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	ks := root.keysOf(RoleLicense, now)
	if len(ks) != 1 || ks[0].Role != RoleLicense {
		t.Fatalf("license keys = %+v", ks)
	}
	if len(root.keysOf(RoleOverride, now)) != 0 {
		t.Error("override keys listed without any")
	}
	msg := []byte("manifest")
	if n := root.countValid(RoleFeed, msg, sign(msg, []ed25519.PrivateKey{lk}), now); n != 0 {
		t.Errorf("license key counted as feed key: %d", n)
	}
}
