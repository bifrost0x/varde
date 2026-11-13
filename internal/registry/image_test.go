// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/httpx"
)

func sum(b string) string {
	h := sha256.Sum256([]byte(b))
	return "sha256:" + hex.EncodeToString(h[:])
}

// imageRegistry serves manifests and blobs of org/app behind a token
// service. Objects are addressed by tag or digest.
type imageRegistry struct {
	mu        sync.Mutex
	manifests map[string]string // reference -> body
	blobs     map[string]string // digest -> content
	tokenAuth []string          // Authorization header of every token request
	requests  []string
	srv       *httptest.Server
	redirect  string // blob redirect target, when set
}

func newImageRegistry(t *testing.T) (*imageRegistry, *Client, string) {
	t.Helper()
	r := &imageRegistry{manifests: map[string]string{}, blobs: map[string]string{}}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.requests = append(r.requests, req.Method+" "+req.URL.Path)
		if req.URL.Path == "/token" {
			r.tokenAuth = append(r.tokenAuth, req.Header.Get("Authorization"))
			_, _ = io.WriteString(w, `{"token":"t0k"}`)
			return
		}
		if req.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="reg"`, r.srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("RateLimit-Remaining", "97;w=21600")
		if ref, ok := strings.CutPrefix(req.URL.Path, "/v2/org/app/manifests/"); ok {
			body, ok := r.manifests[ref]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			ct := "application/vnd.oci.image.manifest.v1+json"
			if strings.Contains(body, `"manifests"`) {
				ct = "application/vnd.oci.image.index.v1+json"
			}
			w.Header().Set("Content-Type", ct)
			_, _ = io.WriteString(w, body)
			return
		}
		if d, ok := strings.CutPrefix(req.URL.Path, "/v2/org/app/blobs/"); ok {
			if r.redirect != "" {
				http.Redirect(w, req, r.redirect+"/cdn/"+d, http.StatusTemporaryRedirect)
				return
			}
			b, ok := r.blobs[d]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = io.WriteString(w, b)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(r.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(r.srv.Certificate())
	hc := httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second})
	host := strings.TrimPrefix(r.srv.URL, "https://")
	return r, New(hc), host
}

func (r *imageRegistry) addManifest(ref, body string) string {
	d := sum(body)
	r.manifests[ref] = body
	r.manifests[d] = body
	return d
}

func platformManifest(layers ...string) (string, string) {
	cfg := sum("cfg" + strings.Join(layers, ","))
	var ls []string
	for _, l := range layers {
		ls = append(ls, fmt.Sprintf(`{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":10}`, l))
	}
	return fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":%q,"size":5},"layers":[%s]}`, cfg, strings.Join(ls, ",")), cfg
}

func TestImageFollowsIndex(t *testing.T) {
	r, c, host := newImageRegistry(t)
	amd, _ := platformManifest(sum("amd-layer"))
	arm, _ := platformManifest(sum("arm-layer"))
	dAmd, dArm := r.addManifest("", amd), r.addManifest("", arm)
	att := `{"schemaVersion":2,"layers":[]}`
	dAtt := r.addManifest("", att)
	index := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}},
{"digest":%q,"platform":{"os":"linux","architecture":"arm64","variant":"v8"}},
{"digest":%q,"platform":{"os":"unknown","architecture":"unknown"}}]}`, dAmd, dArm, dAtt)
	dIdx := r.addManifest("1.0", index)

	ms, d, err := c.Image(t.Context(), host+"/org/app", "1.0", []Platform{{"linux", "amd64", ""}, {"linux", "arm64", ""}})
	if err != nil {
		t.Fatal(err)
	}
	if d != dIdx || len(ms) != 2 {
		t.Fatalf("digest %s manifests %+v", d, ms)
	}
	if ms[0].Digest != dAmd || ms[0].Platform.Arch != "amd64" || len(ms[0].Layers) != 1 || ms[0].Layers[0].Digest != sum("amd-layer") || ms[0].ConfigDigest == "" {
		t.Errorf("amd64 %+v", ms[0])
	}
	if ms[1].Digest != dArm || ms[1].Platform.Variant != "v8" {
		t.Errorf("arm64 %+v", ms[1])
	}
	for _, req := range r.requests {
		if strings.Contains(req, dAtt) {
			t.Errorf("attestation fetched: %s", req)
		}
	}
	// Only amd64 asked: arm64 is not fetched.
	r.requests = nil
	ms, _, err = c.Image(t.Context(), host+"/org/app", "1.0", []Platform{{"linux", "amd64", ""}})
	if err != nil || len(ms) != 1 {
		t.Fatalf("%+v %v", ms, err)
	}
	for _, req := range r.requests {
		if strings.Contains(req, dArm) {
			t.Errorf("unrequested platform fetched: %s", req)
		}
	}
}

func TestImageSingleManifest(t *testing.T) {
	r, c, host := newImageRegistry(t)
	body, cfg := platformManifest(sum("l1"), sum("l2"))
	// The config must hash to its digest for Blob to accept it.
	cfgBody := `{"os":"linux","architecture":"amd64"}`
	body = strings.ReplaceAll(body, cfg, sum(cfgBody))
	d := r.addManifest("2.0", body)
	r.blobs[sum(cfgBody)] = cfgBody

	ms, got, err := c.Image(t.Context(), host+"/org/app", "2.0", []Platform{{"linux", "amd64", ""}})
	if err != nil || got != d || len(ms) != 1 || len(ms[0].Layers) != 2 || ms[0].Platform.Arch != "amd64" {
		t.Fatalf("%+v %s %v", ms, got, err)
	}
	ms, _, err = c.Image(t.Context(), host+"/org/app", "2.0", []Platform{{"linux", "arm64", ""}})
	if err != nil || len(ms) != 0 {
		t.Errorf("image of another platform returned: %+v %v", ms, err)
	}
}

func TestBlobDigestMismatch(t *testing.T) {
	r, c, host := newImageRegistry(t)
	d := sum("expected")
	r.blobs[d] = "tampered"
	rc, err := c.Blob(t.Context(), host+"/org/app", d, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("mismatch not reported at EOF: %v", err)
	}
	r.blobs[d] = "expected"
	rc2, err := c.Blob(t.Context(), host+"/org/app", d, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc2.Close() }()
	if b, err := io.ReadAll(rc2); err != nil || string(b) != "expected" {
		t.Errorf("%q %v", b, err)
	}
	if _, err := c.Blob(t.Context(), host+"/org/app", "sha256:../x", 10); err == nil {
		t.Error("malformed digest accepted")
	}
}

func TestBlobMaxBytes(t *testing.T) {
	r, c, host := newImageRegistry(t)
	content := strings.Repeat("a", 100)
	d := sum(content)
	r.blobs[d] = content
	rc, err := c.Blob(t.Context(), host+"/org/app", d, 10)
	if err == nil {
		defer func() { _ = rc.Close() }()
		_, err = io.ReadAll(rc)
	}
	if err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("limit not enforced: %v", err)
	}
}

func TestBlobRedirectDropsCredentials(t *testing.T) {
	r, _, host := newImageRegistry(t)
	var cdnAuth string
	var cdnHits int
	var cdnHeaders http.Header
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cdnHits++
		cdnAuth = req.Header.Get("Authorization")
		cdnHeaders = req.Header.Clone()
		_, _ = io.WriteString(w, "layer")
	}))
	t.Cleanup(cdn.Close)
	pool := x509.NewCertPool()
	pool.AddCert(r.srv.Certificate())
	pool.AddCert(cdn.Certificate())
	c := New(httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second, AllowInternalRedirects: true}), WithCredentials(host, "user", "tok"))
	r.redirect = cdn.URL
	d := sum("layer")
	rc, err := c.Blob(t.Context(), host+"/org/app", d, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if b, err := io.ReadAll(rc); err != nil || string(b) != "layer" {
		t.Fatalf("%q %v", b, err)
	}
	if cdnHeaders.Get("Authorization") != "" || cdnHeaders.Get("Proxy-Authorization") != "" {
		t.Errorf("credentials reached the cdn: %v", cdnHeaders)
	}
	if cdnHits != 1 || cdnAuth != "" {
		t.Errorf("cdn hits %d, authorization %q", cdnHits, cdnAuth)
	}
}

func TestCredentialsUsedForDockerHub(t *testing.T) {
	// Configured for the registry's own host: the token request carries
	// Basic auth.
	r, _, host := newImageRegistry(t)
	pool := x509.NewCertPool()
	pool.AddCert(r.srv.Certificate())
	hc := httpx.New(httpx.Options{RootCAs: pool, Timeout: 5 * time.Second})
	r.addManifest("1.0", `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)

	withCreds := New(hc, WithCredentials(host, "user", "tok"))
	if _, _, err := withCreds.Image(t.Context(), host+"/org/app", "1.0", nil); err != nil {
		t.Fatal(err)
	}
	if len(r.tokenAuth) != 1 || r.tokenAuth[0] != "Basic dXNlcjp0b2s=" {
		t.Errorf("token auth %q", r.tokenAuth)
	}

	// Configured for another host: anonymous token request.
	r.tokenAuth = nil
	other := New(hc, WithCredentials("docker.io", "user", "tok"))
	if _, _, err := other.Image(t.Context(), host+"/org/app", "1.0", nil); err != nil {
		t.Fatal(err)
	}
	if len(r.tokenAuth) != 1 || r.tokenAuth[0] != "" {
		t.Errorf("credentials sent to a foreign registry: %q", r.tokenAuth)
	}
}

func TestDockerHubHostMapping(t *testing.T) {
	c := New(nil, WithCredentials("docker.io", "u", "t"))
	h, _, _ := endpoint("docker.io/library/nginx")
	if !strings.EqualFold(h, c.credHost) {
		t.Errorf("endpoint %q credentials %q", h, c.credHost)
	}
	if c := New(nil, WithCredentials("docker.io", "", "t")); c.credUser != "" {
		t.Error("incomplete credentials kept")
	}
}

func TestBudgetCountsManifestGETs(t *testing.T) {
	r, c, host := newImageRegistry(t)
	amd, _ := platformManifest(sum("a"))
	dAmd := r.addManifest("", amd)
	r.addManifest("1.0", fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}}]}`, dAmd))
	if _, _, err := c.Image(t.Context(), host+"/org/app", "1.0", []Platform{{"linux", "amd64", ""}}); err != nil {
		t.Fatal(err)
	}
	u := c.Budget()
	if u.ManifestRequests != 2 || u.Bytes == 0 || u.RateRemaining != "97;w=21600" {
		t.Errorf("usage %+v", u)
	}
	// Blob reads add bytes, not manifest requests.
	r.blobs[sum("xyz")] = "xyz"
	rc, err := c.Blob(t.Context(), host+"/org/app", sum("xyz"), 10)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(rc)
	_ = rc.Close()
	u2 := c.Budget()
	if u2.ManifestRequests != 2 || u2.Bytes != u.Bytes+3 {
		t.Errorf("usage after blob %+v (before %+v)", u2, u)
	}
}

func TestBlobRedirectToHTTPRefused(t *testing.T) {
	r, c, host := newImageRegistry(t)
	r.redirect = "http://cdn.example"
	if _, err := c.Blob(t.Context(), host+"/org/app", sum("x"), 10); err == nil {
		t.Error("redirect to http followed")
	}
}

func TestImageIndexEntries(t *testing.T) {
	r, c, host := newImageRegistry(t)
	v6, _ := platformManifest(sum("v6"))
	v7, _ := platformManifest(sum("v7"))
	d6, d7 := r.addManifest("", v6), r.addManifest("", v7)
	r.addManifest("arm", fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
{"digest":%q,"platform":{"os":"linux","architecture":"arm","variant":"v6"}},
{"digest":%q,"platform":{"os":"linux","architecture":"arm","variant":"v7"}}]}`, d6, d7))
	ms, _, err := c.Image(t.Context(), host+"/org/app", "arm", []Platform{{"linux", "arm", ""}})
	if err != nil || len(ms) != 2 {
		t.Fatalf("variants: %+v %v", ms, err)
	}
	r.addManifest("bad", `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
{"digest":"sha256:zz","platform":{"os":"linux","architecture":"amd64"}}]}`)
	if _, _, err := c.Image(t.Context(), host+"/org/app", "bad", []Platform{{"linux", "amd64", ""}}); err == nil {
		t.Error("malformed digest of a wanted platform skipped silently")
	}
	// An unwanted platform with a bad digest is irrelevant.
	if ms, _, err := c.Image(t.Context(), host+"/org/app", "bad", []Platform{{"linux", "arm64", ""}}); err != nil || len(ms) != 0 {
		t.Errorf("%+v %v", ms, err)
	}
}
