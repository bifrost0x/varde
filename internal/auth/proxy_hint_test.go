// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http/httptest"
	"testing"
)

// A request that claims HTTPS from an untrusted peer names that peer; the
// claim itself is still ignored.
func TestUntrustedTLSProxy(t *testing.T) {
	p, err := NewProxies([]string{"10.0.0.2"}, false)
	if err != nil {
		t.Fatal(err)
	}
	req := func(peer, proto string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer + ":4242"
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		return p.UntrustedTLSProxy(r)
	}
	if got := req("172.18.0.5", "https"); got != "172.18.0.5" {
		t.Errorf("untrusted proxy: %q", got)
	}
	if got := req("10.0.0.2", "https"); got != "" {
		t.Errorf("trusted proxy reported: %q", got)
	}
	if got := req("172.18.0.5", ""); got != "" {
		t.Errorf("plain request reported: %q", got)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.18.0.5:4242"
	r.Header.Set("X-Forwarded-Proto", "https")
	if p.IsTLS(r) {
		t.Error("the claim of an untrusted peer was believed")
	}
}
