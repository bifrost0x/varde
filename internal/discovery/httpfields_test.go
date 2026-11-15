// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, org string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " CN"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func fieldValue(fs []Field, name string) string {
	for _, f := range fs {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

func TestCertFields(t *testing.T) {
	self, _ := testCert(t, "UGREEN", nil, nil)
	fs := certFields(self)
	if got := fieldValue(fs, FieldCertSelfSigned); got != "true" {
		t.Errorf("self_signed = %q", got)
	}
	if got := fieldValue(fs, FieldCertIssuer); got != "UGREEN" {
		t.Errorf("issuer = %q", got)
	}
	if got := fieldValue(fs, FieldCertSubject); got != "UGREEN" {
		t.Errorf("subject = %q", got)
	}
	if got := fieldValue(fs, FieldCertFingerprint); len(got) != 64 {
		t.Errorf("fingerprint = %q", got)
	}

	ca, caKey := testCert(t, "Test CA", nil, nil)
	leaf, _ := testCert(t, "UGREEN", ca, caKey)
	fs = certFields(leaf)
	if got := fieldValue(fs, FieldCertSelfSigned); got != "" {
		t.Errorf("CA-signed cert: self_signed = %q", got)
	}
	if got := fieldValue(fs, FieldCertIssuer); got != "Test CA" {
		t.Errorf("issuer = %q", got)
	}
}

func TestPageFields(t *testing.T) {
	fs := pageFields("UGOS Pro", "nginx")
	if fieldValue(fs, FieldHTTPTitle) != "UGOS Pro" || fieldValue(fs, FieldHTTPServer) != "nginx" {
		t.Errorf("fields = %v", fs)
	}
	if got := fieldValue(pageFields("404 Not Found", ""), FieldHTTPTitle); got != "" {
		t.Errorf("generic title kept: %q", got)
	}
}

func httpTestServer(favicon []byte) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<html><title>UGOS Pro</title></html>"))
		case "/favicon.ico":
			_, _ = w.Write(favicon)
		default:
			http.NotFound(w, r)
		}
	}))
}

func readTestHTTP(t *testing.T, srv *httptest.Server) *Service {
	t.Helper()
	s := &Scanner{ReadTimeout: 2 * time.Second, dial: (&net.Dialer{}).DialContext}
	svc := &Service{}
	s.readHTTP(context.Background(), strings.TrimPrefix(srv.URL, "https://"), true, svc)
	return svc
}

func TestReadHTTPFields(t *testing.T) {
	srv := httpTestServer([]byte("icon-bytes"))
	defer srv.Close()
	svc := readTestHTTP(t, srv)
	if got := fieldValue(svc.Fields, FieldHTTPTitle); got != "UGOS Pro" {
		t.Errorf("title = %q", got)
	}
	if got := fieldValue(svc.Fields, FieldFavicon); len(got) != 32 {
		t.Errorf("favicon = %q", got)
	}
	if fieldValue(svc.Fields, FieldCertFingerprint) == "" || fieldValue(svc.Fields, FieldCertSelfSigned) == "" {
		t.Errorf("cert fields missing: %v", svc.Fields)
	}
	if want := productFromHTTP("UGOS Pro", "", "Acme Co "); svc.Product != want {
		t.Errorf("product = %q, want %q", svc.Product, want)
	}
}

func TestReadHTTPFaviconTooLarge(t *testing.T) {
	srv := httpTestServer(make([]byte, 100<<10))
	defer srv.Close()
	svc := readTestHTTP(t, srv)
	if got := fieldValue(svc.Fields, FieldFavicon); got != "" {
		t.Errorf("oversized favicon kept: %q", got)
	}
	if fieldValue(svc.Fields, FieldHTTPTitle) != "UGOS Pro" {
		t.Errorf("title lost: %v", svc.Fields)
	}
}

func TestFaviconNoRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("elsewhere"))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/favicon.ico", http.StatusFound)
	}))
	defer srv.Close()
	s := &Scanner{ReadTimeout: 2 * time.Second, dial: (&net.Dialer{}).DialContext}
	if v, ok := s.favicon(context.Background(), srv.URL); ok {
		t.Errorf("followed redirect: %q", v)
	}
}
