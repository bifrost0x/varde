// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
)

const faviconLimit = 64 << 10

// certFields returns what a TLS certificate says about the service. The
// issuer and subject are names the certificate carries, the fingerprint and
// the self-signed check are computed from the certificate itself.
func certFields(c *x509.Certificate) []Field {
	var fs []Field
	fs = addField(fs, FieldCertIssuer, orgOrCN(c.Issuer.Organization, c.Issuer.CommonName), TrustDerived)
	fs = addField(fs, FieldCertSubject, orgOrCN(c.Subject.Organization, c.Subject.CommonName), TrustDerived)
	sum := sha256.Sum256(c.Raw)
	fs = addField(fs, FieldCertFingerprint, hex.EncodeToString(sum[:]), TrustStated)
	if string(c.RawIssuer) == string(c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
		fs = addField(fs, FieldCertSelfSigned, "true", TrustStated)
	}
	return fs
}

func orgOrCN(org []string, cn string) string {
	if len(org) > 0 && org[0] != "" {
		return org[0]
	}
	return cn
}

// pageFields returns the page title and Server header. Error and redirect
// titles say nothing about the service and are left out.
func pageFields(title, server string) []Field {
	var fs []Field
	if !genericTitle.MatchString(title) {
		fs = addField(fs, FieldHTTPTitle, title, TrustDerived)
	}
	return addField(fs, FieldHTTPServer, server, TrustDerived)
}

// favicon fetches <base>/favicon.ico and returns a short hash of it. Only
// a 200 answer of at most 64 KiB counts, and redirects are not followed,
// so the request never leaves the device being read.
func (s *Scanner) favicon(ctx context.Context, base string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, s.ReadTimeout)
	defer cancel()
	client := &http.Client{
		Transport:     s.fingerprintTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/favicon.ico", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "varde-discovery")
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, faviconLimit+1))
	if err != nil || len(body) == 0 || len(body) > faviconLimit {
		return "", false
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:16]), true
}
