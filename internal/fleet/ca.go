// SPDX-License-Identifier: Apache-2.0

// Package fleet is the server side of agents: the internal CA, enrollment,
// the mTLS listener, and liveness.
package fleet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/fsutil"
)

// Certificate lifetimes. Agents renew when less than RenewBefore remains.
const (
	caLifetime     = 10 * 365 * 24 * time.Hour
	leafLifetime   = 90 * 24 * time.Hour
	RenewBefore    = 30 * 24 * time.Hour
	clockSkewGrace = 5 * time.Minute
)

// CA is the internal certificate authority for agents. Its key is created on
// first start under the data directory and never leaves it.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	now  func() time.Time

	mu     sync.Mutex
	server *tls.Certificate
}

// LoadOrCreateCA reads the CA from dir or creates it. The key file is written
// with mode 0600 inside a 0700 directory.
func LoadOrCreateCA(dir string, now func() time.Time) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	certPEM, certErr := os.ReadFile(certPath) //nolint:gosec // fixed path inside the data directory
	keyPEM, keyErr := os.ReadFile(keyPath)    //nolint:gosec // fixed path inside the data directory
	switch {
	case certErr == nil && keyErr == nil:
		return parseCA(certPEM, keyPEM, now)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
	case certErr != nil && !errors.Is(certErr, os.ErrNotExist):
		return nil, fmt.Errorf("read CA certificate: %w", certErr)
	case keyErr != nil && !errors.Is(keyErr, os.ErrNotExist):
		return nil, fmt.Errorf("read CA key: %w", keyErr)
	default:
		return nil, fmt.Errorf("incomplete CA in %s: certificate and key must both exist", dir)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	start := now().Add(-clockSkewGrace)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Varde agent CA"},
		NotBefore:             start,
		NotAfter:              start.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode CA key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create CA directory: %w", err)
	}
	if err := fsutil.WriteFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := fsutil.WriteFileAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	return parseCA(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), now)
}

func parseCA(certPEM, keyPEM []byte, now func() time.Time) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("CA files are not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("CA key does not match the CA certificate")
	}
	if !cert.IsCA {
		return nil, errors.New("CA certificate is not a CA")
	}
	return &CA{cert: cert, key: key, now: now}, nil
}

// Pin is the fingerprint agents use to recognise this CA.
func (c *CA) Pin() string { return wire.Fingerprint(c.cert) }

// Pool returns a pool containing only this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// SignAgent issues a client certificate for hostID from a PEM CSR. Only
// ECDSA P-256 and Ed25519 keys are accepted.
func (c *CA) SignAgent(csrPEM, hostID string) (*x509.Certificate, []byte, error) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("csr is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("csr signature: %w", err)
	}
	if err := acceptableKey(csr.PublicKey); err != nil {
		return nil, nil, err
	}
	start := c.now().Add(-clockSkewGrace)
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: hostID},
		NotBefore:    start,
		NotAfter:     start.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign agent certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse agent certificate: %w", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func acceptableKey(k crypto.PublicKey) error {
	switch pk := k.(type) {
	case *ecdsa.PublicKey:
		if pk.Curve != elliptic.P256() {
			return errors.New("csr key must be ECDSA P-256 or Ed25519")
		}
	case ed25519.PublicKey:
	default:
		return errors.New("csr key must be ECDSA P-256 or Ed25519")
	}
	return nil
}

// ServerCertificate returns the listener certificate (leaf plus CA), issuing
// a new one in memory when none exists or less than RenewBefore remains.
func (c *CA) ServerCertificate() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.server != nil && c.server.Leaf != nil && c.server.Leaf.NotAfter.Sub(now) > RenewBefore {
		return c.server, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	start := now.Add(-clockSkewGrace)
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "varde-server"},
		DNSNames:     []string{"varde-server"},
		NotBefore:    start,
		NotAfter:     start.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse server certificate: %w", err)
	}
	c.server = &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: leaf}
	return c.server, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return n
}
