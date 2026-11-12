// SPDX-License-Identifier: Apache-2.0

// Package agent implements `varde agent`: it collects the inventory of the
// host it runs on and pushes it to the server over mTLS. It keeps no
// database, advisory data or UI.
package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bifrost0x/varde/internal/fsutil"
)

// File names inside the agent data directory.
const (
	identityFile   = "identity.pem" // private key and client certificate, mode 0600
	stateFile      = "agent.json"
	LastReportFile = "last-report"
)

// identity is what the agent needs to authenticate and to verify the server.
type identity struct {
	HostID string
	CAPin  string
	Cert   tls.Certificate
}

type stateJSON struct {
	HostID string `json:"host_id"`
	CAPin  string `json:"ca_pin"`
}

// loadIdentity returns the stored identity, or os.ErrNotExist before
// enrollment.
func loadIdentity(dir string) (*identity, error) {
	raw, err := os.ReadFile(filepath.Join(dir, stateFile)) //nolint:gosec // fixed path in the data directory
	if err != nil {
		return nil, err
	}
	var st stateJSON
	if err := json.Unmarshal(raw, &st); err != nil || st.HostID == "" || st.CAPin == "" {
		return nil, fmt.Errorf("agent state %s is corrupt; remove the data directory and enroll again", stateFile)
	}
	pemData, err := os.ReadFile(filepath.Join(dir, identityFile)) //nolint:gosec // fixed path in the data directory
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	return &identity{HostID: st.HostID, CAPin: st.CAPin, Cert: cert}, nil
}

// saveIdentity writes key and certificate in one file, so a crash cannot
// leave a key next to a certificate for a different key.
func saveIdentity(dir string, id *identity, keyPEM, certPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, identityFile), append(append([]byte{}, keyPEM...), certPEM...), 0o600); err != nil {
		return err
	}
	raw, err := json.Marshal(stateJSON{HostID: id.HostID, CAPin: id.CAPin})
	if err != nil {
		return fmt.Errorf("encode agent state: %w", err)
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, stateFile), raw, 0o600)
}

// newKeyAndCSR creates an ECDSA P-256 key and a CSR for it.
func newKeyAndCSR(name string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create csr: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// pair builds a TLS certificate from PEM key and certificate and checks that
// the certificate was issued for hostID.
func pair(keyPEM, certPEM []byte, hostID string) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("server returned an unusable certificate: %w", err)
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
		}
	}
	if hostID != "" && cert.Leaf.Subject.CommonName != hostID {
		return tls.Certificate{}, errors.New("server returned a certificate for another host")
	}
	return cert, nil
}
