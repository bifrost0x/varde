// SPDX-License-Identifier: Apache-2.0

// Package wire defines the protocol between agents and the server: request
// and response types, the enrollment token format and the pinned TLS
// verification both sides use.
package wire

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/bifrost0x/varde/internal/inventory"
)

// Endpoints on the agent listener.
const (
	EnrollPath = "/agent/v1/enroll"
	ReportPath = "/agent/v1/report"
	RenewPath  = "/agent/v1/renew"
	// BinaryPath serves the agent binary for a platform (?platform=linux/amd64).
	BinaryPath = "/agent/v1/binary"
)

// Limits shared by both sides.
const (
	MaxBodyBytes = 32 << 20
	// MaxInventoryBytes bounds the host inventory in one report; the same
	// limit applies to the inventory read over SSH.
	MaxInventoryBytes = 16 << 20
	MaxWorkloads      = 5000
	MinIntervalS      = 60
	MaxIntervalS      = 24 * 3600
	tokenPrefix       = "varde-enroll-v1" //nolint:gosec // format prefix, not a credential
	pinHexLength      = 2 * sha256.Size
	secretMinimum     = 32
)

// EnrollRequest is sent once, with the one-time token, before the agent has
// a certificate.
type EnrollRequest struct {
	Token     string `json:"token"`
	CSR       string `json:"csr"` // PEM
	Agent     Agent  `json:"agent"`
	IntervalS int    `json:"interval_s"`
}

// EnrollResponse carries the signed client certificate.
type EnrollResponse struct {
	HostID      string `json:"host_id"`
	Certificate string `json:"certificate"` // PEM
}

// Agent describes the reporting agent and its host.
type Agent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	// Platform is the agent binary's GOOS/GOARCH ("linux/amd64"); the
	// server offers updates only for a platform it has a binary for.
	Platform string `json:"platform,omitempty"`
	// Docker tells whether the agent reads a Docker API; nil (older
	// agents) means it does.
	Docker *bool `json:"docker,omitempty"`
	// Addresses are the host's interface addresses; they tie it to the
	// device the network scan finds. Nil (older agents) keeps the stored.
	Addresses []string `json:"addresses,omitempty"`
}

// HostKind is the kind of host the agent runs on.
func (a Agent) HostKind() inventory.HostKind {
	if a.Docker != nil && !*a.Docker {
		return inventory.HostLinux
	}
	return inventory.HostDocker
}

// Report is pushed by an enrolled agent. Containers is nil when the snapshot
// is unchanged since the last accepted report (a heartbeat).
type Report struct {
	Agent        Agent                 `json:"agent"`
	IntervalS    int                   `json:"interval_s"`
	SnapshotHash string                `json:"snapshot_hash"`
	Containers   *[]inventory.Workload `json:"containers,omitempty"`
	// Inventory is the output of the inventory command run on the host
	// (the same the SSH inventory reads), sent with every full snapshot;
	// nil when the agent could not run it, for example in a container.
	Inventory *string `json:"inventory,omitempty"`
	// Images are the package databases of images the agent read since its
	// last accepted report, for images its own containers use (ADR 0033).
	Images []inventory.ImagePackages `json:"images,omitempty"`
}

// MaxImages bounds the image package records of one report.
const MaxImages = 50

// ReportResponse asks for a full snapshot when the server does not hold the
// one the heartbeat refers to.
type ReportResponse struct {
	NeedSnapshot bool `json:"need_snapshot"`
	// Update names the agent binary the server ships for the agent's
	// platform. The agent replaces itself when its own binary differs and
	// it may write it.
	Update *Update `json:"update,omitempty"`
	// ReadImages tells the agent to read the package databases of its
	// containers' images (the server's container packages setting).
	ReadImages bool `json:"read_images,omitempty"`
}

// Update identifies the agent binary the server offers.
type Update struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// RenewRequest asks for a new certificate for a new key.
type RenewRequest struct {
	CSR string `json:"csr"` // PEM
}

// RenewResponse carries the new certificate.
type RenewResponse struct {
	Certificate string `json:"certificate"` // PEM
}

// Fingerprint is the hex SHA-256 of a certificate's DER encoding.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ErrBadInventory marks a host inventory the server cannot read.
var ErrBadInventory = errors.New("invalid host inventory")

// ErrBadToken reports a malformed enrollment token.
var ErrBadToken = errors.New("malformed enrollment token")

// FormatToken builds an enrollment token from the secret and the CA pin. The
// pin lets the agent verify the server on first contact without trusting
// anything else.
func FormatToken(secret, caPin string) string {
	return tokenPrefix + "." + secret + "." + caPin
}

// ParseToken splits an enrollment token into secret and CA pin.
func ParseToken(tok string) (secret, caPin string, err error) {
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) != 3 || parts[0] != tokenPrefix || len(parts[1]) < secretMinimum || len(parts[1]) > 128 || len(parts[2]) != pinHexLength {
		return "", "", ErrBadToken
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", "", ErrBadToken
	}
	for _, r := range parts[1] {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return "", "", ErrBadToken
		}
	}
	return parts[1], strings.ToLower(parts[2]), nil
}

// PinnedServer returns a TLS verification function that accepts the server
// only if its chain contains the CA with the given pin and the leaf is signed
// by that CA for server authentication. Host names are not checked: the
// private CA pin identifies the server, as an SSH host key does.
func PinnedServer(caPin string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("server sent no certificate")
		}
		var ca *x509.Certificate
		for _, c := range cs.PeerCertificates[1:] {
			if Fingerprint(c) == caPin {
				ca = c
				break
			}
		}
		if ca == nil {
			return fmt.Errorf("server certificate is not issued by the pinned Varde CA")
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return fmt.Errorf("verify server certificate: %w", err)
		}
		return nil
	}
}

// ValidAgent checks the announced agent fields.
func ValidAgent(a Agent) error {
	for name, v := range map[string]string{"name": a.Name, "version": a.Version, "os": a.OS, "arch": a.Arch, "platform": a.Platform} {
		if len(v) > 128 || (name == "name" && v == "") {
			return fmt.Errorf("agent %s must be 1-128 characters", name)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("agent %s contains control characters", name)
			}
		}
	}
	if len(a.Addresses) > 32 {
		return errors.New("at most 32 agent addresses")
	}
	for _, s := range a.Addresses {
		if _, err := netip.ParseAddr(s); err != nil || len(s) > 64 {
			return fmt.Errorf("agent address %q is not an IP address", truncate(s, 64))
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
