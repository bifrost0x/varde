// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

// The functions below expose the pure readers to the evaluation, which
// feeds them recorded answers instead of a network.

// ParseUPnP reads a UPnP device description: the product label, the fields
// it states and whether it names a product.
func ParseUPnP(r io.Reader) (string, []Field, bool) { return parseUPnPDescription(r) }

// TXTFields maps the key=value strings of an mDNS TXT record to fields.
func TXTFields(pairs []string) []Field { return txtFields(pairs) }

// PageFields returns the fields of a page title and Server header.
func PageFields(title, server string) []Field { return pageFields(title, server) }

// CertFieldsPEM returns the fields of the first certificate in a PEM block.
func CertFieldsPEM(data []byte) ([]Field, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate in PEM data")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certFields(c), nil
}
