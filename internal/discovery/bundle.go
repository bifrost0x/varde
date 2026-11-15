// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/bifrost0x/varde/internal/buildinfo"
)

// bundleFormat is the version of the evidence bundle layout.
const bundleFormat = 1

// issueURLLimit caps the length of the pre-filled issue link; browsers and
// GitHub reject much longer ones.
const issueURLLimit = 6000

// needleMin is the shortest dropped value that still serves to find leaks
// in other fields. A one or two character serial would otherwise empty the
// whole bundle.
const needleMin = 4

// bundleKeep lists the fields that describe a device model and carry no
// identity of their own. Everything else is dropped.
var bundleKeep = map[string]bool{
	FieldManufacturer:   true,
	FieldModel:          true,
	FieldModelNumber:    true,
	FieldFirmware:       true,
	FieldOS:             true,
	FieldOSVersion:      true,
	FieldHWVersion:      true,
	FieldVendorOID:      true,
	FieldServiceType:    true,
	FieldSysDescr:       true,
	FieldCertIssuer:     true,
	FieldCertSubject:    true,
	FieldCertSelfSigned: true,
	FieldHTTPTitle:      true,
	FieldHTTPServer:     true,
	FieldFavicon:        true,
}

// Bundle is what a user may send to the project to get a device
// recognized. It holds the device class and the stated model facts, and
// nothing that points at this particular device or installation.
type Bundle struct {
	Format int      `json:"format"`
	Kind   string   `json:"kind"`
	Label  string   `json:"label"`
	Level  string   `json:"level"`
	Ports  []string `json:"ports"`
	// OUI is the manufacturer prefix of the MAC address, the first three
	// octets.
	OUI    string  `json:"oui,omitempty"`
	Fields []Field `json:"fields"`
}

// MakeBundle builds the evidence bundle of d. A field is dropped when it
// names the device (serial, UUID, MAC, certificate or host key
// fingerprint, display name) and also when its value contains any of
// those, the address or the host name, in any letter case. Dropping a
// field is always preferred over the risk of a leak.
func MakeBundle(d Device, shared map[string]bool) Bundle {
	b := Bundle{
		Format: bundleFormat,
		Kind:   d.Kind,
		Level:  DeviceLevel(d, shared).String(),
		Ports:  []string{},
		Fields: []Field{},
	}

	seenPort := map[string]bool{}
	for _, s := range d.Services {
		if s.Port <= 0 {
			continue
		}
		p := strconv.Itoa(s.Port) + "/" + s.Proto
		if !seenPort[p] {
			seenPort[p] = true
			b.Ports = append(b.Ports, p)
		}
	}

	fields := d.Fields()
	var needles []string
	addNeedle := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if len(v) >= needleMin {
			needles = append(needles, v)
		}
	}
	// The address and host name always count, however short.
	if a := strings.ToLower(strings.TrimSpace(d.Address)); a != "" {
		needles = append(needles, a)
	}
	if h := strings.ToLower(strings.TrimSpace(d.Hostname)); h != "" {
		needles = append(needles, h)
		if short, _, ok := strings.Cut(h, "."); ok && short != "" {
			addNeedle(short)
		}
	}
	for _, f := range fields {
		if bundleKeep[f.Name] {
			continue
		}
		addNeedle(f.Value)
		// The same value written without separators: a MAC as
		// aabbccddeeff, a UUID or fingerprint without dashes or colons.
		addNeedle(stripSeparators(f.Value))
		if f.Name == FieldMAC && b.OUI == "" {
			b.OUI = ouiOf(f.Value)
		}
	}

	leaks := func(s string) bool {
		s = strings.ToLower(s)
		compact := stripSeparators(s)
		for _, n := range needles {
			if strings.Contains(s, n) || strings.Contains(compact, n) {
				return true
			}
		}
		return false
	}

	for _, f := range fields {
		if bundleKeep[f.Name] && !leaks(f.Value) {
			b.Fields = append(b.Fields, f)
		}
	}
	if !leaks(d.Label) {
		b.Label = d.Label
	}
	return b
}

// stripSeparators removes the characters that separate the groups of a
// MAC address, UUID or fingerprint.
func stripSeparators(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ':
			return -1
		}
		return r
	}, s)
}

// ouiOf returns the first three octets of a colon separated MAC address,
// or "" for anything else.
func ouiOf(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if len(mac) != 17 {
		return ""
	}
	return mac[:8]
}

// IssueURL returns a link that opens the device issue form with the bundle
// filled in. ok is false when the link would be too long; the bundle then
// goes in as a file.
func (b Bundle) IssueURL() (string, bool) {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return "", false
	}
	var model []string
	for _, name := range []string{FieldManufacturer, FieldModel} {
		for _, f := range b.Fields {
			if f.Name == name {
				model = append(model, f.Value)
				break
			}
		}
	}
	title := "Device: " + strings.Join(model, " ")
	if len(model) == 0 {
		title = "Device: " + b.Label
	}
	q := url.Values{}
	q.Set("template", "device.yml")
	q.Set("title", strings.TrimSpace(title))
	q.Set("evidence", string(raw))
	u := buildinfo.RepoURL + "/issues/new?" + q.Encode()
	if len(u) > issueURLLimit {
		return "", false
	}
	return u, true
}
