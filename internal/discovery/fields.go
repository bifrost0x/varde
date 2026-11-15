// SPDX-License-Identifier: Apache-2.0

package discovery

// Trust says where a field value comes from.
type Trust string

const (
	// TrustStated marks a value the device itself reported.
	TrustStated Trust = "stated"
	// TrustDerived marks a value Varde inferred, such as from a MAC prefix.
	TrustDerived Trust = "derived"
)

// Field is one typed fact a device stated about itself.
type Field struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
	Trust Trust  `json:"trust" yaml:"trust"`
}

// Field names. Readers use these and nothing else.
const (
	FieldManufacturer    = "manufacturer"
	FieldModel           = "model"
	FieldModelNumber     = "model_number"
	FieldFirmware        = "firmware"
	FieldOS              = "os"
	FieldOSVersion       = "os_version"
	FieldHWVersion       = "hw_version"
	FieldSerial          = "serial"
	FieldUUID            = "uuid"
	FieldMAC             = "mac"
	FieldVendorOID       = "vendor_oid"
	FieldServiceType     = "service_type"
	FieldSysDescr        = "sys_descr"
	FieldCertIssuer      = "cert_issuer"
	FieldCertSubject     = "cert_subject"
	FieldCertFingerprint = "cert_fingerprint"
	FieldCertSelfSigned  = "cert_self_signed"
	FieldSSHHostKey      = "ssh_hostkey"
	FieldHTTPTitle       = "http_title"
	FieldHTTPServer      = "http_server"
	FieldFavicon         = "favicon"
	FieldDisplayName     = "display_name"
)

const (
	fieldValueLimit = 128
	fieldsPerList   = 32
)

// addField appends a field to fs. Values come off the network, so they are
// trimmed and stripped of control characters and cut to a fixed length;
// empty values, repeats of a name and value, and anything past the list
// cap are dropped.
func addField(fs []Field, name, value string, t Trust) []Field {
	value = printable(value, fieldValueLimit)
	if value == "" || len(fs) >= fieldsPerList {
		return fs
	}
	for _, f := range fs {
		if f.Name == name && f.Value == value {
			return fs
		}
	}
	return append(fs, Field{Name: name, Value: value, Trust: t})
}

// Fields returns the fields of all services of the device, without repeats.
func (d Device) Fields() []Field {
	var out []Field
	seen := map[[2]string]bool{}
	for _, s := range d.Services {
		for _, f := range s.Fields {
			k := [2]string{f.Name, f.Value}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
