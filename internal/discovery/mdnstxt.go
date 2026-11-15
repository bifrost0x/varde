// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// mdnsInfoTypes are the DNS-SD service types whose instances carry TXT
// records worth a follow-up query, in the order they are asked.
var mdnsInfoTypes = []string{"_device-info._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_googlecast._tcp", "_hap._tcp", "_airplay._tcp", "_esphomelib._tcp", "_shelly._tcp", "_smb._tcp", "_http._tcp"}

// mdnsFollowUps caps the queries sent to one device after the enumeration.
const mdnsFollowUps = 4

// mdnsRecordLimit bounds the records read from one section of a message.
const mdnsRecordLimit = 64

// mdnsQuery builds a PTR question for the instances of one service type,
// such as "_ipp._tcp".
func mdnsQuery(name string) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0})
	n, err := dnsmessage.NewName(name + ".local.")
	if err != nil {
		return nil, err
	}
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// parseMDNSInstances reads instance names (PTR) and TXT records from the
// answer and additional sections of a response. SRV records carry only a
// host name and a port and add nothing identifying, so they are skipped.
func parseMDNSInstances(msg []byte) (fields []Field) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	read := func(header func() (dnsmessage.ResourceHeader, error), skip func() error) {
		for range mdnsRecordLimit {
			h, err := header()
			if err != nil {
				return
			}
			switch h.Type {
			case dnsmessage.TypePTR:
				r, err := p.PTRResource()
				if err != nil {
					return
				}
				if strings.HasPrefix(h.Name.String(), "_services.") {
					continue
				}
				// "nas._ipp._tcp.local." names the instance "nas".
				full := r.PTR.String()
				if i := strings.Index(full, "._"); i > 0 {
					fields = addField(fields, FieldDisplayName, full[:i], TrustStated)
				}
			case dnsmessage.TypeTXT:
				r, err := p.TXTResource()
				if err != nil {
					return
				}
				for _, f := range txtFields(r.TXT) {
					fields = addField(fields, f.Name, f.Value, f.Trust)
				}
			default:
				if skip() != nil {
					return
				}
			}
		}
	}
	read(p.AnswerHeader, p.SkipAnswer)
	if p.SkipAllAuthorities() != nil {
		return fields
	}
	read(p.AdditionalHeader, p.SkipAdditional)
	return fields
}

// txtFields maps the key=value strings of a TXT record to fields. Keys are
// case-insensitive; display-only keys such as fn are ignored.
func txtFields(pairs []string) []Field {
	var out []Field
	for _, kv := range pairs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		var name string
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "md", "model", "usb_mdl", "ty":
			name = FieldModel
		case "mfg", "usb_mfg", "manufacturer":
			name = FieldManufacturer
		case "fw", "fwversion", "firmware", "fv":
			name = FieldFirmware
		case "serial", "sn":
			name = FieldSerial
		case "mac":
			name = FieldMAC
		case "deviceid", "id":
			if !isMAC(v) {
				continue
			}
			name = FieldMAC
		case "osxvers":
			name = FieldOSVersion
		default:
			continue
		}
		if name == FieldMAC {
			v = strings.ToLower(v)
		}
		out = addField(out, name, v, TrustStated)
	}
	return out
}

// isMAC reports whether s is a colon-separated MAC address.
func isMAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i%3 == 2:
			if c != ':' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// mdnsInfoFields sends the follow-up queries for the info types the device
// listed, at most mdnsFollowUps, and returns what they state.
func (s *Scanner) mdnsInfoFields(ctx context.Context, to netip.AddrPort, types []string) []Field {
	var fields []Field
	listed := map[string]bool{}
	for _, t := range types {
		listed[t] = true
	}
	sent := 0
	for _, t := range mdnsInfoTypes {
		if sent == mdnsFollowUps || ctx.Err() != nil {
			break
		}
		if !listed[t] {
			continue
		}
		sent++
		q, err := mdnsQuery(t)
		if err != nil {
			continue
		}
		ans, ok := s.udpExchange(ctx, to, q)
		if !ok {
			continue
		}
		for _, f := range parseMDNSInstances(ans) {
			fields = addField(fields, f.Name, f.Value, f.Trust)
		}
	}
	return fields
}

// mdnsTypeFields lists the enumerated service types as fields.
func mdnsTypeFields(fields []Field, types []string) []Field {
	for _, t := range types {
		fields = addField(fields, FieldServiceType, t, TrustStated)
	}
	return fields
}
