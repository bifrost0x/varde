// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"sort"
	"strings"
)

// Level says how far a device is identified.
type Level int

// The levels, from least to most identified.
const (
	LevelSeen Level = iota
	LevelAnchored
	LevelClass
	LevelModel
	LevelFirmware
	LevelSoftware
)

func (l Level) String() string {
	switch l {
	case LevelAnchored:
		return "anchored"
	case LevelClass:
		return "class"
	case LevelModel:
		return "model"
	case LevelFirmware:
		return "firmware"
	case LevelSoftware:
		return "software"
	}
	return "seen"
}

// Anchors returns the keys that identify the device across scans, sorted.
// A key in shared is left out: several addresses present it, so it names
// no single device (a default certificate, a cloned image).
func Anchors(d Device, shared map[string]bool) []string {
	var keys []string
	add := func(k string) {
		if !shared[k] {
			keys = append(keys, k)
		}
	}
	fields := d.Fields()
	manufacturer := statedManufacturer(fields)
	selfSigned := false
	for _, f := range fields {
		if f.Name == FieldCertSelfSigned && f.Value == "true" {
			selfSigned = true
		}
	}
	for _, f := range fields {
		switch f.Name {
		case FieldMAC:
			add("mac:" + strings.ToLower(f.Value))
		case FieldUUID:
			add("uuid:" + strings.ToLower(f.Value))
		case FieldSerial:
			if manufacturer != "" {
				// Protocols of one device spell the maker in different
				// letter case; the serial itself is kept as stated.
				add("serial:" + strings.ToLower(manufacturer) + "/" + f.Value)
			}
		case FieldSSHHostKey:
			add("ssh:" + f.Value)
		case FieldCertFingerprint:
			if selfSigned {
				add("cert:" + f.Value)
			}
		}
	}
	sort.Strings(keys)
	return dedupe(keys)
}

func dedupe(sorted []string) []string {
	out := sorted[:0]
	for i, k := range sorted {
		if i == 0 || k != sorted[i-1] {
			out = append(out, k)
		}
	}
	return out
}

// statedManufacturer returns the manufacturer the device states, or "" when
// it states none or several that differ (compared ignoring case).
func statedManufacturer(fields []Field) string {
	name := ""
	for _, f := range fields {
		if f.Name != FieldManufacturer || f.Trust != TrustStated {
			continue
		}
		v := strings.TrimSpace(f.Value)
		if name != "" && !strings.EqualFold(name, v) {
			return ""
		}
		name = v
	}
	return name
}

// SharedKeys returns the anchor keys that occur on more than one address.
func SharedKeys(ds []Device) map[string]bool {
	addrs := map[string]map[string]bool{}
	for _, d := range ds {
		for _, k := range Anchors(d, nil) {
			if addrs[k] == nil {
				addrs[k] = map[string]bool{}
			}
			addrs[k][d.Address] = true
		}
	}
	shared := map[string]bool{}
	for k, a := range addrs {
		if len(a) > 1 {
			shared[k] = true
		}
	}
	return shared
}

// DeviceLevel reports how far the device is identified.
func DeviceLevel(d Device, shared map[string]bool) Level {
	fields := d.Fields()
	if statedManufacturer(fields) != "" {
		model, version := false, false
		for _, f := range fields {
			if f.Trust != TrustStated {
				continue
			}
			switch f.Name {
			case FieldModel:
				model = true
			case FieldFirmware, FieldOSVersion:
				version = true
			}
		}
		if model && version {
			return LevelFirmware
		}
		if model {
			return LevelModel
		}
	}
	if d.Kind != "" && d.Kind != KindOther {
		return LevelClass
	}
	for _, f := range fields {
		if f.Name == FieldServiceType && f.Trust == TrustStated && mdnsClass(f.Value) {
			return LevelClass
		}
	}
	if len(Anchors(d, shared)) > 0 {
		return LevelAnchored
	}
	return LevelSeen
}

// mdnsClass reports whether Varde labels devices announcing the type.
func mdnsClass(typ string) bool {
	for _, m := range mdnsTypes {
		if m.typ == typ && m.label != "" {
			return true
		}
	}
	return false
}

// NextStep tells what would raise the level, in one line.
func NextStep(l Level) string {
	switch l {
	case LevelSeen:
		return "Varde sees only an address. Run Varde on the same network segment so it can read the device's MAC."
	case LevelAnchored, LevelClass, LevelModel:
		return "Help recognise this device: send its evidence, and the next data package names it for everyone."
	case LevelFirmware:
		return "Connect the device to read what runs on it."
	}
	return ""
}
