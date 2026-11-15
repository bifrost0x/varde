// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"reflect"
	"testing"
)

func dev(kind string, fs ...Field) Device {
	return Device{Kind: kind, Services: []Service{{Port: 80, Proto: ProtoHTTP, Fields: fs}}}
}

func st(name, value string) Field { return Field{Name: name, Value: value, Trust: TrustStated} }

func TestDeviceLevel(t *testing.T) {
	cases := []struct {
		name string
		d    Device
		want Level
	}{
		{"nothing", dev(KindOther), LevelSeen},
		{"empty kind", dev(""), LevelSeen},
		{"mac", dev(KindOther, st(FieldMAC, "AA:BB:CC:DD:EE:FF")), LevelAnchored},
		{"class", dev(KindNAS), LevelClass},
		{"service type", dev(KindOther, st(FieldServiceType, "_ipp._tcp")), LevelClass},
		{"unlabelled service type", dev(KindOther, st(FieldServiceType, "_unknown._tcp")), LevelSeen},
		{"model", dev(KindOther, st(FieldManufacturer, "UGREEN"), st(FieldModel, "DXP4800")), LevelModel},
		{"manufacturer case", dev(KindOther, st(FieldManufacturer, "UGREEN"), st(FieldManufacturer, " Ugreen "), st(FieldModel, "DXP4800")), LevelModel},
		{"firmware", dev(KindOther, st(FieldManufacturer, "UGREEN"), st(FieldModel, "DXP4800"), st(FieldFirmware, "1.2.0")), LevelFirmware},
		{"os version", dev(KindOther, st(FieldManufacturer, "UGREEN"), st(FieldModel, "DXP4800"), st(FieldOSVersion, "6.1")), LevelFirmware},
		{"model without manufacturer", dev(KindOther, st(FieldModel, "DXP4800")), LevelSeen},
		{"derived is not stated", dev(KindOther,
			Field{FieldManufacturer, "UGREEN", TrustDerived}, st(FieldModel, "DXP4800")), LevelSeen},
		{"disagreeing manufacturers", dev(KindNAS,
			st(FieldManufacturer, "UGREEN"), st(FieldModel, "DXP4800"),
			st(FieldManufacturer, "Synology"), st(FieldModel, "DS920+")), LevelClass},
	}
	for _, c := range cases {
		if got := DeviceLevel(c.d, nil); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLevelStringAndNextStep(t *testing.T) {
	names := []string{"seen", "anchored", "class", "model", "firmware", "software"}
	for i, n := range names {
		if got := Level(i).String(); got != n {
			t.Errorf("Level(%d) = %q, want %q", i, got, n)
		}
	}
	if got, want := NextStep(LevelSeen), "Varde sees only an address. Run Varde on the same network segment so it can read the device's MAC."; got != want {
		t.Errorf("seen: %q", got)
	}
	if NextStep(LevelSoftware) != "" {
		t.Error("software has a next step")
	}
	for _, l := range []Level{LevelSeen, LevelAnchored, LevelClass, LevelModel, LevelFirmware} {
		if NextStep(l) == "" {
			t.Errorf("%v has no next step", l)
		}
	}
}

func TestAnchorsSharedKeyIsNoAnchor(t *testing.T) {
	cert := func(addr, fp string) Device {
		d := dev(KindOther, st(FieldCertFingerprint, fp), st(FieldCertSelfSigned, "true"))
		d.Address = addr
		return d
	}
	a, b, c := cert("10.0.0.1", "fp-shared"), cert("10.0.0.2", "fp-shared"), cert("10.0.0.3", "fp-own")
	shared := SharedKeys([]Device{a, b, c})
	if !shared["cert:fp-shared"] || shared["cert:fp-own"] || len(shared) != 1 {
		t.Fatalf("shared = %v", shared)
	}
	if got := Anchors(a, shared); len(got) != 0 {
		t.Errorf("shared key kept: %v", got)
	}
	if got := Anchors(c, shared); !reflect.DeepEqual(got, []string{"cert:fp-own"}) {
		t.Errorf("own key lost: %v", got)
	}
	if DeviceLevel(a, shared) != LevelSeen || DeviceLevel(c, shared) != LevelAnchored {
		t.Error("level ignores shared keys")
	}
}

func TestAnchorKeys(t *testing.T) {
	d := dev(KindOther,
		st(FieldMAC, "AA:BB:CC:00:11:22"), st(FieldUUID, "ABC-DEF"),
		st(FieldSSHHostKey, "SHA256:xyz"), st(FieldSerial, "S1"),
		st(FieldCertFingerprint, "cf"), st(FieldCertSelfSigned, "false"))
	got := Anchors(d, nil)
	want := []string{"mac:aa:bb:cc:00:11:22", "ssh:SHA256:xyz", "uuid:abc-def"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	d = dev(KindOther, st(FieldManufacturer, "UGREEN"), st(FieldSerial, "S1"))
	if got := Anchors(d, nil); !reflect.DeepEqual(got, []string{"serial:ugreen/S1"}) {
		t.Fatalf("serial: %v", got)
	}
	// The same device states its maker in other letter case on another
	// protocol; the key must not change with it.
	other := dev(KindOther, st(FieldManufacturer, "Ugreen"), st(FieldSerial, "S1"))
	if a, b := Anchors(d, nil), Anchors(other, nil); !reflect.DeepEqual(a, b) {
		t.Errorf("UGREEN %v and Ugreen %v give different keys", a, b)
	}
}
