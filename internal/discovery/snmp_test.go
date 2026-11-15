// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"net"
	"net/netip"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// snmpAgent answers v2c GET requests with the community "home".
func snmpAgent(t *testing.T) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		dec := &gosnmp.GoSNMP{Version: gosnmp.Version2c}
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := dec.SnmpDecodePacket(buf[:n])
			if err != nil || req.Community != "home" {
				continue
			}
			resp := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID,
				Variables: []gosnmp.SnmpPDU{
					{Name: oidSysDescr, Type: gosnmp.OctetString, Value: []byte("GS108Tv3 8-Port Gigabit Smart Managed Plus Switch\nB7.0.2.3")},
					{Name: oidSysObjectID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.4526.100.4.50"},
					{Name: oidSysName, Type: gosnmp.OctetString, Value: []byte("core-switch")},
				}}
			b, err := resp.MarshalMsg()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(b, from)
		}
	}()
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
}

// With a community the scan names a managed switch by its system
// description and takes its name; without one, or with a wrong one, it
// sends nothing or learns nothing.
func TestSNMPDescription(t *testing.T) {
	port := snmpAgent(t)
	a := netip.MustParseAddr("127.0.0.1")
	s := &Scanner{InFlight: 2, SNMP: &SNMP{Community: "home"}, snmpPort: port}
	got := s.snmpScan(t.Context(), []netip.Addr{a}, func(netip.Addr) bool { return true })
	ans, ok := got[a]
	if !ok || ans.svc.Product != "GS108Tv3 8-Port Gigabit Smart Managed Plus Switch" || ans.name != "core-switch" {
		t.Fatalf("answer %+v", got)
	}
	if len(ans.svc.Fields) == 0 || ans.svc.Fields[0].Name != FieldSysDescr {
		t.Errorf("fields %+v", ans.svc.Fields)
	}
	if kind, label := Classify([]Service{{Port: 22, Proto: ProtoSSH, Product: "OpenSSH_9.2"}, ans.svc}); kind != KindOther || label != ans.svc.Product {
		t.Errorf("classified %s %q", kind, label)
	}
	wrong := &Scanner{InFlight: 2, SNMP: &SNMP{Community: "public"}, snmpPort: port}
	if got := wrong.snmpScan(t.Context(), []netip.Addr{a}, func(netip.Addr) bool { return true }); len(got) != 0 {
		t.Errorf("wrong community answered: %+v", got)
	}
	if (&SNMP{}).Enabled() || (*SNMP)(nil).Enabled() || !(&SNMP{User: "u", Auth: "a"}).Enabled() {
		t.Error("enabled rule")
	}
}

// The object ID and the ENTITY-MIB columns become typed fields; an object
// the device does not have is skipped, and the name is a display name only.
func TestSNMPFields(t *testing.T) {
	vars := []gosnmp.SnmpPDU{
		{Name: oidSysDescr, Type: gosnmp.OctetString, Value: []byte("DiskStation\nDSM 7.2")},
		{Name: oidSysObjectID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.6574.1"},
		{Name: oidSysName, Type: gosnmp.OctetString, Value: []byte("box")},
		{Name: oidEntFirmware, Type: gosnmp.OctetString, Value: []byte("DSM 7.2")},
		{Name: oidEntSerial, Type: gosnmp.OctetString, Value: []byte("X1")},
		{Name: oidEntModel, Type: gosnmp.NoSuchObject},
		{Name: oidEntMfg, Type: gosnmp.NoSuchInstance},
	}
	want := map[string]Field{
		FieldVendorOID:   {FieldVendorOID, "1.3.6.1.4.1.6574.1", TrustStated},
		FieldFirmware:    {FieldFirmware, "DSM 7.2", TrustStated},
		FieldSerial:      {FieldSerial, "X1", TrustStated},
		FieldDisplayName: {FieldDisplayName, "box", TrustStated},
		FieldSysDescr:    {FieldSysDescr, "DiskStation", TrustDerived},
	}
	got := snmpFields(vars)
	if len(got) != len(want) {
		t.Fatalf("fields %+v", got)
	}
	for _, f := range got {
		if w, ok := want[f.Name]; !ok || w != f {
			t.Errorf("unexpected field %+v", f)
		}
	}
}
