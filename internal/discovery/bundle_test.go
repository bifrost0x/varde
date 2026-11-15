// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bifrost0x/varde/internal/buildinfo"
)

func bundleDevice() Device {
	return Device{
		Address:  "192.168.1.20",
		Hostname: "marcels-nas",
		Kind:     "nas",
		Label:    "NAS marcels-nas",
		Services: []Service{
			{Proto: ProtoARP, Fields: []Field{
				{Name: FieldMAC, Value: "aa:bb:cc:dd:ee:ff", Trust: TrustStated},
			}},
			{Port: 443, Proto: ProtoHTTPS, Fields: []Field{
				{Name: FieldHTTPTitle, Value: "marcels-nas - UGOS Pro", Trust: TrustStated},
				{Name: FieldHTTPServer, Value: "nginx", Trust: TrustStated},
				{Name: FieldCertFingerprint, Value: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", Trust: TrustStated},
			}},
			{Port: 22, Proto: ProtoSSH, Fields: []Field{
				{Name: FieldSSHHostKey, Value: "SHA256:abcdefghijklmnop", Trust: TrustStated},
			}},
			{Port: 9999, Proto: ProtoSSDP, Fields: []Field{
				{Name: FieldManufacturer, Value: "UGREEN", Trust: TrustStated},
				{Name: FieldModel, Value: "DXP4800", Trust: TrustStated},
				{Name: FieldModelNumber, Value: "DXP4800-SN123", Trust: TrustStated},
				{Name: FieldSerial, Value: "SN123", Trust: TrustStated},
				{Name: FieldUUID, Value: "11111111-2222-3333-4444-555555555555", Trust: TrustStated},
				{Name: FieldDisplayName, Value: "marcels-nas", Trust: TrustStated},
			}},
		},
	}
}

func TestBundleDropsIdentity(t *testing.T) {
	b := MakeBundle(bundleDevice(), nil)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	js := strings.ToLower(string(raw))
	for _, secret := range []string{
		"sn123", "192.168.1.20", "marcels-nas", "aa:bb:cc:dd:ee:ff", "dd:ee:ff",
		"0f1e2d3c", "abcdefghijklmnop", "11111111-2222",
	} {
		if strings.Contains(js, secret) {
			t.Errorf("bundle leaks %q: %s", secret, raw)
		}
	}
	if b.OUI != "aa:bb:cc" {
		t.Errorf("OUI = %q", b.OUI)
	}
	if b.Label != "" {
		t.Errorf("label with the host name kept: %q", b.Label)
	}
	got := map[string]string{}
	for _, f := range b.Fields {
		got[f.Name] = f.Value
	}
	if got[FieldModel] != "DXP4800" || got[FieldManufacturer] != "UGREEN" || got[FieldHTTPServer] != "nginx" {
		t.Errorf("fields = %v", got)
	}
	if _, ok := got[FieldHTTPTitle]; ok {
		t.Error("http_title with the host name kept")
	}
	if _, ok := got[FieldModelNumber]; ok {
		t.Error("model_number with the serial kept")
	}
	if b.Format != 1 || b.Kind != "nas" || b.Level == "" {
		t.Errorf("header = %+v", b)
	}
	want := []string{"443/https", "22/ssh", "9999/ssdp"}
	if strings.Join(b.Ports, ",") != strings.Join(want, ",") {
		t.Errorf("ports = %v, want %v", b.Ports, want)
	}
}

func TestBundleKeepsCleanLabel(t *testing.T) {
	d := bundleDevice()
	d.Label = "NAS"
	if b := MakeBundle(d, nil); b.Label != "NAS" {
		t.Errorf("label = %q", b.Label)
	}
}

func TestBundleContainmentIsCaseInsensitive(t *testing.T) {
	d := Device{Address: "10.0.0.5", Hostname: "Printer-Office", Kind: "printer", Services: []Service{
		{Port: 80, Proto: ProtoHTTP, Fields: []Field{
			{Name: FieldHTTPTitle, Value: "PRINTER-OFFICE status", Trust: TrustStated},
			{Name: FieldHTTPServer, Value: "lighttpd 10.0.0.5", Trust: TrustStated},
			{Name: FieldModel, Value: "X1", Trust: TrustStated},
			{Name: FieldSerial, Value: "ab", Trust: TrustStated},
			{Name: FieldFirmware, Value: "ab-1.2", Trust: TrustStated},
		}},
	}}
	b := MakeBundle(d, nil)
	got := map[string]bool{}
	for _, f := range b.Fields {
		got[f.Name] = true
	}
	if got[FieldHTTPTitle] || got[FieldHTTPServer] {
		t.Errorf("fields = %v", b.Fields)
	}
	// A two character serial is dropped but does not serve as a needle.
	if got[FieldSerial] || !got[FieldFirmware] || !got[FieldModel] {
		t.Errorf("fields = %v", b.Fields)
	}
}

func TestBundleDropsMACWithoutColons(t *testing.T) {
	d := Device{Address: "10.0.0.5", Services: []Service{
		{Proto: ProtoARP, Fields: []Field{{Name: FieldMAC, Value: "aa:bb:cc:dd:ee:ff", Trust: TrustStated}}},
		{Port: 80, Proto: ProtoHTTP, Fields: []Field{
			{Name: FieldHTTPTitle, Value: "AABBCCDDEEFF setup", Trust: TrustStated},
			{Name: FieldModel, Value: "Z", Trust: TrustStated},
		}},
	}}
	for _, f := range MakeBundle(d, nil).Fields {
		if f.Name == FieldHTTPTitle {
			t.Errorf("title with the MAC kept: %v", f)
		}
	}
}

func TestBundleEmptyDeviceMarshalsLists(t *testing.T) {
	raw, _ := json.Marshal(MakeBundle(Device{Address: "10.0.0.5"}, nil))
	if strings.Contains(string(raw), "null") {
		t.Errorf("bundle = %s", raw)
	}
}

func TestBundleIssueURL(t *testing.T) {
	u, ok := MakeBundle(bundleDevice(), nil).IssueURL()
	if !ok {
		t.Fatal("small bundle gets no URL")
	}
	if !strings.HasPrefix(u, buildinfo.RepoURL+"/issues/new?") || !strings.Contains(u, "template=device.yml") {
		t.Errorf("url = %s", u)
	}
	if !strings.Contains(u, "title=Device%3A+UGREEN+DXP4800") {
		t.Errorf("url = %s", u)
	}
	if strings.Contains(u, "192.168.1.20") || strings.Contains(u, "SN123") {
		t.Errorf("url leaks: %s", u)
	}

	big := Bundle{Format: 1, Kind: "nas", Label: "NAS"}
	for i := 0; i < 32; i++ {
		big.Fields = append(big.Fields, Field{Name: FieldSysDescr, Value: strings.Repeat("x", 128), Trust: TrustStated})
	}
	if u, ok := big.IssueURL(); ok || u != "" {
		t.Errorf("large bundle: ok=%v len=%d", ok, len(u))
	}
}

func TestBundleIssueURLTitleFallsBackToLabel(t *testing.T) {
	u, ok := Bundle{Format: 1, Label: "Router"}.IssueURL()
	if !ok || !strings.Contains(u, "title=Device%3A+Router") {
		t.Errorf("url = %s", u)
	}
}
