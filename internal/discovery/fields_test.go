// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"fmt"
	"strings"
	"testing"
)

func TestAddFieldBounds(t *testing.T) {
	var fs []Field
	fs = addField(fs, FieldModel, "   ", TrustStated)
	if len(fs) != 0 {
		t.Fatalf("empty value kept: %v", fs)
	}
	fs = addField(fs, FieldModel, " DXP4800 ", TrustStated)
	fs = addField(fs, FieldModel, "DXP4800", TrustDerived)
	if len(fs) != 1 || fs[0].Value != "DXP4800" || fs[0].Trust != TrustStated {
		t.Fatalf("duplicate or untrimmed: %v", fs)
	}
	fs = addField(nil, FieldSysDescr, strings.Repeat("é", 200), TrustStated)
	if got := len([]rune(fs[0].Value)); got > 128 {
		t.Fatalf("value not cut: %d runes", got)
	}
	fs = addField(nil, FieldHTTPTitle, "a\x00b\x1b[0m\n", TrustStated)
	if fs[0].Value != "ab[0m" {
		t.Fatalf("control characters kept: %q", fs[0].Value)
	}
	fs = nil
	for i := 0; i < 40; i++ {
		fs = addField(fs, FieldSerial, fmt.Sprintf("S%d", i), TrustStated)
	}
	if len(fs) != 32 {
		t.Fatalf("cap: got %d, want 32", len(fs))
	}
}

func TestDeviceFieldsDeduplicated(t *testing.T) {
	d := Device{Services: []Service{
		{Fields: []Field{{FieldModel, "X", TrustStated}, {FieldMAC, "aa", TrustStated}}},
		{Fields: []Field{{FieldModel, "X", TrustStated}}},
	}}
	if got := d.Fields(); len(got) != 2 {
		t.Fatalf("got %v, want 2 fields", got)
	}
}
