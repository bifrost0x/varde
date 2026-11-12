// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"strings"
	"testing"
)

func TestTokenFormat(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	secret := strings.Repeat("x", 43)
	s, p, err := ParseToken("  " + FormatToken(secret, strings.ToUpper(pin)) + "\n")
	if err != nil || s != secret || p != pin {
		t.Fatalf("round trip: %q %q %v", s, p, err)
	}
	for _, bad := range []string{
		"",
		"varde-enroll-v1." + secret,
		"varde-enroll-v2." + secret + "." + pin,
		"varde-enroll-v1.short." + pin,
		"varde-enroll-v1." + secret + "." + pin[:60],
		"varde-enroll-v1." + secret + "." + strings.Repeat("zz", 32),
		"varde-enroll-v1." + strings.Repeat("x", 42) + "/." + pin,
		"varde-enroll-v1." + secret + "." + pin + ".extra",
	} {
		if _, _, err := ParseToken(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestValidAgent(t *testing.T) {
	if ValidAgent(Agent{Name: "nas", Version: "1.0.0", OS: "Debian GNU/Linux 13", Arch: "arm64"}) != nil {
		t.Error("valid agent rejected")
	}
	for _, a := range []Agent{{}, {Name: strings.Repeat("n", 129)}, {Name: "a\nb"}, {Name: "ok", OS: "x\x00"}} {
		if ValidAgent(a) == nil {
			t.Errorf("accepted %+v", a)
		}
	}
}
