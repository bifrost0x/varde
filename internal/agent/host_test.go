// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVirtualBridge(t *testing.T) {
	for name, want := range map[string]bool{
		"docker0": true, "br-3f2a1b": true, "veth12ab": true, "virbr0": true, "cni0": true,
		"eth0": false, "enp3s0": false, "vmbr0": false, "wlan0": false, "tailscale0": false,
	} {
		if virtualBridge(name) != want {
			t.Errorf("virtualBridge(%q) = %v", name, !want)
		}
	}
}

func TestPrettyName(t *testing.T) {
	f := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(f, []byte("ID=alpine\nPRETTY_NAME=\"Alpine Linux v3.22\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := prettyName(f); got != "Alpine Linux v3.22" {
		t.Fatalf("prettyName = %q", got)
	}
}
