// SPDX-License-Identifier: Apache-2.0

package web

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// tokenBlock returns the hex colour tokens between a marker and the next
// "/* end */".
func tokenBlock(t *testing.T, css, marker string) map[string]string {
	t.Helper()
	i := strings.Index(css, "/* "+marker+" */")
	if i < 0 {
		t.Fatalf("marker %s missing", marker)
	}
	rest := css[i:]
	j := strings.Index(rest, "/* end */")
	if j < 0 {
		t.Fatalf("end of %s missing", marker)
	}
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;`).FindAllStringSubmatch(rest[:j], -1) {
		out[m[1]] = m[2]
	}
	return out
}

func luminance(t *testing.T, hex string) float64 {
	t.Helper()
	ch := func(s string) float64 {
		v, err := strconv.ParseUint(s, 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(hex[1:3]) + 0.7152*ch(hex[3:5]) + 0.0722*ch(hex[5:7])
}

func contrast(t *testing.T, a, b string) float64 {
	la, lb := luminance(t, a), luminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// TestTokenContrast requires WCAG AA (4.5:1) for every text pairing the
// stylesheet uses, in both colour schemes, and 3:1 for focus rings.
func TestTokenContrast(t *testing.T) {
	b, err := os.ReadFile("static/css/varde.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	text := [][2]string{
		{"text", "bg"}, {"text", "surface-1"}, {"text", "surface-2"}, {"text", "surface-3"},
		{"text-muted", "bg"}, {"text-muted", "surface-1"}, {"text-muted", "surface-2"},
		{"stone", "bg"}, {"stone", "surface-1"},
		{"link", "bg"}, {"link", "surface-1"},
		{"ember", "bg"}, {"ember", "surface-1"},
		{"on-ember", "ember"}, {"on-amber", "amber"}, {"on-info", "info"}, {"on-ok", "ok"},
	}
	ui := [][2]string{{"focus", "bg"}, {"focus", "surface-1"}}
	for _, scheme := range []string{"tokens:dark", "tokens:light"} {
		tok := tokenBlock(t, css, scheme)
		check := func(pairs [][2]string, min float64) {
			for _, p := range pairs {
				fg, ok1 := tok[p[0]]
				bg, ok2 := tok[p[1]]
				if !ok1 || !ok2 {
					t.Errorf("%s: token %s or %s missing", scheme, p[0], p[1])
					continue
				}
				if r := contrast(t, fg, bg); r < min {
					t.Errorf("%s: %s on %s = %.2f:1, need %.1f:1", scheme, p[0], p[1], r, min)
				}
			}
		}
		check(text, 4.5)
		check(ui, 3)
	}
}
