// SPDX-License-Identifier: Apache-2.0

package identify

import "testing"

func TestVariantBase(t *testing.T) {
	for in, want := range map[string]string{
		"2.1.2-alpine":    "2.1.2",
		"4.0.20.3014-ls4": "4.0.20.3014",
		"1.37.5-slim":     "1.37.5",
		"3.4-bookworm":    "3.4",
		"1.2.3-rc1":       "1.2.3-rc1",
		"1.2.3-beta":      "1.2.3-beta",
		"1.2.3-beta.2":    "1.2.3-beta.2",
		"1.2.3":           "1.2.3",
	} {
		if got := variantBase(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
