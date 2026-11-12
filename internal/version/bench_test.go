// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func BenchmarkParseSemVer(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Parse(SemVer, "v1.123.4-rc.1")
	}
}

func BenchmarkCompare(b *testing.B) {
	x, y := MustParse(SemVer, "1.123.4"), MustParse(SemVer, "1.123.10")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = x.Compare(y)
	}
}
