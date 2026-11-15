// SPDX-License-Identifier: Apache-2.0

package upstream

import "testing"

func TestTrack(t *testing.T) {
	tags := []string{
		"latest", "release", "v3",
		"1.26.0", "1.27.4", "1.27.5", "1.28.0-rc1", "2.0.0",
		"1.27.4-alpine", "1.27.6-alpine", "1.27.4-alpine3.20", "1.28.0-alpine3.21", "2.1.0-alpine",
		"3.4.1", "3.4.1-cuda", "3.5.0-cuda", "3.5.0-openvino", "3.6.0-rc.1-cuda",
		"v5.120.0", "v5.121.0", "5.122.0",
		"4.0.15.2941-ls275", "4.0.15.2941-ls276", "4.0.16.2950-ls280",
		"0.9.1", "0.9.4", "0.10.0",
		"2.0.0-rc.1", "2.0.0-rc.2",
	}
	cases := []struct {
		name, running string
		crossMajor    bool
		want          string
		ok            bool
	}{
		{"plain: newest of the major", "1.27.4", false, "1.27.5", true},
		{"major boundary crossed on request", "1.27.4", true, "5.122.0", true},
		{"alpine stays alpine", "1.27.4-alpine", false, "1.27.6-alpine", true},
		{"alpine with a base release may move base", "1.27.4-alpine3.20", false, "1.28.0-alpine3.21", true},
		{"cuda stays cuda, pre-releases ignored", "3.4.1-cuda", false, "3.5.0-cuda", true},
		{"no newer tag in the track", "3.4.1", false, "", true},
		{"prefix kept", "v5.120.0", false, "v5.121.0", true},
		{"build numbers of one variant", "4.0.15.2941-ls275", false, "4.0.16.2950-ls280", true},
		{"0.x minors are breaking", "0.9.1", false, "0.9.4", true},
		{"pre-release may move to a later pre-release", "2.0.0-rc.1", false, "2.0.0", true},
		{"floating tag has no track", "latest", false, "", false},
		{"major-only tag has no track", "v3", false, "", false},
		{"newest already", "2.1.0-alpine", false, "", true},
	}
	for _, c := range cases {
		got, ok := Track(c.running, tags, c.crossMajor)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: Track(%q) = %q, %v; want %q, %v", c.name, c.running, got, ok, c.want, c.ok)
		}
	}
}

func TestFloating(t *testing.T) {
	for tag, want := range map[string]bool{"latest": true, "release": true, "v3": true, "3": true, "1.2.3": false, "3.4.1-cuda": false, "": true} {
		if got := Floating(tag); got != want {
			t.Errorf("Floating(%q) = %v", tag, got)
		}
	}
}
