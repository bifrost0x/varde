// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/bifrost0x/varde/internal/advisory/sources"
	"github.com/bifrost0x/varde/internal/catalog"
)

// The records of the vulnerability datasets stop counting when they are
// switched off; every other source keeps the rule it had.
func TestWithVulnDB(t *testing.T) {
	on := true
	feedApp := &catalog.App{ID: "a", Origin: catalog.OriginFeed}
	s := withVulnDB(nil, func() bool { return on })
	if s(nil, sources.SourceVulnDB) || s(feedApp, sources.SourceVulnDB) {
		t.Error("records of the datasets dropped while they are on")
	}
	if !s(feedApp, "github:x/y") || s(nil, "github:x/y") {
		t.Error("the default rule for other sources changed")
	}
	on = false
	if !s(nil, sources.SourceVulnDB) {
		t.Error("records of the datasets count while they are off")
	}
	base := withVulnDB(func(*catalog.App, string) bool { return true }, func() bool { return true })
	if base(nil, sources.SourceVulnDB) || !base(nil, "osv") {
		t.Error("a given rule is not kept for the other sources")
	}
}
