// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/store"
)

func TestLayers(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	cfg, err := config.Load(func(k string) (string, bool) {
		if k == "VARDE_INTERNAL_DOMAINS" {
			return "home.arpa", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get().Policy.P1CVSSPublic != 9.0 || s.Get().DigestHour != 8 || !s.Get().ContainerPackages || s.Get().RegistryTags {
		t.Fatalf("defaults: %+v", s.Get())
	}
	now := time.Now()
	if err := s.Update(ctx, map[string]string{KeyPublicDomains: "Example.com, foo.org", KeyP1EPSS: "0.2", KeyDirectOSV: "true"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	e := s.Get()
	if len(e.PublicDomains) != 2 || e.PublicDomains[0] != "example.com" || e.Policy.P1EPSS != 0.2 || !e.DirectOSV {
		t.Fatalf("ui values: %+v", e)
	}
	if err := s.Update(ctx, map[string]string{KeyInternalDomains: "lan"}, "admin", now); !errors.Is(err, ErrLocked) || !s.Locked(KeyInternalDomains) {
		t.Fatalf("env lock: %v", err)
	}
	for _, bad := range []map[string]string{{KeyP2CVSS: "11"}, {KeyP1EPSS: "x"}, {KeyDigestHour: "25"}, {KeyPublicDomains: "https://x"}, {"BOGUS": "1"}, {KeyContainerPackages: "maybe"}} {
		if err := s.Update(ctx, bad, "admin", now); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if err := s.Update(ctx, map[string]string{KeyContainerPackages: "false"}, "admin", now); err != nil || s.Get().ContainerPackages {
		t.Fatalf("container packages off: %v", err)
	}
	// Persisted: a fresh service sees the values.
	s2, err := New(ctx, st, cfg)
	if err != nil || len(s2.Get().PublicDomains) != 2 || s2.Get().InternalDomains[0] != "home.arpa" {
		t.Fatalf("reload: %+v %v", s2.Get(), err)
	}
	// Reset to default.
	if err := s.Update(ctx, map[string]string{KeyP1EPSS: ""}, "admin", now); err != nil || s.Get().Policy.P1EPSS != 0.10 {
		t.Fatalf("reset: %v %v", err, s.Get().Policy.P1EPSS)
	}
}

func TestDirectQueriesSetting(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	cfg, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get().DirectQueries {
		t.Fatal("direct queries are on by default")
	}
	if err := s.Update(ctx, map[string]string{KeyDirectQueries: "true"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !s.Get().DirectQueries {
		t.Fatal("switch not effective")
	}
	if err := s.Update(ctx, map[string]string{KeyDirectQueries: "perhaps"}, "admin", time.Now()); err == nil {
		t.Fatal("bad value accepted")
	}
}
