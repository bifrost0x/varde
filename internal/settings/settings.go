// SPDX-License-Identifier: Apache-2.0

// Package settings merges configuration from three layers: built-in
// defaults < values saved in the UI < environment variables. Environment
// values are locked in the UI (docs/configuration.md).
package settings

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/exposure"
	"github.com/bifrost0x/varde/internal/policy"
)

// Store persists UI-managed values.
type Store interface {
	Settings(ctx context.Context) (map[string]string, error)
	PutSettings(ctx context.Context, values map[string]string, by string, now time.Time) error
}

// Effective is the merged view used by the running components.
type Effective struct {
	PublicDomains   []string
	InternalDomains []string
	Policy          policy.Thresholds
	DigestHour      int
	DigestWeekday   time.Weekday
	DirectOSV       bool
	DirectNVD       bool
	// DirectQueries: ask the public sources for apps the data package
	// does not cover.
	DirectQueries bool
	// Networks are the ranges Varde may scan and connect to (ADR 0020).
	Networks discovery.Scope
	// ScanEvery is the period of scheduled network scans; zero means off.
	ScanEvery time.Duration
	// RegistryTags lets Varde ask the registries which version tag points
	// to a running image (off by default: a new outbound connection).
	RegistryTags bool
	// ContainerPackages lets Varde read the package databases of images
	// from their containers (on by default: no new connection, the Docker
	// access already allows it).
	ContainerPackages bool
	// EOLData lets Varde read release lines from endoflife.date (off by
	// default: a new outbound connection that reveals the products).
	EOLData bool
}

// ScanPeriods are the allowed periods of scheduled scans.
var ScanPeriods = map[string]time.Duration{"off": 0, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "168h": 7 * 24 * time.Hour}

// Key names. Each maps to the environment variable VARDE_<KEY>; thresholds
// have no environment variable and are UI-only.
const (
	KeyPublicDomains    = "PUBLIC_DOMAINS"
	KeyInternalDomains  = "INTERNAL_DOMAINS"
	KeyDigestHour       = "DIGEST_HOUR"
	KeyDigestWeekday    = "DIGEST_WEEKDAY"
	KeyDirectOSV        = "DIRECT_OSV"
	KeyDirectNVD        = "DIRECT_NVD"
	KeyDirectQueries    = "DIRECT_QUERIES"
	KeyP1CVSSPublic     = "P1_CVSS_PUBLIC"
	KeyP1CVSSPublicEPSS = "P1_CVSS_PUBLIC_EPSS"
	KeyP1EPSS           = "P1_EPSS"
	KeyP2CVSS           = "P2_CVSS"
	KeyP2CVSSExposed    = "P2_CVSS_EXPOSED"
	// KeyNetworks is UI-only: the user grants network access in the UI.
	KeyNetworks = "DISCOVERY_NETWORKS"
	// KeyScanEvery is the period of scheduled network scans (off, 6h,
	// 24h, 168h); UI-only, off by default.
	KeyScanEvery = "DISCOVERY_SCAN_EVERY"
	// KeyRegistryTags switches registry tag resolution on; UI-only.
	KeyRegistryTags = "REGISTRY_TAGS"
	// KeyContainerPackages switches reading container package databases;
	// UI-only, on by default.
	KeyContainerPackages = "CONTAINER_PACKAGES"
	// KeyEOLData switches reading release lines from endoflife.date;
	// UI-only, off by default.
	KeyEOLData = "EOL_DATA"
)

// Keys lists every UI-editable key.
var Keys = []string{
	KeyPublicDomains, KeyInternalDomains, KeyDigestHour, KeyDigestWeekday, KeyDirectOSV, KeyDirectNVD,
	KeyP1CVSSPublic, KeyP1CVSSPublicEPSS, KeyP1EPSS, KeyP2CVSS, KeyP2CVSSExposed, KeyNetworks, KeyScanEvery, KeyRegistryTags,
	KeyContainerPackages, KeyEOLData, KeyDirectQueries,
}

// Service provides the effective settings.
type Service struct {
	store Store
	cfg   config.Config

	mu  sync.RWMutex
	eff Effective
	ui  map[string]string
}

// New loads the saved values and computes the effective settings.
func New(ctx context.Context, st Store, cfg config.Config) (*Service, error) {
	s := &Service{store: st, cfg: cfg}
	ui, err := st.Settings(ctx)
	if err != nil {
		return nil, err
	}
	eff, err := s.merge(ui)
	if err != nil {
		// A bad stored value must not stop the server: fall back to
		// environment and defaults, and let the user fix it in the UI.
		eff, _ = s.merge(map[string]string{})
	}
	s.ui, s.eff = ui, eff
	return s, nil
}

// Get returns the effective settings.
func (s *Service) Get() Effective {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.eff
}

// Locked reports whether key is fixed by the environment.
func (s *Service) Locked(key string) bool { return s.cfg.FromEnv(key) }

// UIValue returns the stored UI value of key (may be empty).
func (s *Service) UIValue(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ui[key]
}

// Exposure returns a detector for the current domains.
func (s *Service) Exposure() *exposure.Detector {
	e := s.Get()
	return exposure.New(exposure.Config{PublicDomains: e.PublicDomains, InternalDomains: e.InternalDomains})
}

// ErrLocked is returned when updating a key set by the environment.
var ErrLocked = errors.New("setting is locked by an environment variable")

// Update validates and stores values (empty string resets to default).
func (s *Service) Update(ctx context.Context, values map[string]string, by string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]string, len(s.ui))
	for k, v := range s.ui {
		next[k] = v
	}
	for k, v := range values {
		if !known(k) {
			return fmt.Errorf("unknown setting %q", k)
		}
		if s.cfg.FromEnv(k) && v != s.ui[k] {
			return fmt.Errorf("%s: %w", k, ErrLocked)
		}
		next[k] = strings.TrimSpace(v)
	}
	eff, err := s.merge(next)
	if err != nil {
		return err
	}
	if err := s.store.PutSettings(ctx, values, by, now); err != nil {
		return err
	}
	s.ui, s.eff = next, eff
	return nil
}

func known(k string) bool {
	for _, x := range Keys {
		if x == k {
			return true
		}
	}
	return false
}

// merge computes effective settings: env (already in cfg) wins, else UI,
// else defaults.
func (s *Service) merge(ui map[string]string) (Effective, error) {
	c := s.cfg
	eff := Effective{
		PublicDomains:     c.PublicDomains,
		InternalDomains:   c.InternalDomains,
		Policy:            policy.Defaults(),
		DigestHour:        c.Notify.DigestHour,
		DigestWeekday:     c.Notify.DigestWeekday,
		DirectOSV:         c.DirectOSV,
		DirectNVD:         c.DirectNVD,
		DirectQueries:     c.DirectQueries,
		ContainerPackages: true,
	}
	var errs []error
	use := func(key string) (string, bool) {
		v := ui[key]
		return v, v != "" && !c.FromEnv(key)
	}
	if v, ok := use(KeyPublicDomains); ok {
		d, err := domains(v)
		errs = append(errs, err)
		eff.PublicDomains = d
	}
	if v, ok := use(KeyInternalDomains); ok {
		d, err := domains(v)
		errs = append(errs, err)
		eff.InternalDomains = d
	}
	if v, ok := use(KeyDigestHour); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 23 {
			errs = append(errs, fmt.Errorf("digest hour must be 0-23"))
		} else {
			eff.DigestHour = n
		}
	}
	if v, ok := use(KeyDigestWeekday); ok {
		found := false
		for d := time.Sunday; d <= time.Saturday; d++ {
			if strings.EqualFold(v, d.String()) {
				eff.DigestWeekday, found = d, true
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("digest weekday %q unknown", v))
		}
	}
	for key, dst := range map[string]*bool{KeyDirectOSV: &eff.DirectOSV, KeyDirectNVD: &eff.DirectNVD, KeyDirectQueries: &eff.DirectQueries} {
		if v, ok := use(key); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s must be true or false", strings.ToLower(key)))
				continue
			}
			*dst = b
		}
	}
	for key, dst := range map[string]*float64{
		KeyP1CVSSPublic: &eff.Policy.P1CVSSPublic, KeyP1CVSSPublicEPSS: &eff.Policy.P1CVSSPublicEPSS,
		KeyP2CVSS: &eff.Policy.P2CVSS, KeyP2CVSSExposed: &eff.Policy.P2CVSSExposed,
	} {
		if v, ok := use(key); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < 0 || f > 10 {
				errs = append(errs, fmt.Errorf("%s must be a CVSS score between 0 and 10", strings.ToLower(key)))
				continue
			}
			*dst = f
		}
	}
	if v, ok := use(KeyNetworks); ok {
		sc, err := discovery.ParseScope(v)
		errs = append(errs, err)
		eff.Networks = sc
	}
	if v, ok := use(KeyRegistryTags); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("registry_tags must be true or false"))
		}
		eff.RegistryTags = b
	}
	if v, ok := use(KeyEOLData); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("eol_data must be true or false"))
		}
		eff.EOLData = b
	}
	if v, ok := use(KeyContainerPackages); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("container_packages must be true or false"))
		}
		eff.ContainerPackages = b
	}
	if v, ok := use(KeyScanEvery); ok {
		d, known := ScanPeriods[v]
		if !known {
			errs = append(errs, errors.New("discovery_scan_every must be off, 6h, 24h or 168h"))
		}
		eff.ScanEvery = d
	}
	if v, ok := use(KeyP1EPSS); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 || f > 1 {
			errs = append(errs, errors.New("p1_epss must be between 0 and 1"))
		} else {
			eff.Policy.P1EPSS = f
		}
	}
	return eff, errors.Join(errs...)
}

func domains(v string) ([]string, error) {
	var out []string
	for _, d := range strings.Split(v, ",") {
		d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, "/:@ *") || len(d) > 253 {
			return nil, fmt.Errorf("%q is not a domain suffix", d)
		}
		out = append(out, d)
	}
	return out, nil
}
