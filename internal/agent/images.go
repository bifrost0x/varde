// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"maps"
	"sync"

	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/inventory"
)

// imageStore keeps what the agent read from its containers' images: when
// each image was read, and the records not delivered to the server yet. It
// is the agent's side of the image package reader (ADR 0033).
type imageStore struct {
	mu      sync.Mutex
	read    map[string]inventory.ImagePackages
	pending []inventory.ImagePackages
}

func newImageStore() *imageStore {
	return &imageStore{read: map[string]inventory.ImagePackages{}}
}

// ImagePackagesRead implements docker.PackageStore: the read times, so an
// image is read again only when due.
func (s *imageStore) ImagePackagesRead(context.Context) (map[string]inventory.ImagePackages, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.read), nil
}

// RecordImagePackages implements docker.PackageStore: the read is queued
// for the next report.
func (s *imageStore) RecordImagePackages(_ context.Context, p inventory.ImagePackages) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.read[p.ImageID] = inventory.ImagePackages{ImageID: p.ImageID, Read: p.Read, Error: p.Error, Format: p.Format}
	if p.Error != "" {
		return nil
	}
	for i, q := range s.pending {
		if q.ImageID == p.ImageID {
			s.pending[i] = p
			return nil
		}
	}
	s.pending = append(s.pending, p)
	return nil
}

// take returns up to wire.MaxImages pending records.
func (s *imageStore) take() []inventory.ImagePackages {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(len(s.pending), wire.MaxImages)
	return append([]inventory.ImagePackages(nil), s.pending[:n]...)
}

// delivered drops the records the server accepted.
func (s *imageStore) delivered(sent []inventory.ImagePackages) {
	s.mu.Lock()
	defer s.mu.Unlock()
	done := map[string]bool{}
	for _, p := range sent {
		done[p.ImageID] = true
	}
	kept := s.pending[:0]
	for _, p := range s.pending {
		if !done[p.ImageID] {
			kept = append(kept, p)
		}
	}
	s.pending = kept
}
