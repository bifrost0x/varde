// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/bifrost0x/varde/internal/inventory"
)

// maxImagePackages bounds the packages kept per image; a large Debian
// image has one or two thousand. The reader puts the app's manifests first,
// so a cut never drops them.
const maxImagePackages = 20000

// ImagePackagesRead returns when Varde itself last read each image and
// whether the read failed, keyed by image ID, without the packages. Agents'
// reads do not count: Varde reads an image it can reach itself.
func (s *Store) ImagePackagesRead(ctx context.Context) (map[string]inventory.ImagePackages, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT image_id, read_at, error, format FROM image_package_reads WHERE source = ''`)
	if err != nil {
		return nil, fmt.Errorf("query image packages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]inventory.ImagePackages{}
	for rows.Next() {
		var p inventory.ImagePackages
		var read int64
		if err := rows.Scan(&p.ImageID, &read, &p.Error, &p.Format); err != nil {
			return nil, fmt.Errorf("scan image packages: %w", err)
		}
		p.Read = fromMillis(read)
		out[p.ImageID] = p
	}
	return out, rows.Err()
}

// ImageRef names the image of a container on a host.
type ImageRef struct{ ImageID, HostID string }

// ImagePackagesFor returns the record each container is checked against:
// Varde's own successful read of the image, else the one of the agent on
// the container's own host. Another agent's record is never used.
func (s *Store) ImagePackagesFor(ctx context.Context, refs []ImageRef) (map[ImageRef]inventory.ImagePackages, error) {
	ids := make([]string, 0, len(refs))
	seen := map[string]bool{}
	for _, r := range refs {
		if !seen[r.ImageID] {
			seen[r.ImageID] = true
			ids = append(ids, r.ImageID)
		}
	}
	all, err := s.imageReads(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := map[ImageRef]inventory.ImagePackages{}
	for _, r := range refs {
		bySource := all[r.ImageID]
		own, haveOwn := bySource[""]
		agent, haveAgent := bySource["agent:"+r.HostID]
		switch {
		case haveOwn && usable(own):
			out[r] = own
		case haveAgent && usable(agent):
			out[r] = agent
		case haveOwn:
			out[r] = own
		}
	}
	return out, nil
}

// usable reports whether a record has something to check: a successful
// read, or a failed one that kept an earlier read's packages.
func usable(p inventory.ImagePackages) bool { return p.Error == "" || len(p.Packages) > 0 }

// ImagePackages returns a successful record of each given image, Varde's
// own first. It serves the list of packages to ask osv.dev about, where any
// source is fine; checking a container uses ImagePackagesFor.
func (s *Store) ImagePackages(ctx context.Context, imageIDs []string) (map[string]inventory.ImagePackages, error) {
	all, err := s.imageReads(ctx, imageIDs)
	if err != nil {
		return nil, err
	}
	out := map[string]inventory.ImagePackages{}
	for id, bySource := range all {
		if p, ok := bySource[""]; ok && usable(p) {
			out[id] = p
			continue
		}
		srcs := make([]string, 0, len(bySource))
		for src := range bySource {
			srcs = append(srcs, src)
		}
		sort.Strings(srcs)
		for _, src := range srcs {
			if usable(bySource[src]) {
				out[id] = bySource[src]
				break
			}
		}
		if _, ok := out[id]; !ok {
			if p, ok := bySource[""]; ok {
				out[id] = p
			}
		}
	}
	return out, nil
}

// imageReads returns every record of the given images by source.
func (s *Store) imageReads(ctx context.Context, imageIDs []string) (map[string]map[string]inventory.ImagePackages, error) {
	out := map[string]map[string]inventory.ImagePackages{}
	if len(imageIDs) == 0 {
		return out, nil
	}
	ids, err := json.Marshal(imageIDs)
	if err != nil {
		return nil, fmt.Errorf("encode image IDs: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT image_id, source, distro, os, packages, read_at, error, partial FROM image_package_reads
		WHERE image_id IN (SELECT value FROM json_each(?))`, string(ids))
	if err != nil {
		return nil, fmt.Errorf("query image packages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p inventory.ImagePackages
		var source, raw string
		var read int64
		if err := rows.Scan(&p.ImageID, &source, &p.Distro, &p.OS, &raw, &read, &p.Error, &p.Partial); err != nil {
			return nil, fmt.Errorf("scan image packages: %w", err)
		}
		if err := json.Unmarshal([]byte(raw), &p.Packages); err != nil {
			return nil, fmt.Errorf("decode packages of %s: %w", p.ImageID, err)
		}
		p.Read = fromMillis(read)
		if out[p.ImageID] == nil {
			out[p.ImageID] = map[string]inventory.ImagePackages{}
		}
		out[p.ImageID][source] = p
	}
	return out, rows.Err()
}

// RecordImagePackages stores one of Varde's own reads. A failed read keeps
// the packages of an earlier successful one.
func (s *Store) RecordImagePackages(ctx context.Context, p inventory.ImagePackages) error {
	return s.recordImageRead(ctx, "", p)
}

func (s *Store) recordImageRead(ctx context.Context, source string, p inventory.ImagePackages) error {
	if p.Error != "" {
		// A failed read keeps the packages and the format of the earlier
		// successful one: they are what is still checked.
		_, err := s.db.ExecContext(ctx, `INSERT INTO image_package_reads (image_id, source, read_at, error, format) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (image_id, source) DO UPDATE SET read_at = excluded.read_at, error = excluded.error`,
			truncate(p.ImageID, 128), source, millis(p.Read), truncate(p.Error, 512), p.Format)
		if err != nil {
			return fmt.Errorf("record image packages: %w", err)
		}
		return nil
	}
	pkgs := p.Packages
	if len(pkgs) > maxImagePackages {
		pkgs = pkgs[:maxImagePackages]
	}
	if pkgs == nil {
		pkgs = []inventory.Package{}
	}
	raw, err := json.Marshal(pkgs)
	if err != nil {
		return fmt.Errorf("encode packages: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO image_package_reads (image_id, source, distro, os, packages, read_at, error, format, partial) VALUES (?, ?, ?, ?, ?, ?, '', ?, ?)
		ON CONFLICT (image_id, source) DO UPDATE SET distro = excluded.distro, os = excluded.os, packages = excluded.packages,
		read_at = excluded.read_at, error = '', format = excluded.format, partial = excluded.partial`,
		truncate(p.ImageID, 128), source, truncate(p.Distro, 64), truncate(p.OS, 128), string(raw), millis(p.Read), p.Format, p.Partial || len(p.Packages) > maxImagePackages)
	if err != nil {
		return fmt.Errorf("record image packages: %w", err)
	}
	return nil
}

// AgentImageIDs returns the image IDs of the active containers an agent
// reported: the only images it may report packages for (ADR 0033).
func (s *Store) AgentImageIDs(ctx context.Context, hostID string) (map[string]bool, error) {
	ws, err := s.Workloads(ctx, WorkloadFilter{HostID: hostID, Kind: inventory.KindContainer})
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, w := range ws {
		if w.Container != nil && w.Container.ImageID != "" && w.RemovedAt == nil {
			out[w.Container.ImageID] = true
		}
	}
	return out, nil
}

// RecordAgentImagePackages stores a successful read an agent reported, as
// that agent's own record: it is used only for the containers of the
// agent's host (ImagePackagesFor). It reports whether it was stored.
func (s *Store) RecordAgentImagePackages(ctx context.Context, hostID string, p inventory.ImagePackages) (bool, error) {
	p.Error = ""
	if err := s.recordImageRead(ctx, "agent:"+hostID, p); err != nil {
		return false, fmt.Errorf("record agent image packages: %w", err)
	}
	return true, nil
}
