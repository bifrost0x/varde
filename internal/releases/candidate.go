// SPDX-License-Identifier: Apache-2.0

package releases

import (
	"context"
	"fmt"

	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/imagelayers"
	"github.com/bifrost0x/varde/internal/registry"
	"github.com/bifrost0x/varde/internal/remedy"
)

// ReadImage reads the package list of one image in the registry for one
// platform, the way a release is read: manifests, config and layers come
// from the registry and are squashed in memory; nothing is pulled into a
// Docker daemon. ref is a tag or a digest. An installation uses it to judge
// a newer image of a running container before suggesting it (ADR 0045);
// the layer reads it caches are shared with the release reads. maxBytes
// bounds the layer bytes fetched; a larger image is remedy.ErrImageTooLarge.
func (r *Reader) ReadImage(ctx context.Context, image, ref string, platform registry.Platform, maxBytes int64) (remedy.Candidate, error) {
	if platform.Arch == "" {
		return remedy.Candidate{}, remedy.ErrNoPlatform
	}
	rctx, cancel := r.imageContext(ctx)
	defer cancel()
	ms, _, err := r.Registry.Image(rctx, r.remote(image), ref, []registry.Platform{platform})
	if err != nil {
		return remedy.Candidate{}, fmt.Errorf("manifests of %s: %w", image, err)
	}
	if len(ms) == 0 {
		return remedy.Candidate{}, remedy.ErrNoPlatform
	}
	m := ms[0]
	cfg, err := r.config(ctx, rctx, image, m.ConfigDigest)
	if err != nil {
		return remedy.Candidate{}, fmt.Errorf("config of %s: %w", image, err)
	}
	cache := &layerCache{store: r.Store, now: r.Now, log: r.log(), recs: map[string]*imagelayers.LayerRecord{}}
	need, err := cache.missing(ctx, m.Layers, cfg, r.Limits)
	if err != nil {
		return remedy.Candidate{}, fmt.Errorf("layers of %s: %w", image, err)
	}
	if maxBytes > 0 && need > maxBytes {
		return remedy.Candidate{}, fmt.Errorf("%w (%d MB)", remedy.ErrImageTooLarge, need>>20)
	}
	pr := platformRead{m: m, cfg: cfg, cache: cache}
	l, err := r.readPlatform(ctx, rctx, job{app: &catalog.App{}, image: image}, pr)
	if err != nil {
		if cache.err != nil {
			return remedy.Candidate{}, fmt.Errorf("layer cache: %w", cache.err)
		}
		return remedy.Candidate{}, fmt.Errorf("layers of %s: %w", image, err)
	}
	return remedy.Candidate{Distro: l.Distro, Packages: l.Packages, Partial: l.Partial}, nil
}
