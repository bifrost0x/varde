// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Sources as Report.Stopped names them.
const (
	sourceRegistry = "registry"
	sourceGitHub   = "github"
	sourceNVD      = "nvd"
	sourceHub      = "hub"
	// stopDeadline is recorded when the build's time ran out.
	stopDeadline = "deadline"
)

// limits remembers which sources refused because of their rate limit in
// this build; such a source is not asked again until the next build, so
// one refusal does not turn into hundreds.
type limits struct {
	stopped map[string]bool
	order   []string
}

func (l *limits) ask(source string) error {
	if l.stopped[source] {
		return fmt.Errorf("%s: %w; not asked again in this build", source, ErrRateLimited)
	}
	return nil
}

func (l *limits) note(source string, err error) error {
	if err != nil && rateLimited(err) {
		l.stop(source)
	}
	return err
}

func (l *limits) stop(source string) {
	if !l.stopped[source] {
		l.stopped[source] = true
		l.order = append(l.order, source)
	}
}

type limitedRegistry struct {
	inner RegistryAPI
	l     *limits
}

func (r limitedRegistry) AllTags(ctx context.Context, repository string) ([]string, bool, error) {
	if err := r.l.ask(sourceRegistry); err != nil {
		return nil, false, err
	}
	tags, complete, err := r.inner.AllTags(ctx, repository)
	return tags, complete, r.l.note(sourceRegistry, err)
}

func (r limitedRegistry) Digest(ctx context.Context, repository, tag string) (string, error) {
	if err := r.l.ask(sourceRegistry); err != nil {
		return "", err
	}
	d, err := r.inner.Digest(ctx, repository, tag)
	return d, r.l.note(sourceRegistry, err)
}

type limitedGitHub struct {
	inner GitHubAPI
	l     *limits
}

func (g limitedGitHub) Releases(ctx context.Context, repo, etag string) ([]Release, string, bool, error) {
	if err := g.l.ask(sourceGitHub); err != nil {
		return nil, "", false, err
	}
	rels, newETag, nm, err := g.inner.Releases(ctx, repo, etag)
	return rels, newETag, nm, g.l.note(sourceGitHub, err)
}

type limitedNVD struct {
	inner NVDAPI
	l     *limits
}

func (n limitedNVD) SearchProducts(ctx context.Context, keyword string) ([]CPEProduct, error) {
	if err := n.l.ask(sourceNVD); err != nil {
		return nil, err
	}
	ps, err := n.inner.SearchProducts(ctx, keyword)
	return ps, n.l.note(sourceNVD, err)
}

func (n limitedNVD) Products(ctx context.Context, cpe string) ([]CPEProduct, error) {
	if err := n.l.ask(sourceNVD); err != nil {
		return nil, err
	}
	ps, err := n.inner.Products(ctx, cpe)
	return ps, n.l.note(sourceNVD, err)
}

type limitedHub struct {
	inner HubAPI
	l     *limits
}

func (h limitedHub) PullCount(ctx context.Context, repository string) (int64, error) {
	if err := h.l.ask(sourceHub); err != nil {
		return 0, err
	}
	n, err := h.inner.PullCount(ctx, repository)
	return n, h.l.note(sourceHub, err)
}

// pacer keeps a pause between the requests of an HTTP client.
type pacer struct {
	mu   sync.Mutex
	last time.Time
}

func (p *pacer) wait(ctx context.Context, pause time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d := time.Until(p.last.Add(pause)); !p.last.IsZero() && d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	p.last = time.Now()
	return nil
}
