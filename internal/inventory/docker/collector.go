// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/inventory"
)

const (
	labelComposeProject = "com.docker.compose.project"
	labelComposeService = "com.docker.compose.service"
)

// Events that can change what Varde reports. Everything else (exec, health
// checks, attach) is noise.
var relevantActions = map[string]map[string]bool{
	"container": {"create": true, "start": true, "die": true, "destroy": true, "rename": true, "update": true, "pause": true, "unpause": true},
	"image":     {"pull": true, "tag": true, "untag": true, "delete": true, "load": true, "import": true},
}

// Collector reports the containers of one Docker host.
type Collector struct {
	client *Client
	log    *slog.Logger

	mu         sync.Mutex
	imageCache map[string]ImageInspect
	// runtimes keeps the inspected settings per container: they do not
	// change after the container was created.
	runtimes map[string]*inventory.Runtime
	// changes is the last change check per container ID.
	changes map[string]changeState

	// Packages, when set, reads the package databases of new images.
	Packages *PackageReader

	// backoff bounds for the event stream; variables for tests.
	minBackoff, maxBackoff time.Duration
}

var _ inventory.Collector = (*Collector)(nil)

// NewCollector returns a collector using client.
func NewCollector(client *Client, log *slog.Logger) *Collector {
	return &Collector{
		client:     client,
		log:        log,
		imageCache: map[string]ImageInspect{},
		runtimes:   map[string]*inventory.Runtime{},
		minBackoff: time.Second,
		maxBackoff: time.Minute,
	}
}

// Kind implements inventory.Collector.
func (*Collector) Kind() inventory.Kind { return inventory.KindContainer }

// List implements inventory.Collector.
func (c *Collector) List(ctx context.Context) (inventory.Snapshot, error) {
	if _, err := c.client.Negotiate(ctx); err != nil {
		return inventory.Snapshot{}, err
	}
	info, err := c.client.Info(ctx)
	if err != nil {
		return inventory.Snapshot{}, err
	}
	summaries, err := c.client.Containers(ctx)
	if err != nil {
		return inventory.Snapshot{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	cache := make(map[string]ImageInspect, len(c.imageCache))

	workloads := make([]inventory.Workload, 0, len(summaries))
	refs := map[string]string{}
	for _, s := range summaries {
		w, err := c.workload(ctx, s, cache)
		if err != nil {
			return inventory.Snapshot{}, err
		}
		c.pulledImage(ctx, &w, refs)
		workloads = append(workloads, w)
	}
	// Only images still in use stay cached, which bounds the cache.
	c.imageCache = cache
	live := map[string]bool{}
	for _, s := range summaries {
		live[s.ID] = true
	}
	for id := range c.runtimes {
		if !live[id] {
			delete(c.runtimes, id)
		}
	}

	sort.Slice(workloads, func(i, j int) bool { return workloads[i].Name < workloads[j].Name })
	config := func(id string) ImageConfig { return cache[id].Config }
	c.changedFiles(ctx, workloads, config)
	c.Packages.Read(ctx, c.client, summaries, config)
	return inventory.Snapshot{
		Host: inventory.HostInfo{
			Name: info.Name,
			OS:   strings.TrimSpace(info.OperatingSystem),
			Arch: info.Architecture,
		},
		Workloads: workloads,
	}, nil
}

func (c *Collector) workload(ctx context.Context, s ContainerSummary, cache map[string]ImageInspect) (inventory.Workload, error) {
	ref := s.Image
	// The runtime settings come from the container's configuration, read
	// once per container. When the tag a container was created from has
	// moved, the list shows the image ID instead; the original reference
	// survives in the configuration too.
	rt, known := c.runtimes[s.ID]
	if !known || ref == "" || strings.HasPrefix(ref, "sha256:") || validID(ref) {
		ci, err := c.client.InspectContainer(ctx, s.ID)
		switch {
		case err != nil && isNotFound(err):
			// Removed between list and inspect: the next sync drops it.
		case err != nil:
			return inventory.Workload{}, err
		default:
			rt = runtimeOf(ci)
			c.runtimes[s.ID] = rt
			if ref == "" || strings.HasPrefix(ref, "sha256:") || validID(ref) {
				ref = ci.Config.Image
			}
		}
	}

	img, ok := cache[s.ImageID]
	if !ok {
		if img, ok = c.imageCache[s.ImageID]; !ok {
			var err error
			img, err = c.client.InspectImage(ctx, s.ImageID)
			if err != nil {
				if !isNotFound(err) {
					return inventory.Workload{}, err
				}
				// The image can be removed while a container still uses it.
				img = ImageInspect{ID: s.ImageID}
			}
		}
		cache[s.ImageID] = img
	}

	ports := make([]inventory.Port, 0, len(s.Ports))
	for _, p := range s.Ports {
		ports = append(ports, inventory.Port{IP: p.IP, PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Protocol: p.Type})
	}
	sort.Slice(ports, func(i, j int) bool {
		a, b := ports[i], ports[j]
		if a.PrivatePort != b.PrivatePort {
			return a.PrivatePort < b.PrivatePort
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.IP < b.IP
	})

	networks := make([]inventory.Network, 0, len(s.NetworkSettings.Networks))
	for name, n := range s.NetworkSettings.Networks {
		networks = append(networks, inventory.Network{Name: name, IPAddress: n.IPAddress})
	}
	sort.Slice(networks, func(i, j int) bool { return networks[i].Name < networks[j].Name })

	var mounts []inventory.Mount
	for _, m := range s.Mounts {
		mounts = append(mounts, inventory.Mount{Type: m.Type, Name: m.Name, Source: m.Source, Destination: m.Destination, ReadWrite: m.RW})
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Destination < mounts[j].Destination })

	name := s.ID
	if len(s.Names) > 0 {
		name = strings.TrimPrefix(s.Names[0], "/")
	}

	return inventory.Workload{
		Kind:      inventory.KindContainer,
		RuntimeID: s.ID,
		Name:      name,
		State:     s.State,
		Container: &inventory.Container{
			ImageRef:       ref,
			ImageID:        s.ImageID,
			RepoDigests:    img.RepoDigests,
			ImageLabels:    img.Config.Labels,
			Labels:         s.Labels,
			Ports:          ports,
			Networks:       networks,
			Mounts:         mounts,
			Runtime:        rt,
			ComposeProject: s.Labels[labelComposeProject],
			ComposeService: s.Labels[labelComposeService],
		},
	}, nil
}

// Watch implements inventory.Collector. It reconnects with exponential
// backoff and emits a signal after every reconnect, because events may have
// been missed while disconnected.
func (c *Collector) Watch(ctx context.Context) <-chan inventory.Event {
	ch := make(chan inventory.Event, 1)
	go func() {
		defer close(ch)
		backoff := c.minBackoff
		first := true
		for {
			if !first {
				signal(ch, "events reconnected")
			}
			first = false
			started := time.Now()
			// Negotiate per connection so the stream uses the same API
			// version as List, also after a daemon upgrade.
			_, err := c.client.Negotiate(ctx)
			if err == nil {
				err = c.client.Events(ctx, func(m Message) {
					if relevantActions[m.Type][m.Action] {
						signal(ch, m.Type+" "+m.Action)
					}
				})
			}
			if ctx.Err() != nil {
				return
			}
			if time.Since(started) > c.maxBackoff {
				backoff = c.minBackoff
			}
			c.log.Warn("docker event stream interrupted", "err", err, "retry_in", backoff)
			if !sleep(ctx, jitter(backoff)) {
				return
			}
			backoff = min(backoff*2, c.maxBackoff)
		}
	}()
	return ch
}

// signal performs a coalescing, non-blocking send.
func signal(ch chan<- inventory.Event, reason string) {
	select {
	case ch <- inventory.Event{Reason: reason}:
	default:
	}
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	// ±20 %
	delta := time.Duration(rand.Int64N(int64(d)/5*2+1)) - d/5 //nolint:gosec // jitter, not security relevant
	return d + delta
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func isNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == http.StatusNotFound
}

// runtimeOf keeps the settings of a container that decide what it can do on
// its host, bounded.
func runtimeOf(ci ContainerInspect) *inventory.Runtime {
	rt := &inventory.Runtime{Privileged: ci.HostConfig.Privileged, NetworkMode: ci.HostConfig.NetworkMode,
		PidMode: ci.HostConfig.PidMode, User: ci.Config.User, Devices: len(ci.HostConfig.Devices)}
	for _, c := range ci.HostConfig.CapAdd {
		if len(rt.CapAdd) < 40 && len(c) <= 40 {
			rt.CapAdd = append(rt.CapAdd, strings.ToUpper(strings.TrimPrefix(c, "CAP_")))
		}
	}
	if len(rt.User) > 64 {
		rt.User = rt.User[:64]
	}
	if len(rt.NetworkMode) > 128 {
		rt.NetworkMode = rt.NetworkMode[:128]
	}
	return rt
}
