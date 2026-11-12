// SPDX-License-Identifier: Apache-2.0

// Package docker reads containers, images and events from the Docker Engine
// API. It is deliberately read-only: the transport refuses any method other
// than GET and HEAD (ADR 0006, ADR 0016).
package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
)

// API versions this client understands. Responses are decoded leniently, so
// newer daemons work as long as they still serve minAPIVersion.
const (
	minAPIVersion = "1.41"
	maxAPIVersion = "1.51"
)

const (
	requestTimeout   = 30 * time.Second
	maxListBytes     = 32 << 20
	maxInspectBytes  = 8 << 20
	maxEventLineSize = 1 << 20
)

// ErrMethodNotAllowed is returned when code attempts a non-read request.
var ErrMethodNotAllowed = errors.New("docker: only GET and HEAD requests are permitted")

// Client is a minimal, read-only Docker Engine API client.
type Client struct {
	base *url.URL
	http *http.Client

	mu      sync.Mutex
	version string // negotiated API version, e.g. "1.47"
}

// New creates a client for host, which is tcp://, http://, https:// or
// unix://. Validation of whether unix sockets are allowed happens in config.
func New(host string) (*Client, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("parse docker host: %w", err)
	}
	transport := &http.Transport{
		Proxy:                 nil, // the Engine API is local; never route it via HTTP(S)_PROXY
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	base := &url.URL{Scheme: "http"}
	switch u.Scheme {
	case "tcp", "http":
		base.Host = u.Host
	case "https":
		base.Scheme = "https"
		base.Host = u.Host
	case "unix":
		path := u.Path
		base.Host = "docker"
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
	default:
		return nil, fmt.Errorf("unsupported docker host scheme %q", u.Scheme)
	}
	return &Client{
		base: base,
		http: &http.Client{
			Transport: readOnlyTransport{next: transport},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// NewDialer creates a client whose connections come from dial, for example
// an SSH session running "docker system dial-stdio" on a remote host. The
// read-only contract applies as for New.
func NewDialer(dial func(ctx context.Context) (net.Conn, error)) *Client {
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          2,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx)
		},
	}
	return &Client{
		base: &url.URL{Scheme: "http", Host: "docker"},
		http: &http.Client{
			Transport: readOnlyTransport{next: transport},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// readOnlyTransport enforces the read-only contract below every caller.
type readOnlyTransport struct{ next http.RoundTripper }

func (t readOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil, ErrMethodNotAllowed
	}
	return t.next.RoundTrip(r)
}

// Version is the response of GET /version.
type Version struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	OS            string `json:"Os"`
	Arch          string `json:"Arch"`
}

// Negotiate queries the daemon version and selects the API version to use.
func (c *Client) Negotiate(ctx context.Context) (Version, error) {
	var v Version
	if err := c.get(ctx, "/version", nil, maxInspectBytes, &v); err != nil {
		return Version{}, err
	}
	use := maxAPIVersion
	if v.APIVersion != "" && compareVersion(v.APIVersion, use) < 0 {
		use = v.APIVersion
	}
	if compareVersion(use, minAPIVersion) < 0 {
		return Version{}, fmt.Errorf("docker API %s is older than the minimum supported %s", v.APIVersion, minAPIVersion)
	}
	if v.MinAPIVersion != "" && compareVersion(use, v.MinAPIVersion) < 0 {
		return Version{}, fmt.Errorf("docker daemon requires API >= %s; this client supports up to %s", v.MinAPIVersion, maxAPIVersion)
	}
	c.mu.Lock()
	c.version = use
	c.mu.Unlock()
	return v, nil
}

// Info is the subset of GET /info that Varde uses.
type Info struct {
	Name            string `json:"Name"`
	OperatingSystem string `json:"OperatingSystem"`
	OSType          string `json:"OSType"`
	Architecture    string `json:"Architecture"`
}

// Info returns daemon information.
func (c *Client) Info(ctx context.Context) (Info, error) {
	var i Info
	err := c.getVersioned(ctx, "/info", nil, maxInspectBytes, &i)
	return i, err
}

// ContainerSummary is one entry of GET /containers/json.
type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort uint16 `json:"PrivatePort"`
		PublicPort  uint16 `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

// Containers lists all containers, including stopped ones.
func (c *Client) Containers(ctx context.Context) ([]ContainerSummary, error) {
	var out []ContainerSummary
	q := url.Values{"all": {"1"}}
	err := c.getVersioned(ctx, "/containers/json", q, maxListBytes, &out)
	return out, err
}

// ContainerInspect is the subset of GET /containers/{id}/json that Varde uses.
type ContainerInspect struct {
	ID     string `json:"Id"`
	Config struct {
		Image string `json:"Image"`
		User  string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		CapAdd      []string `json:"CapAdd"`
		NetworkMode string   `json:"NetworkMode"`
		PidMode     string   `json:"PidMode"`
		Devices     []struct {
			PathOnHost string `json:"PathOnHost"`
		} `json:"Devices"`
	} `json:"HostConfig"`
}

// InspectContainer returns details of one container.
func (c *Client) InspectContainer(ctx context.Context, id string) (ContainerInspect, error) {
	var out ContainerInspect
	if !validID(id) {
		return out, fmt.Errorf("invalid container id %q", id)
	}
	err := c.getVersioned(ctx, "/containers/"+id+"/json", nil, maxInspectBytes, &out)
	return out, err
}

// ImageInspect is the subset of GET /images/{id}/json that Varde uses.
type ImageInspect struct {
	ID          string      `json:"Id"`
	RepoTags    []string    `json:"RepoTags"`
	RepoDigests []string    `json:"RepoDigests"`
	Config      ImageConfig `json:"Config"`
}

// ImageConfig is the part of an image's configuration Varde reads: the
// labels, and where the app is (working directory, the program it runs).
type ImageConfig struct {
	Labels     map[string]string `json:"Labels"`
	WorkingDir string            `json:"WorkingDir"`
	Entrypoint []string          `json:"Entrypoint"`
	Cmd        []string          `json:"Cmd"`
}

// InspectImage returns details of one local image.
func (c *Client) InspectImage(ctx context.Context, id string) (ImageInspect, error) {
	var out ImageInspect
	if !validID(id) {
		return out, fmt.Errorf("invalid image id %q", id)
	}
	err := c.getVersioned(ctx, "/images/"+id+"/json", nil, maxInspectBytes, &out)
	return out, err
}

// Message is one entry of the GET /events stream.
type Message struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID string `json:"ID"`
	} `json:"Actor"`
}

// Events streams container and image events until ctx is cancelled or the
// connection fails. handle is called for every message.
func (c *Client) Events(ctx context.Context, handle func(Message)) error {
	filters, err := json.Marshal(map[string][]string{"type": {"container", "image"}})
	if err != nil {
		return fmt.Errorf("encode event filters: %w", err)
	}
	req, err := c.request(ctx, c.versionedPath("/events"), url.Values{"filters": {string(filters)}})
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker events: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return statusError("/events", resp)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), maxEventLineSize)
	for sc.Scan() {
		var m Message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			return fmt.Errorf("decode docker event: %w", err)
		}
		handle(m)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read docker events: %w", err)
	}
	return io.ErrUnexpectedEOF
}

func (c *Client) versionedPath(path string) string {
	c.mu.Lock()
	v := c.version
	c.mu.Unlock()
	if v == "" {
		v = minAPIVersion
	}
	return "/v" + v + path
}

func (c *Client) getVersioned(ctx context.Context, path string, q url.Values, limit int64, out any) error {
	return c.get(ctx, c.versionedPath(path), q, limit, out)
}

func (c *Client) get(ctx context.Context, path string, q url.Values, limit int64, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := c.request(ctx, path, q)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return statusError(path, resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("docker GET %s: read body: %w", path, err)
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("docker GET %s: response exceeds %d bytes", path, limit)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("docker GET %s: decode: %w", path, err)
	}
	return nil
}

func (c *Client) request(ctx context.Context, path string, q url.Values) (*http.Request, error) {
	u := *c.base
	u.Path = path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build docker request: %w", err)
	}
	req.Header.Set("User-Agent", buildinfo.UserAgent())
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// StatusError is a non-200 response from the Engine API or the proxy.
type StatusError struct {
	Path   string
	Status int
}

func (e *StatusError) Error() string {
	hint := ""
	if e.Status == http.StatusForbidden {
		hint = " (blocked by the socket proxy; check its permissions)"
	}
	return fmt.Sprintf("docker GET %s: status %d%s", e.Path, e.Status, hint)
}

func statusError(path string, resp *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return &StatusError{Path: path, Status: resp.StatusCode}
}

// validID accepts Docker object IDs (hex, optionally "sha256:"-prefixed) so
// that no caller can smuggle path segments into a request.
func validID(id string) bool {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) < 12 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// compareVersion compares dotted numeric API versions ("1.41" < "1.47").
func compareVersion(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
