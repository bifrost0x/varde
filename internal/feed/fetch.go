// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bifrost0x/varde/internal/httpx"
)

// ErrNotFound reports a missing file on a mirror.
var ErrNotFound = errors.New("not found")

// Fetcher reads feed files from one location. Integrity comes from the
// signatures, so fetchers and mirrors are not trusted.
type Fetcher interface {
	// Get returns the file at path (e.g. "v1/manifest.json"), reading at
	// most limit bytes. With a non-empty etag the request is conditional and
	// notModified reports an unchanged file.
	Get(ctx context.Context, path, etag string, limit int64) (data []byte, newETag string, notModified bool, err error)
	String() string
}

var feedPath = regexp.MustCompile(`^v1/(root\.json|root/[0-9]{1,9}\.json|manifest\.json|manifest\.json\.sig|blobs/sha256/[0-9a-f]{64})$`)

// NewFetcher returns a fetcher for an https:// mirror or for a local
// directory or tarball given as file:// URL (air-gapped import).
// authorization, when it returns a value, is sent as the Authorization
// header of every request to an https:// mirror (the uplink license); it is
// asked per request, so nothing is sent while the uplink is off. Local
// fetchers ignore it.
func NewFetcher(raw string, hc *httpx.Client, authorization func() string) (Fetcher, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("feed URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("feed URL %q: must be https://host[/path]", raw)
		}
		return &httpFetcher{base: strings.TrimRight(u.String(), "/"), hc: hc, authorization: authorization}, nil
	case "file":
		if u.Host != "" || !path.IsAbs(u.Path) {
			return nil, fmt.Errorf("feed URL %q: use file:///absolute/path", raw)
		}
		p := filepath.FromSlash(u.Path)
		if strings.HasSuffix(p, ".tar") {
			return &tarFetcher{file: p}, nil
		}
		return &dirFetcher{root: p}, nil
	default:
		return nil, fmt.Errorf("feed URL %q: scheme must be https or file", raw)
	}
}

func checkPath(p string) error {
	if !feedPath.MatchString(p) {
		return fmt.Errorf("invalid feed path %q", p)
	}
	return nil
}

type httpFetcher struct {
	base          string
	hc            *httpx.Client
	authorization func() string
}

func (f *httpFetcher) String() string { return f.base }

func (f *httpFetcher) Get(ctx context.Context, p, etag string, limit int64) ([]byte, string, bool, error) {
	if err := checkPath(p); err != nil {
		return nil, "", false, err
	}
	req := httpx.Request{URL: f.base + "/" + p, ETag: etag, MaxBytes: limit}
	if f.authorization != nil {
		if v := f.authorization(); v != "" {
			req.Header = http.Header{"Authorization": []string{v}}
		}
	}
	resp, err := f.hc.Do(ctx, req)
	var se *httpx.StatusError
	if errors.As(err, &se) && se.Status == http.StatusNotFound {
		return nil, "", false, fmt.Errorf("%s: %w", p, ErrNotFound)
	}
	if err != nil {
		return nil, "", false, err
	}
	if resp.NotModified {
		return nil, etag, true, nil
	}
	return resp.Body, resp.ETag, false, nil
}

type dirFetcher struct{ root string }

func (f *dirFetcher) String() string { return "file://" + filepath.ToSlash(f.root) }

func (f *dirFetcher) Get(_ context.Context, p, _ string, limit int64) ([]byte, string, bool, error) {
	if err := checkPath(p); err != nil {
		return nil, "", false, err
	}
	fh, err := os.Open(filepath.Join(f.root, filepath.FromSlash(p)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", false, fmt.Errorf("%s: %w", p, ErrNotFound)
	}
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = fh.Close() }()
	data, err := readLimited(fh, limit)
	return data, "", false, err
}

type tarFetcher struct{ file string }

func (f *tarFetcher) String() string { return "file://" + filepath.ToSlash(f.file) }

// Get scans the tarball for p. Tarballs are small and read rarely, so a
// scan per file keeps the code simple and the memory bounded.
func (f *tarFetcher) Get(_ context.Context, p, _ string, limit int64) ([]byte, string, bool, error) {
	if err := checkPath(p); err != nil {
		return nil, "", false, err
	}
	fh, err := os.Open(f.file)
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = fh.Close() }()
	tr := tar.NewReader(fh)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, "", false, fmt.Errorf("%s: %w", p, ErrNotFound)
		}
		if err != nil {
			return nil, "", false, fmt.Errorf("read %s: %w", f.file, err)
		}
		if h.Typeflag == tar.TypeReg && strings.TrimPrefix(h.Name, "./") == p {
			data, err := readLimited(tr, limit)
			return data, "", false, err
		}
	}
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file larger than %d bytes", limit)
	}
	return data, nil
}
