// SPDX-License-Identifier: Apache-2.0

package catgen

import (
	"context"
	"errors"
	"net/http"

	"github.com/bifrost0x/varde/internal/httpx"
)

// ErrNotFound marks an answer that the thing asked about does not exist. It
// is a verdict (the check fails), unlike any other error, which only means
// the candidate could not be checked this time.
var ErrNotFound = errors.New("catgen: not found")

// notFound reports ErrNotFound or a 404 from a server.
func notFound(err error) bool {
	var se *httpx.StatusError
	return errors.Is(err, ErrNotFound) || (errors.As(err, &se) && se.Status == http.StatusNotFound)
}

// RegistryAPI is what the generator asks a container registry;
// registry.Client implements it.
type RegistryAPI interface {
	Tags(ctx context.Context, repository string) ([]string, error)
	Digest(ctx context.Context, repository, tag string) (string, error)
}

// Release is one GitHub release of a repository.
type Release struct {
	Tag        string
	Prerelease bool
	Draft      bool
}

// GitHubAPI lists the releases of a repository ("owner/name"). With an etag
// the request is conditional: notModified reports an unchanged list, which
// then is not returned.
type GitHubAPI interface {
	Releases(ctx context.Context, repo, etag string) (rels []Release, newETag string, notModified bool, err error)
}

// CPEProduct is one entry of NVD's CPE dictionary.
type CPEProduct struct {
	// Name is the full CPE 2.3 name.
	Name       string
	Deprecated bool
	// Refs are the reference URLs NVD records for the product.
	Refs []string
}

// NVDAPI asks NVD's CPE dictionary.
type NVDAPI interface {
	// SearchProducts finds products by a keyword.
	SearchProducts(ctx context.Context, keyword string) ([]CPEProduct, error)
	// Products lists the products a CPE prefix ("cpe:2.3:a:vendor:product")
	// matches.
	Products(ctx context.Context, cpe string) ([]CPEProduct, error)
}

// HubAPI reads Docker Hub's repository metadata.
type HubAPI interface {
	// PullCount returns the pull count of a Docker Hub repository
	// ("namespace/name").
	PullCount(ctx context.Context, repository string) (int64, error)
}
