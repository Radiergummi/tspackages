package composer

import (
	"context"
	"io"

	"github.com/radiergummi/tspackages/internal/resolve"
)

// Version is one released version of a package.
type Version struct {
	Package   map[string]any `json:"package"`   // composer.json fields + version, version_normalized, dist (url filled by handler)
	Version   string         `json:"version"`   // as published
	Reference string         `json:"reference"` // commit SHA (git), upstream dist.reference (registry), sha256 of zip (storage)
	Dev       bool           `json:"dev"`
}

// Artifact is a dist archive ready to be served.
type Artifact struct {
	Body io.ReadCloser
	Size int64
	SHA1 string
}

// Source provides Composer packages. Methods return an error wrapping
// resolve.ErrNotFound only for a definite miss.
type Source interface {
	resolve.Claimed
	Type() string
	Versions(ctx context.Context, name string) ([]Version, error) // resolve.ErrNotFound if unknown
	Dist(ctx context.Context, name, version, reference string) (Artifact, error)
	Packages(ctx context.Context) (names []string, enumerable bool, err error)
}
