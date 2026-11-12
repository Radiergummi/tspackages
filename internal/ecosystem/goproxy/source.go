package goproxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// Info is a module version's metadata, marshalled as GOPROXY expects:
// {"Version","Time"} with Time in RFC 3339 UTC.
type Info struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// Artifact is a file ready to be served. Body may implement io.ReadSeeker,
// in which case ranged requests are answered from it.
type Artifact struct {
	Body io.ReadCloser
	Size int64 // 0 = unknown
}

// ErrUnavailable marks a module a source cannot serve right now (conflicts,
// not yet indexed). It answers 502 and never wraps resolve.ErrNotFound.
var ErrUnavailable = errors.New("goproxy: module unavailable")

// Source provides Go modules. Paths are case-preserved module paths. Methods
// return an error wrapping resolve.ErrNotFound only for a definite miss.
type Source interface {
	resolve.Claimed
	// List returns canonical versions, without pseudo-versions.
	List(ctx context.Context, path string) ([]string, error)
	// Info resolves version, which may be a query (branch, hash, pseudo-version).
	Info(ctx context.Context, path, version string) (Info, error)
	Latest(ctx context.Context, path string) (Info, error)
	// Mod and Zip take a canonical version.
	Mod(ctx context.Context, path, version string) (Artifact, error)
	Zip(ctx context.Context, path, version string) (Artifact, error)
}

// SumDB serves /go/sumdb/. rest is what follows "sumdb/".
type SumDB interface {
	ServeSumDB(w http.ResponseWriter, r *http.Request, caller identity.Caller, rest string)
}
