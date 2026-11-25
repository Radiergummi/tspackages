package apt

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/radiergummi/tspackages/internal/identity"
)

// RequestError is a client mistake or conflict: Status is 400, 409 or 413 and
// Detail is sent to the client as the response body.
type RequestError struct {
	Status int
	Detail string
}

func (e *RequestError) Error() string { return e.Detail }

// ErrExists says a file with the same name, version and architecture already
// exists with other bytes.
var ErrExists = errors.New("already exists with other content")

// ReadAccess is what a caller's rules allow, computed once per request.
type ReadAccess struct {
	Any  bool                   // some valid apt: read rule (or "*")
	Name func(name string) bool // authz.Allowed(rules, "apt", name, authz.Read, Match)
	// Viewer is the caller's node, one apt client state: the Release
	// Dates it is served only rise.
	Viewer string
}

// Blob is a file a source serves. The caller closes Body.
type Blob struct {
	Body      io.ReadCloser
	Size      int64     // negative when unknown
	ETag      string    // strong, quoted
	Modified  time.Time // zero when unknown
	Immutable bool
}

// Source serves one apt repository below /apt/<Name()>/. A miss is
// resolve.ErrNotFound.
type Source interface {
	Name() string
	// Release returns "InRelease", "Release" or "Release.gpg" of suite as acc sees it.
	Release(ctx context.Context, acc ReadAccess, suite, which string) (Blob, error)
	Dist(ctx context.Context, acc ReadAccess, suite, rel string) (Blob, error)
	ByHash(ctx context.Context, acc ReadAccess, suite, rel, sha256 string) (Blob, error)
	Pool(ctx context.Context, acc ReadAccess, p Path) (Blob, error)
}

// Uploader is a Source that accepts uploads: a storage source.
type Uploader interface {
	Source
	Claims() []string
	// Upload stores body (spooled, read from 0) into suite/component.
	Upload(ctx context.Context, c identity.Caller, suite, component string, ctl Control, body *os.File, size int64) (created bool, err error)
}
