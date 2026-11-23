package maven

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// File is an artifact file as a source serves it.
type File struct {
	Body io.ReadCloser
	Size int64 // -1 = unknown
	// Digests has SHA1 set whenever the file's bytes are verified or
	// stored; the others when known. An empty SHA1 (an upstream signature
	// served uncached) sends no checksum headers and no-store.
	Digests   Digests
	Modified  time.Time // zero = unknown
	Immutable bool      // release or timestamped SNAPSHOT file
}

// Source provides Maven repository content. Methods return an error wrapping
// resolve.ErrNotFound only for a definite miss.
type Source interface {
	resolve.Claimed
	// File serves a KindFile path; p.Checksum is ignored.
	File(ctx context.Context, p Path) (File, error)
	// Digests returns all four digests of a KindFile path; it may fetch the
	// file.
	Digests(ctx context.Context, p Path) (Digests, error)
	// Metadata returns artifact- or version-level maven-metadata.xml;
	// p.Checksum is ignored.
	Metadata(ctx context.Context, p Path) ([]byte, error)
}

// Deployer is a Source that accepts deploys.
type Deployer interface {
	Source
	// Deploy stores one PUT. body is the spooled request, read from 0.
	Deploy(ctx context.Context, c identity.Caller, p Path, body *os.File, size int64) error
}

// ErrExists rejects a deploy of a file that is already stored with other
// bytes (409).
var ErrExists = errors.New("already exists with other content")

// RequestError is a request the client got wrong: Status is 400, 409 or 413,
// Title and Detail are sent in the problem+json body.
type RequestError struct {
	Status        int
	Title, Detail string
}

func (e *RequestError) Error() string { return e.Detail }
