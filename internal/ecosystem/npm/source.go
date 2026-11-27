package npm

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// Doc is a stored document: Body holds BaseToken placeholders (Tokens of
// them), Size and SHA256 are of the stored bytes. The handler expands,
// sizes and tags it per request.
type Doc struct {
	Body   io.ReadCloser
	Size   int64
	SHA256 string // hex
	Tokens int
}

// Artifact is a file served as stored.
type Artifact struct {
	Body io.ReadCloser
	Size int64 // 0 = unknown
}

// Source provides npm packages. Methods get the name as requested (routing
// used its Norm) and return an error wrapping resolve.ErrNotFound only for a
// definite miss.
type Source interface {
	resolve.Claimed
	// Packument is the full document, or the abbreviated one when corgi.
	Packument(ctx context.Context, n Name, corgi bool) (Doc, error)
	// Version is one version object, with BaseToken placeholders.
	Version(ctx context.Context, n Name, versionOrTag string) ([]byte, error)
	Tarball(ctx context.Context, n Name, file string) (Artifact, error)
	DistTags(ctx context.Context, n Name) (map[string]string, error)
}

// Publisher is a Source that accepts publishes and dist-tag changes.
type Publisher interface {
	Source
	// Publish inspects and stores the spooled body (read from its start).
	// notice, when not empty, is sent as the npm-notice header.
	Publish(ctx context.Context, c identity.Caller, n Name, body *os.File, size int64) (notice string, err error)
	SetTag(ctx context.Context, c identity.Caller, n Name, tag, version string) error
	RemoveTag(ctx context.Context, c identity.Caller, n Name, tag string) error
}

// Attester serves the registry signing keys and attestation bundles.
type Attester interface {
	Keys(ctx context.Context) (Artifact, error)
	Attestations(ctx context.Context, n Name, version string) (Artifact, error)
}

// ErrVersionExists rejects a publish of a version the package already has
// (409).
var ErrVersionExists = errors.New("version already exists")

// ErrNoTarball rejects a publish body without a tarball attachment, which is
// how npm deprecate arrives (405).
var ErrNoTarball = errors.New("this registry does not support deprecate")

// RequestError is a publish or dist-tag request the client got wrong; Status
// is 400, 409 or 413 and Reason is sent as the error body.
type RequestError struct {
	Status int
	Reason string
}

func (e *RequestError) Error() string { return e.Reason }
