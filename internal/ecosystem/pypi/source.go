package pypi

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// Artifact is a file ready to be served. Body may implement io.ReadSeeker,
// in which case ranged requests are answered from it.
type Artifact struct {
	Body io.ReadCloser
	Size int64 // 0 = unknown
}

// Source provides Python projects. Names passed in are normalised. Methods
// return an error wrapping resolve.ErrNotFound only for a definite miss.
type Source interface {
	resolve.Claimed
	Project(ctx context.Context, name string) (Project, error)
	File(ctx context.Context, name, filename string) (Artifact, error)
	// Metadata is a file's core metadata (PEP 658).
	Metadata(ctx context.Context, name, filename string) (Artifact, error)
	// Provenance is a file's PEP 740 provenance object.
	Provenance(ctx context.Context, name, filename string) (Artifact, error)
}

// Lister is a Source that can enumerate its projects, for the index page.
type Lister interface {
	Names(ctx context.Context) ([]string, error)
}

// Upload is one file sent through the legacy upload API. Name and Version
// are the form fields as sent; Content is the spooled file, read from its
// start.
type Upload struct {
	Name, Version, Filename string
	Content                 *os.File
	Size                    int64
	SHA256                  string // the form's sha256_digest, if sent
	Attestations            []byte // the form's attestations, if sent
}

// Uploader is a Source that accepts uploads.
type Uploader interface {
	Source
	Upload(ctx context.Context, caller identity.Caller, u Upload) (File, error)
}

// ErrFileExists rejects an upload whose filename, or whose release's sdist or
// wheel tags, already exist. twine and uv recognise PyPI's wording for it.
var ErrFileExists = errors.New("File already exists") //nolint:staticcheck // PyPI's wording, which clients match

// UploadError is an upload the client got wrong.
type UploadError struct{ Reason string }

func (e *UploadError) Error() string { return e.Reason }
