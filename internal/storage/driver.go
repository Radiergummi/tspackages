// Package storage provides the blob store drivers (filesystem and S3) that
// back hosted stores, the durable state store and the cache.
package storage

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"iter"
	"regexp"
	"strings"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
)

var (
	ErrNotFound     = errors.New("storage: not found")
	ErrExists       = errors.New("storage: already exists")
	ErrPrecondition = errors.New("storage: precondition failed")
	ErrInvalidKey   = errors.New("storage: invalid key")
)

// Info describes a stored object.
type Info struct {
	Key     string
	Size    int64
	ETag    string
	ModTime time.Time
}

// Driver is a flat key/value blob store with conditional writes. Keys are
// validated with ValidKey. Delete of a missing key is not an error. A key must
// not also be a prefix of another key ("a" and "a/b"): the fs driver rejects
// this, the S3 driver cannot detect it cheaply and allows it, so callers must
// not rely on either.
type Driver interface {
	Get(ctx context.Context, key string) (io.ReadCloser, Info, error)
	Stat(ctx context.Context, key string) (Info, error)
	Put(ctx context.Context, key string, r io.Reader) (Info, error)                     // unconditional
	PutIfAbsent(ctx context.Context, key string, r io.Reader) (Info, error)             // ErrExists
	PutIfMatch(ctx context.Context, key string, r io.Reader, etag string) (Info, error) // etag "" = must not exist; ErrPrecondition
	Delete(ctx context.Context, key string) error
	// List yields every key that starts with prefix, in byte-wise lexical order.
	List(ctx context.Context, prefix string) iter.Seq2[Info, error]
}

var segmentRE = regexp.MustCompile(`^[A-Za-z0-9._~+-]+$`)

// ValidKey reports whether key is a "/"-separated path of safe segments.
func ValidKey(key string) error {
	if key == "" || len(key) > 1024 {
		return fmt.Errorf("%w: length %d", ErrInvalidKey, len(key))
	}
	for seg := range strings.SplitSeq(key, "/") {
		if seg == "." || seg == ".." || !segmentRE.MatchString(seg) {
			return fmt.Errorf("%w: %q", ErrInvalidKey, key)
		}
	}
	return nil
}

// EscapeSegment encodes an arbitrary string as a single valid key segment
// (unpadded base64url).
func EscapeSegment(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// validPrefix accepts "" or a key prefix, optionally ending in "/".
func validPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	return ValidKey(strings.TrimSuffix(prefix, "/"))
}

// Open builds the driver selected by c.Driver.
func Open(ctx context.Context, c config.StoreConfig) (Driver, error) {
	switch c.Driver {
	case "fs":
		return NewFS(c.Path)
	case "s3":
		return NewS3(ctx, c)
	default:
		return nil, fmt.Errorf("storage: unknown driver %q", c.Driver)
	}
}
