// Package resolve decides which package source may answer a name.
package resolve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"

	"github.com/radiergummi/tspackages/internal/authz"
)

// ErrNotFound is the only error that lets resolution move on to the next
// source. Sources must return it (bare or wrapped with %w) only for a definite
// miss, and never join it with other errors.
var ErrNotFound = errors.New("not found")

// Claimed is a source with a name and a set of claimed name patterns.
type Claimed interface {
	Name() string
	Claims() []string
}

// SourceError is a failure of a single source; it never falls through.
type SourceError struct {
	Source  string
	Err     error
	Timeout bool
}

func (e *SourceError) Error() string { return "source " + e.Source + ": " + e.Err.Error() }
func (e *SourceError) Unwrap() error { return e.Err }

// Candidates returns the claiming sources in order when any claim matches
// name (claimed=true); otherwise the unclaimed source, if any.
func Candidates[S Claimed](sources []S, name string, m authz.Matcher) (cands []S, claimed bool) {
	for _, s := range sources {
		for _, c := range s.Claims() {
			if m(c, name) {
				cands = append(cands, s)
				break
			}
		}
	}
	if len(cands) > 0 {
		return cands, true
	}
	for _, s := range sources {
		if len(s.Claims()) == 0 {
			return []S{s}, false
		}
	}
	return nil, false
}

// First asks candidates in order. Only ErrNotFound moves on to the next one;
// any other error stops and is returned as a *SourceError.
func First[S Claimed, T any](ctx context.Context, cands []S, fn func(context.Context, S) (T, error)) (T, S, error) {
	var zeroT T
	var zeroS S
	for _, s := range cands {
		v, err := fn(ctx, s)
		if err == nil {
			return v, s, nil
		}
		if errors.Is(err, ErrNotFound) && !isJoined(err) {
			continue
		}
		return zeroT, zeroS, &SourceError{
			Source:  s.Name(),
			Err:     err,
			Timeout: isTimeout(err),
		}
	}
	return zeroT, zeroS, ErrNotFound
}

// isJoined reports whether a multi-error (errors.Join or similar) is anywhere
// in the chain; such an error may hide a real failure next to a not-found.
func isJoined(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if _, ok := err.(interface{ Unwrap() []error }); ok {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// HTTPStatus maps a resolution error to a response status.
func HTTPStatus(err error) int {
	var se *SourceError
	if errors.As(err, &se) {
		if se.Timeout {
			return http.StatusGatewayTimeout
		}
		return http.StatusBadGateway
	}
	if errors.Is(err, ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}
