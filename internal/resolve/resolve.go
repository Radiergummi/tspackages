// Package resolve decides which package source may answer a name.
package resolve

import (
	"context"
	"errors"
	"net/http"

	"github.com/radiergummi/tspackages/internal/authz"
)

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
		if errors.Is(err, ErrNotFound) {
			continue
		}
		return zeroT, zeroS, &SourceError{
			Source:  s.Name(),
			Err:     err,
			Timeout: errors.Is(err, context.DeadlineExceeded),
		}
	}
	return zeroT, zeroS, ErrNotFound
}

// HTTPStatus maps a resolution error to a response status.
func HTTPStatus(err error) int {
	if errors.Is(err, ErrNotFound) {
		return http.StatusNotFound
	}
	var se *SourceError
	if errors.As(err, &se) {
		if se.Timeout {
			return http.StatusGatewayTimeout
		}
		return http.StatusBadGateway
	}
	return http.StatusInternalServerError
}
