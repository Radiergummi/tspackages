// Package goproxy serves Go modules over the GOPROXY protocol.
package goproxy

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/module"

	"github.com/radiergummi/tspackages/internal/storage"
)

const ecoName = "go" //nolint:unused // used by the handler and sources added next

var segmentRE = regexp.MustCompile(`^[a-z0-9._~*-]+$`)

// ValidPattern reports whether p is a claim or rule: "*", or "/"-separated
// non-empty segments of [a-z0-9._~-] and "*". internal/config keeps the same
// grammar as config.ValidGoPattern (it can't import this package); the
// agreement test and FuzzMatch keep the two identical.
func ValidPattern(p string) bool {
	if p == "*" {
		return true
	}
	return !slices.ContainsFunc(strings.Split(p, "/"), func(seg string) bool { return !segmentRE.MatchString(seg) })
}

// Match reports whether a pattern matches a module path, ignoring the path's
// case. A malformed pattern matches nothing. A trailing major-version suffix
// "/vN" (N >= 2, as module.SplitPathVersion splits it; not gopkg.in ".vN") is
// dropped before matching, because a claim covers every major version of its
// module: "go.acme.dev/sdk" matches "go.acme.dev/sdk/v2" but not
// "go.acme.dev/sdk/v1" or "go.acme.dev/sdkv2". A path also matches when the
// pattern fits it with the suffix. It is the same as config.GoMatch.
func Match(pattern, p string) bool {
	if !ValidPattern(pattern) {
		return false
	}
	if pattern == "*" {
		return true
	}
	p = strings.ToLower(p)
	if matchExact(pattern, p) {
		return true
	}
	prefix, major, ok := module.SplitPathVersion(p)
	return ok && strings.HasPrefix(major, "/") && matchExact(pattern, prefix)
}

func matchExact(pattern, p string) bool {
	ps, xs := strings.Split(pattern, "/"), strings.Split(p, "/")
	if len(ps) > 1 && ps[len(ps)-1] == "*" {
		n := len(ps)
		if len(xs) < n {
			return false
		}
		ps, xs = ps[:n-1], xs[:n-1]
	}
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if ok, err := path.Match(ps[i], xs[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// Kind is the kind of resource a route asks for.
type Kind int

const (
	KindList Kind = iota
	KindInfo
	KindMod
	KindZip
	KindLatest
)

// Route is a decoded GOPROXY request.
type Route struct {
	Path, Version string // Version is "" for list and latest
	Kind          Kind
}

var errRoute = errors.New("not a module route")

// ParseRoute parses what follows "/go/" (never "sumdb/..."); an error means
// 404. The version is not checked for being canonical: a non-canonical .info
// is a query, which the handler resolves.
func ParseRoute(rest string) (Route, error) {
	var r Route
	var escPath string
	if p, ok := strings.CutSuffix(rest, "/@latest"); ok {
		r.Kind, escPath = KindLatest, p
	} else {
		before, tail, ok := strings.CutLast(rest, "/@v/")
		if !ok {
			return Route{}, errRoute
		}
		escPath = before
		switch tail {
		case "list":
			r.Kind = KindList
		default:
			ext := path.Ext(tail)
			kind, ok := map[string]Kind{".info": KindInfo, ".mod": KindMod, ".zip": KindZip}[ext]
			ver := strings.TrimSuffix(tail, ext)
			if !ok || ver == "" || strings.Contains(ver, "/") {
				return Route{}, errRoute
			}
			v, err := module.UnescapeVersion(ver)
			if err != nil {
				return Route{}, fmt.Errorf("%w: %w", errRoute, err)
			}
			r.Kind, r.Version = kind, v
		}
	}
	p, err := module.UnescapePath(escPath)
	if err != nil {
		return Route{}, fmt.Errorf("%w: %w", errRoute, err)
	}
	if err := module.CheckPath(p); err != nil {
		return Route{}, fmt.Errorf("%w: %w", errRoute, err)
	}
	r.Path = p
	return r, nil
}

// pathSeg and versionSeg return the storage key segment for a raw module
// path or version, or false when it exceeds storage.MaxSegment. The base32
// encoding keeps keys that differ only in case apart.
func pathSeg(p string) (string, bool) { return seg(p) }

func versionSeg(v string) (string, bool) { return seg(v) }

func seg(s string) (string, bool) {
	e := storage.EscapeSegment(s)
	return e, len(e) <= storage.MaxSegment
}
