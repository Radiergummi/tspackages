// Package npm serves an npm registry: packuments, tarballs and publishes.
package npm

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/radiergummi/tspackages/internal/storage"
)

const maxNameLen = 214 // npm's limit, scope included

var (
	partRE    = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	patternRE = regexp.MustCompile(`^(\*|@[a-z0-9._*-]+/[a-z0-9._*-]+|[a-z0-9._*-]+)$`)
	tagRE     = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
)

// Name is a package name, unscoped ("name") or scoped ("@scope/name").
type Name struct {
	Exact string // as requested, "@scope/base" or "base"
	Norm  string // strings.ToLower(Exact): claims, authorization and storage
	Scope string // without "@", exact case; "" when unscoped
	Base  string // exact case
}

// ParseName parses the URL-decoded form of a package name. It refuses what
// npm refuses (a leading "." or "_" in the name or in either part, characters
// outside [A-Za-z0-9._~-], more than 214 bytes) and names whose escaped
// normalised form would not fit one storage key segment.
func ParseName(s string) (Name, error) {
	if s == "" || len(s) > maxNameLen {
		return Name{}, fmt.Errorf("invalid package name length %d", len(s))
	}
	n := Name{Exact: s, Norm: strings.ToLower(s), Base: s}
	if rest, ok := strings.CutPrefix(s, "@"); ok {
		scope, base, ok := strings.Cut(rest, "/")
		if !ok || scope == "" || base == "" {
			return Name{}, fmt.Errorf("invalid scoped package name %q", s)
		}
		n.Scope, n.Base = scope, base
	}
	for _, part := range []string{n.Scope, n.Base} {
		if part == "" {
			continue // the scope of an unscoped name
		}
		if part[0] == '.' || part[0] == '_' {
			return Name{}, fmt.Errorf("invalid package name %q: must not start with %q", s, part[:1])
		}
		if !partRE.MatchString(part) {
			return Name{}, fmt.Errorf("invalid package name %q: characters outside [A-Za-z0-9._~-]", s)
		}
	}
	if len(storage.EscapeSegment(n.Norm)) > storage.MaxSegment {
		return Name{}, fmt.Errorf("package name %q is too long to store", s)
	}
	return n, nil
}

// Escaped is the name as a registry URL path segment: "@scope%2fbase" (exact
// case) or "base".
func (n Name) Escaped() string {
	if n.Scope == "" {
		return n.Base
	}
	return "@" + n.Scope + "%2f" + n.Base
}

// TarballFile is the tarball's file name, "<base>-<version>.tgz".
func (n Name) TarballFile(version string) string { return n.Base + "-" + version + ".tgz" }

// ValidPattern reports whether p is a claim or capability pattern: "*", or
// "@scope/name" or "name" in lowercase [a-z0-9._*-]. internal/config keeps
// the same grammar for claims (it can't import this package).
func ValidPattern(p string) bool { return patternRE.MatchString(p) }

// Match reports whether a pattern matches a normalised name. "*" matches
// every name; any other "*" stays within one part. A malformed pattern
// matches nothing.
func Match(pattern, norm string) bool {
	if !ValidPattern(pattern) {
		return false
	}
	if pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, norm)
	return err == nil && ok
}

// ValidTag reports whether t is a dist-tag: 1-64 bytes of [a-z0-9._-] that
// does not start with a digit or with "v" and a digit (npm refuses tags that
// read as a semver range).
func ValidTag(t string) bool {
	if !tagRE.MatchString(t) || t[0] >= '0' && t[0] <= '9' {
		return false
	}
	return t[0] != 'v' || len(t) == 1 || t[1] < '0' || t[1] > '9'
}
