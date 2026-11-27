package apt

import (
	"path"
	"regexp"
)

var patternRE = regexp.MustCompile(`^[a-z0-9+.*-]+$`)

// ValidPattern reports whether p is a claim or capability pattern: "*" or a
// lowercase name pattern of [a-z0-9+.-] and "*" (any run of characters).
// internal/config keeps the same grammar for claims (it can't import this
// package); a test there checks that the two agree.
func ValidPattern(p string) bool { return patternRE.MatchString(p) }

// Match reports whether a pattern matches a package name. A malformed pattern
// matches nothing.
func Match(pattern, name string) bool {
	if !ValidPattern(pattern) {
		return false
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
