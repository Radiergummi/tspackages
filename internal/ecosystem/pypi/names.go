// Package pypi serves a Python package index (the simple API, PEP 503 and
// PEP 691) and accepts uploads through the legacy upload API.
package pypi

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	validNameRE = regexp.MustCompile(`(?i)^([a-z0-9]|[a-z0-9][a-z0-9._-]*[a-z0-9])$`) // PEP 508
	separatorRE = regexp.MustCompile(`[-_.]+`)
	patternRE   = regexp.MustCompile(`^([a-z0-9*]+(-[a-z0-9*]+)+|\**[a-z0-9][a-z0-9*]*)$`)
)

// Normalize returns the PEP 503 normalised form of a valid PEP 508 project
// name: lowercase, with every run of "-", "_" and "." turned into "-".
func Normalize(name string) (string, error) {
	if !validNameRE.MatchString(name) {
		return "", fmt.Errorf("invalid project name %q", name)
	}
	return strings.ToLower(separatorRE.ReplaceAllString(name, "-")), nil
}

// ValidPattern reports whether p is a claim or capability pattern: "*", or
// normalised name characters with "*" wildcards and at least one other
// character, where "-" only joins two non-empty parts (no leading, trailing
// or doubled "-", which no normalised name has). internal/config keeps the
// same grammar for claims.
func ValidPattern(p string) bool { return p == "*" || patternRE.MatchString(p) }

// Match reports whether a pattern matches a normalised name, ignoring case
// (capability rules are case-insensitive). A malformed pattern matches
// nothing.
func Match(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	if !ValidPattern(pattern) {
		return false
	}
	ok, err := path.Match(pattern, strings.ToLower(name))
	return err == nil && ok
}
