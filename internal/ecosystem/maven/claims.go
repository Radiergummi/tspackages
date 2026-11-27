package maven

import (
	"path"
	"regexp"
	"strings"
)

var patternRE = regexp.MustCompile(`^(\*|[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?(:[a-z0-9._*-]+)?)$`)

// ValidPattern reports whether p is a claim or capability pattern: "*", or
// "<group>" or "<group>:<artifact>" in lowercase, where the group is dotted
// segments of [a-z0-9_-] whose last segment may be "*" (one or more trailing
// segments) and the artifact is [a-z0-9._-] with "*" inside it. internal/config
// keeps the same grammar for claims (it can't import this package); a test
// there checks that the two agree.
func ValidPattern(p string) bool { return patternRE.MatchString(p) }

// Match reports whether a pattern matches the lowercased groupId:artifactId of
// c. A malformed pattern matches nothing.
func Match(pattern string, c Coords) bool {
	if !ValidPattern(pattern) {
		return false
	}
	if pattern == "*" {
		return true
	}
	key := c.Key()
	group, artifact, _ := strings.Cut(key, ":")
	gp, ap, hasArtifact := strings.Cut(pattern, ":")
	if !groupMatch(gp, group) {
		return false
	}
	if !hasArtifact {
		return true
	}
	ok, err := path.Match(ap, artifact)
	return err == nil && ok
}

// MatchGroup reports whether a pattern's group part matches the lowercased
// group, the group-level reading of a metadata path. The artifact part, if
// any, is ignored. A malformed pattern matches nothing.
func MatchGroup(pattern, group string) bool {
	if !ValidPattern(pattern) {
		return false
	}
	if pattern == "*" {
		return true
	}
	gp, _, _ := strings.Cut(pattern, ":")
	return groupMatch(gp, strings.ToLower(group))
}

// groupMatch matches a group pattern against a lowercased group: literal, or
// a literal prefix followed by ".*" for one or more further segments.
func groupMatch(pattern, group string) bool {
	prefix, open := strings.CutSuffix(pattern, ".*")
	if !open {
		return pattern == group
	}
	rest, ok := strings.CutPrefix(group, prefix+".")
	return ok && rest != ""
}
