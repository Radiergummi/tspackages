// Package authz evaluates tailnet capability rules. It is pure: no HTTP.
package authz

import "strings"

type Action string

const (
	Read  Action = "read"
	Write Action = "write"
)

// Rule is one capability value from the tailnet grants.
type Rule struct {
	Read  []string `json:"read"`
	Write []string `json:"write"`
}

// Matcher reports whether a package name matches an ecosystem-specific pattern.
type Matcher func(pattern, name string) bool

// Allowed reports whether any rule grants action a on the package. A rule
// string "*" grants everything; otherwise it must be "<ecosystem>:<pattern>"
// with an exactly matching ecosystem. Write does not imply read.
func Allowed(rules []Rule, ecosystem, name string, a Action, m Matcher) bool {
	if ecosystem == "" || name == "" {
		return false
	}
	for _, r := range rules {
		var entries []string
		switch a {
		case Read:
			entries = r.Read
		case Write:
			entries = r.Write
		}
		for _, e := range entries {
			if e == "*" {
				return true
			}
			eco, pattern, ok := strings.Cut(e, ":")
			if ok && eco == ecosystem && m(pattern, name) {
				return true
			}
		}
	}
	return false
}
