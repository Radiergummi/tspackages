// Package composer implements the Composer ecosystem: names, versions and the
// hosted storage source.
package composer

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/radiergummi/tspackages/internal/authz"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// nameRE is Composer's package-name pattern, applied to the lowercased name.
var nameRE = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`)

// Normalize lowercases name and validates it as a Composer package name. The
// result is a safe storage-key path ("vendor/name").
func Normalize(name string) (string, error) {
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 { // before lowercasing: ToLower maps U+212A (Kelvin) to "k"
			return "", fmt.Errorf("invalid package name %q", name)
		}
	}
	n := strings.ToLower(name)
	if len(n) > 255 || !nameRE.MatchString(n) {
		return "", fmt.Errorf("invalid package name %q", name)
	}
	return n, nil
}

// patternRE is the grammar of claim and capability patterns: "<vendor>/<name>"
// of [a-z0-9_.-] and "*", case-insensitive. Config additionally requires
// claims to be lowercase.
var patternRE = regexp.MustCompile(`^[a-zA-Z0-9_.*-]+/[a-zA-Z0-9_.*-]+$`)

// ValidPattern reports whether p is "*" or matches patternRE.
func ValidPattern(p string) bool { return p == "*" || patternRE.MatchString(p) }

// Match reports whether name matches a claim or capability pattern: "*"
// matches everything, a valid pattern is path.Match on both lowercased, and
// an invalid pattern matches nothing.
func Match(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	if !ValidPattern(pattern) {
		return false
	}
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(name))
	return err == nil && ok
}

// malformedRules returns the capability entries that can never grant
// anything for Composer: entries without an ecosystem and Composer entries
// with an invalid pattern. Entries for other ecosystems are not checked.
func malformedRules(rules []authz.Rule) []string {
	var bad []string
	for _, r := range rules {
		for _, e := range slices.Concat(r.Read, r.Write) {
			eco, pattern, ok := strings.Cut(e, ":")
			if e != "*" && (!ok || eco == "" || (eco == ecoName && !ValidPattern(pattern))) {
				bad = append(bad, e)
			}
		}
	}
	return bad
}

// lookupName normalises a requested name; an invalid name is a definite miss.
func lookupName(name string) (string, error) {
	pkg, err := Normalize(name)
	if err != nil {
		return "", fmt.Errorf("%w: %v", resolve.ErrNotFound, err) //nolint:errorlint // ErrNotFound is never joined with another error
	}
	return pkg, nil
}
