// Package composer implements the Composer ecosystem: names, versions and the
// hosted storage source.
package composer

import (
	"fmt"
	"path"
	"regexp"
	"strings"

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

// Match reports whether name matches a claim or capability pattern: "*"
// matches everything, anything else is path.Match on both lowercased.
func Match(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(name))
	return err == nil && ok
}

// lookupName normalises a requested name; an invalid name is a definite miss.
func lookupName(name string) (string, error) {
	pkg, err := Normalize(name)
	if err != nil {
		return "", fmt.Errorf("%w: %v", resolve.ErrNotFound, err) //nolint:errorlint // ErrNotFound is never joined with another error
	}
	return pkg, nil
}
