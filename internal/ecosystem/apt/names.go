// Package apt serves Debian (apt) repositories: generated Release and Packages
// indexes for hosted packages and verified pass-through of upstream
// repositories, for apt clients.
package apt

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ecoName is the ecosystem name in config, capability rules and metrics.
const ecoName = "apt"

// MaxName is the longest package name or version in bytes: the storage key
// rule (storage.EscapeSegment must fit storage.MaxSegment).
const MaxName = 156

const (
	maxArch  = 32
	maxSuite = 64
)

var (
	nameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:-]*$`)
	epochRE   = regexp.MustCompile(`^[0-9]+$`)
	archRE    = regexp.MustCompile(`^[a-z0-9-]+$`)
	suiteRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
)

// ValidName reports whether s is a package name: [a-z0-9][a-z0-9+.-]+, at
// most MaxName bytes.
func ValidName(s string) bool { return len(s) <= MaxName && nameRE.MatchString(s) }

// ValidVersion reports whether s is "[epoch:]upstream[-revision]" of
// [A-Za-z0-9.+~:-], the epoch digits, at most MaxName bytes.
func ValidVersion(s string) bool {
	if len(s) > MaxName {
		return false
	}
	if epoch, rest, ok := strings.Cut(s, ":"); ok {
		if !epochRE.MatchString(epoch) {
			return false
		}
		s = rest
	}
	return versionRE.MatchString(s)
}

// ValidArch reports whether s is an architecture: [a-z0-9-]+, at most 32 bytes.
func ValidArch(s string) bool { return len(s) <= maxArch && archRE.MatchString(s) }

// ValidSuite reports whether s is a suite or component name:
// [a-z0-9][a-z0-9._-]*, at most 64 bytes.
func ValidSuite(s string) bool { return len(s) <= maxSuite && suiteRE.MatchString(s) }

// StripEpoch returns v without its "<digits>:" epoch.
func StripEpoch(v string) string {
	if epoch, rest, ok := strings.Cut(v, ":"); ok && epochRE.MatchString(epoch) {
		return rest
	}
	return v
}

// Deb identifies a binary package file. Version may carry an epoch.
type Deb struct{ Name, Version, Arch string }

// FileName is "<name>_<version without epoch>_<arch>.deb".
func (d Deb) FileName() string { return d.Name + "_" + StripEpoch(d.Version) + "_" + d.Arch + ".deb" }

// ParseFileName is the inverse of FileName; the Version has no epoch.
func ParseFileName(f string) (Deb, error) {
	base, ok := strings.CutSuffix(f, ".deb")
	parts := strings.Split(base, "_")
	if !ok || len(parts) != 3 {
		return Deb{}, fmt.Errorf("%q is not <name>_<version>_<arch>.deb", f)
	}
	d := Deb{parts[0], parts[1], parts[2]}
	switch {
	case !ValidName(d.Name):
		return Deb{}, fmt.Errorf("invalid package name in %q", f)
	case strings.Contains(d.Version, ":") || !ValidVersion(d.Version):
		return Deb{}, fmt.Errorf("invalid version in %q", f)
	case !ValidArch(d.Arch):
		return Deb{}, fmt.Errorf("invalid architecture in %q", f)
	}
	return d, nil
}

var errNotFound = errors.New("not found")
