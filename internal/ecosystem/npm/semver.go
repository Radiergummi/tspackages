package npm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxVersionLen keeps a version within one escaped storage key segment.
const maxVersionLen = 156

// Version is a strict SemVer 2.0.0 version.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string // pre-release identifiers, as written
	Build               string   // build metadata, as written, without "+"
}

// ParseVersion parses MAJOR.MINOR.PATCH[-pre][+build] strictly: at most 156
// bytes, no leading zeros in numeric parts or numeric pre-release
// identifiers, no overflow of uint64, no leading "v" or "=".
func ParseVersion(s string) (Version, error) {
	if len(s) > maxVersionLen {
		return Version{}, errors.New("version too long")
	}
	var v Version
	core, build, hasBuild := strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(core, "-")
	nums := strings.Split(core, ".")
	if len(nums) != 3 {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}
	for i, p := range []*uint64{&v.Major, &v.Minor, &v.Patch} {
		n, err := parseNumeric(nums[i])
		if err != nil {
			return Version{}, fmt.Errorf("invalid version %q: %w", s, err)
		}
		*p = n
	}
	if hasPre {
		v.Pre = strings.Split(pre, ".")
		for _, id := range v.Pre {
			if !validIdentifier(id) {
				return Version{}, fmt.Errorf("invalid version %q: bad pre-release identifier %q", s, id)
			}
			if isNumeric(id) && len(id) > 1 && id[0] == '0' {
				return Version{}, fmt.Errorf("invalid version %q: leading zero in %q", s, id)
			}
		}
	}
	if hasBuild {
		for id := range strings.SplitSeq(build, ".") {
			if !validIdentifier(id) {
				return Version{}, fmt.Errorf("invalid version %q: bad build identifier %q", s, id)
			}
		}
		v.Build = build
	}
	return v, nil
}

func parseNumeric(s string) (uint64, error) {
	if !isNumeric(s) || len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("bad number %q", s)
	}
	return strconv.ParseUint(s, 10, 64)
}

func isNumeric(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func validIdentifier(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool {
		return (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-'
	}) < 0
}

// Compare orders versions by SemVer 2.0.0 section 11: -1, 0 or 1. Build
// metadata is ignored.
func Compare(a, b Version) int {
	for _, p := range [][2]uint64{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if p[0] != p[1] {
			return cmpUint(p[0], p[1])
		}
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		if c := compareIdentifier(a.Pre[i], b.Pre[i]); c != 0 {
			return c
		}
	}
	return cmpUint(uint64(len(a.Pre)), uint64(len(b.Pre)))
}

// compareIdentifier: numeric identifiers compare as numbers and sort before
// alphanumeric ones, which compare in ASCII order.
func compareIdentifier(a, b string) int {
	an, bn := isNumeric(a), isNumeric(b)
	switch {
	case an && bn:
		// No leading zeros: a longer number is larger, equal lengths compare as text.
		if len(a) != len(b) {
			return cmpUint(uint64(len(a)), uint64(len(b)))
		}
		return strings.Compare(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// String returns the version as parsed.
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if len(v.Pre) > 0 {
		s += "-" + strings.Join(v.Pre, ".")
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// Prerelease reports whether v has pre-release identifiers.
func (v Version) Prerelease() bool { return len(v.Pre) > 0 }
