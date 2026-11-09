package composer

// Port of composer/semver (MIT, https://github.com/composer/semver),
// VersionParser::normalize, normalizeBranch and expandStability. PHP regexes
// are translated to RE2; the possessive quantifiers in the originals are
// plain greedy here, which accepts the same strings because each is followed
// by a character class that cannot match what it consumed.

import (
	"fmt"
	"regexp"
	"strings"
)

const modifierRegex = `[._-]?(?:(stable|beta|b|RC|alpha|a|patch|pl|p)((?:[.-]?\d+)*)?)?([.-]?dev)?`

var (
	aliasRE     = regexp.MustCompile(`^([^,\s]+) +as +([^,\s]+)$`)
	stabilityRE = regexp.MustCompile(`(?i)@(?:stable|RC|beta|alpha|dev)$`)
	metadataRE  = regexp.MustCompile(`^([^,\s+]+)\+[^\s]+$`)
	classicalRE = regexp.MustCompile(`(?i)^v?(\d{1,5})(\.\d+)?(\.\d+)?(\.\d+)?` + modifierRegex + `$`)
	datetimeRE  = regexp.MustCompile(`(?i)^v?(\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2})` + modifierRegex + `$`)
	devSuffixRE = regexp.MustCompile(`(?i)(.*?)[.-]?dev$`)
	branchRE    = regexp.MustCompile(`(?i)^v?(\d+)(\.(?:\d+|[xX*]))?(\.(?:\d+|[xX*]))?(\.(?:\d+|[xX*]))?$`)
	nonDigitRE  = regexp.MustCompile(`\D`)
)

// phpTrim is PHP's default trim() character set.
const phpTrim = " \t\n\r\x00\x0B"

// NormalizeVersion converts a version string to Composer's normalised form
// ("1.2.0" -> "1.2.0.0", "v1.0.0-rc1" -> "1.0.0.0-RC1").
func NormalizeVersion(v string) (string, error) {
	version := strings.Trim(v, phpTrim)
	orig := version

	// strip off aliasing
	if m := aliasRE.FindStringSubmatch(version); m != nil {
		version = m[1]
	}
	// strip off stability flag
	if loc := stabilityRE.FindStringIndex(version); loc != nil {
		version = version[:loc[0]]
	}
	// master/trunk/default are branches
	switch version {
	case "master", "trunk", "default":
		version = "dev-" + version
	}
	// branch-like: keep the full name
	if len(version) >= 4 && strings.EqualFold(version[:4], "dev-") {
		return "dev-" + version[4:], nil
	}
	// strip off build metadata
	if m := metadataRE.FindStringSubmatch(version); m != nil {
		version = m[1]
	}

	var m []string
	index := 0
	if m = classicalRE.FindStringSubmatch(version); m != nil {
		version = m[1] + orDefault(m[2], ".0") + orDefault(m[3], ".0") + orDefault(m[4], ".0")
		index = 5
	} else if m = datetimeRE.FindStringSubmatch(version); m != nil {
		version = nonDigitRE.ReplaceAllString(m[1], ".")
		index = 2
	}
	if index != 0 {
		if m[index] != "" {
			if m[index] == "stable" { // case-sensitive, as in the original
				return version, nil
			}
			version += "-" + expandStability(m[index]) + strings.TrimLeft(m[index+1], ".-")
		}
		if m[index+2] != "" {
			version += "-dev"
		}
		return version, nil
	}

	// dev branches such as "1.x-dev"; only numeric branches are valid here
	if m := devSuffixRE.FindStringSubmatch(version); m != nil {
		if _, normalized := NormalizeBranch(m[1]); !strings.Contains(normalized, "dev-") {
			return normalized, nil
		}
	}
	return "", fmt.Errorf("invalid version string %q", orig)
}

// NormalizeBranch normalises a branch name: numeric branches ("v1.x") become
// "1.9999999.9999999.9999999-dev", anything else "dev-<name>". It returns the
// trimmed input as version.
func NormalizeBranch(b string) (version, normalized string) {
	name := strings.Trim(b, phpTrim)
	m := branchRE.FindStringSubmatch(name)
	if m == nil {
		return name, "dev-" + name
	}
	var sb strings.Builder
	for i := 1; i < 5; i++ {
		if m[i] == "" {
			sb.WriteString(".x")
		} else {
			sb.WriteString(strings.NewReplacer("*", "x", "X", "x").Replace(m[i]))
		}
	}
	return name, strings.ReplaceAll(sb.String(), "x", "9999999") + "-dev"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func expandStability(s string) string {
	s = strings.ToLower(s)
	switch s {
	case "a":
		return "alpha"
	case "b":
		return "beta"
	case "p", "pl":
		return "patch"
	case "rc":
		return "RC"
	}
	return s
}

var digitRunRE = regexp.MustCompile(`\d+`)

// compareNormalized orders two normalised versions: the dotted numeric core
// numerically (missing parts count as 0), then the stability
// (dev < alpha < beta < RC < stable < patch), then the numbers in the
// modifier. It returns -1, 0 or 1. Inputs must be normalised and non-branch.
func compareNormalized(a, b string) int {
	ca, ra, _ := strings.Cut(a, "-")
	cb, rb, _ := strings.Cut(b, "-")
	if c := compareNumbers(strings.Split(ca, "."), strings.Split(cb, ".")); c != 0 {
		return c
	}
	if c := cmpInt(stabilityRank(ra), stabilityRank(rb)); c != 0 {
		return c
	}
	return compareNumbers(digitRunRE.FindAllString(ra, -1), digitRunRE.FindAllString(rb, -1))
}

func stabilityRank(rest string) int {
	r := strings.ToLower(rest)
	switch {
	case r == "":
		return 4
	case strings.HasSuffix(r, "dev"):
		return 0
	case strings.HasPrefix(r, "alpha"):
		return 1
	case strings.HasPrefix(r, "beta"):
		return 2
	case strings.HasPrefix(r, "rc"):
		return 3
	case strings.HasPrefix(r, "patch"):
		return 5
	}
	return 4
}

// compareNumbers compares digit strings element-wise without parsing them, so
// arbitrarily long numbers cannot overflow.
func compareNumbers(a, b []string) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		x, y := "", "" // missing = 0, which trims to ""
		if i < len(a) {
			x = strings.TrimLeft(a[i], "0")
		}
		if i < len(b) {
			y = strings.TrimLeft(b[i], "0")
		}
		if c := cmpInt(len(x), len(y)); c != 0 {
			return c
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
