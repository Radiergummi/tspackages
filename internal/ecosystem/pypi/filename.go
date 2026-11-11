package pypi

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Wheel build and compatibility tags, as escaped by the binary distribution
// format: runs of other characters become "_", and tag sets join with ".".
var (
	wheelTagRE   = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)
	wheelBuildRE = regexp.MustCompile(`^[0-9][A-Za-z0-9_.]*$`)
)

// WheelName is a wheel filename split into its parts (PEP 427/491), as
// written; Name and Version are not normalised.
type WheelName struct {
	Name, Version, Build string
	Tags                 []string // python, abi, platform
}

// ParseWheelFilename splits a wheel filename.
func ParseWheelFilename(f string) (WheelName, error) {
	stem, ok := strings.CutSuffix(f, ".whl")
	if !ok || strings.ContainsAny(stem, "/\\") {
		return WheelName{}, fmt.Errorf("invalid wheel filename %q", f)
	}
	parts := strings.Split(stem, "-")
	var w WheelName
	switch len(parts) {
	case 5:
		w = WheelName{Name: parts[0], Version: parts[1], Tags: parts[2:]}
	case 6:
		if !wheelBuildRE.MatchString(parts[2]) {
			return WheelName{}, fmt.Errorf("invalid wheel build tag in %q", f)
		}
		w = WheelName{Name: parts[0], Version: parts[1], Build: parts[2], Tags: parts[3:]}
	default:
		return WheelName{}, fmt.Errorf("invalid wheel filename %q", f)
	}
	if slices.Contains(parts, "") || slices.ContainsFunc(w.Tags, func(t string) bool { return !wheelTagRE.MatchString(t) }) {
		return WheelName{}, fmt.Errorf("invalid wheel filename %q", f)
	}
	if err := filenameVersion(w.Version); err != nil {
		return WheelName{}, fmt.Errorf("invalid wheel filename %q: %w", f, err)
	}
	return w, nil
}

// ParseSdistFilename splits a ".tar.gz" sdist filename at the last "-" that
// leaves a valid version, so legacy dashed names ("foo-bar-1.0.tar.gz") still
// parse. Name and version are returned as written.
func ParseSdistFilename(f string) (name, version string, err error) {
	stem, ok := strings.CutSuffix(f, ".tar.gz")
	if !ok || strings.ContainsAny(stem, "/\\") {
		return "", "", fmt.Errorf("invalid sdist filename %q (want <name>-<version>.tar.gz)", f)
	}
	i := strings.LastIndex(stem, "-")
	if i <= 0 || i == len(stem)-1 {
		return "", "", fmt.Errorf("invalid sdist filename %q", f)
	}
	name, version = stem[:i], stem[i+1:]
	if err := filenameVersion(version); err != nil {
		return "", "", fmt.Errorf("invalid sdist filename %q: %w", f, err)
	}
	if _, err := Normalize(name); err != nil {
		return "", "", fmt.Errorf("invalid sdist filename %q: %w", f, err)
	}
	return name, version, nil
}

// filenameVersion checks a version as a filename writes it: valid, and
// without the surrounding whitespace ParseVersion tolerates.
func filenameVersion(v string) error {
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("invalid version %q", v)
	}
	_, err := ParseVersion(v)
	return err
}

// SdistFilename is the PEP 625 filename of the sdist of a normalised name
// at v: "-" in the name becomes "_".
func SdistFilename(name string, v Version) string {
	return strings.ReplaceAll(name, "-", "_") + "-" + v.String() + ".tar.gz"
}
