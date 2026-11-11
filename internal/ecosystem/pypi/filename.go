package pypi

import (
	"fmt"
	"slices"
	"strings"
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
		if parts[2] == "" || parts[2][0] < '0' || parts[2][0] > '9' {
			return WheelName{}, fmt.Errorf("invalid wheel build tag in %q", f)
		}
		w = WheelName{Name: parts[0], Version: parts[1], Build: parts[2], Tags: parts[3:]}
	default:
		return WheelName{}, fmt.Errorf("invalid wheel filename %q", f)
	}
	if slices.Contains(parts, "") {
		return WheelName{}, fmt.Errorf("invalid wheel filename %q", f)
	}
	if _, err := ParseVersion(w.Version); err != nil {
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
	if _, err := ParseVersion(version); err != nil {
		return "", "", fmt.Errorf("invalid sdist filename %q: %w", f, err)
	}
	if _, err := Normalize(name); err != nil {
		return "", "", fmt.Errorf("invalid sdist filename %q: %w", f, err)
	}
	return name, version, nil
}

// SdistFilename is the PEP 625 filename of the sdist of a normalised name
// at v: "-" in the name becomes "_".
func SdistFilename(name string, v Version) string {
	return strings.ReplaceAll(name, "-", "_") + "-" + v.String() + ".tar.gz"
}
