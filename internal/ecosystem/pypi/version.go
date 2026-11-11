package pypi

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The PEP 440 grammar and normalisation follow packaging.version
// (https://github.com/pypa/packaging, BSD-2-Clause/Apache-2.0).
var versionRE = regexp.MustCompile(`(?i)^v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

// Version is a parsed PEP 440 version.
type Version struct {
	epoch   int
	release []int
	pre     string // "a", "b" or "rc"; "" for none
	preN    int
	post    int // -1 for none
	dev     int // -1 for none
	local   []string
}

// ParseVersion parses s as a PEP 440 version, accepting the spellings PEP 440
// normalises (a "v" prefix, case, separators, implicit numbers).
func ParseVersion(s string) (Version, error) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}
	g := func(name string) string { return m[versionRE.SubexpIndex(name)] }
	// Digits only, by the grammar; "" is an implicit 0. A number too large
	// for an int would otherwise make distinct versions equal.
	var overflow bool
	num := func(s string) int {
		if s == "" {
			return 0
		}
		n, err := strconv.Atoi(s)
		overflow = overflow || err != nil
		return n
	}
	v := Version{epoch: num(g("epoch")), post: -1, dev: -1}
	for part := range strings.SplitSeq(g("release"), ".") {
		v.release = append(v.release, num(part))
	}
	if l := strings.ToLower(g("pre_l")); l != "" {
		switch l {
		case "alpha":
			l = "a"
		case "beta":
			l = "b"
		case "c", "pre", "preview":
			l = "rc"
		}
		v.pre, v.preN = l, num(g("pre_n"))
	}
	switch {
	case g("post_n1") != "":
		v.post = num(g("post_n1"))
	case g("post_l") != "":
		v.post = num(g("post_n2"))
	}
	if g("dev_l") != "" {
		v.dev = num(g("dev_n"))
	}
	if l := g("local"); l != "" {
		for _, part := range separatorRE.Split(strings.ToLower(l), -1) {
			if strings.Trim(part, "0123456789") == "" {
				part = strings.TrimLeft(part, "0")
				if part == "" {
					part = "0"
				}
			}
			v.local = append(v.local, part)
		}
	}
	if overflow {
		return Version{}, fmt.Errorf("invalid version %q: a number is too large", s)
	}
	return v, nil
}

// String is the normalised version, as packaging.version.Version prints it.
func (v Version) String() string { return v.format(v.release) }

// Canonical is the form two equal versions share, as
// packaging.utils.canonicalize_version: String with trailing ".0" release
// segments stripped. 1.0, 1.0.0 and v1.0 are all "1".
func (v Version) Canonical() string {
	rel := v.release
	for len(rel) > 1 && rel[len(rel)-1] == 0 {
		rel = rel[:len(rel)-1]
	}
	return v.format(rel)
}

func (v Version) format(release []int) string {
	var b strings.Builder
	if v.epoch != 0 {
		fmt.Fprintf(&b, "%d!", v.epoch)
	}
	for i, n := range release {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(n))
	}
	if v.pre != "" {
		fmt.Fprintf(&b, "%s%d", v.pre, v.preN)
	}
	if v.post >= 0 {
		fmt.Fprintf(&b, ".post%d", v.post)
	}
	if v.dev >= 0 {
		fmt.Fprintf(&b, ".dev%d", v.dev)
	}
	if len(v.local) > 0 {
		b.WriteByte('+')
		b.WriteString(strings.Join(v.local, "."))
	}
	return b.String()
}
