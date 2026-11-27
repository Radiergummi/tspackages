package npm

import (
	"errors"
	"net/url"
	"strings"
)

// RouteKind is what a request path under /npm/ addresses.
type RouteKind int

const (
	RoutePackument    RouteKind = iota // <name>
	RouteVersion                       // <name>/<version-or-tag>
	RouteTarball                       // <name>/-/<file>.tgz, -/npm-<version>.tgz
	RouteDistTags                      // -/package/<name>/dist-tags
	RouteDistTag                       // -/package/<name>/dist-tags/<tag>
	RouteKeys                          // -/npm/v1/keys
	RouteAttestations                  // -/npm/v1/attestations/<name>@<version>
	RouteRev                           // <name>/-rev/<rev>, <name>/-/<file>/-rev/<rev> (unpublish)
)

// Route is a parsed request path. Version, File and Tag are URL-decoded.
type Route struct {
	Kind    RouteKind
	Name    Name
	Version string // RouteVersion (version or tag), RouteAttestations
	File    string // RouteTarball
	Tag     string // RouteDistTag
}

var errNoRoute = errors.New("npm: no such route")

// ParsePath parses an escaped request path with "/npm/" trimmed. A name is
// "name", "@scope%2fname" (either case of %2f) or "@scope/name", with "@"
// also accepted as "%40". Any "-/" path other than the routes above is an
// error.
func ParsePath(escaped string) (Route, error) {
	segs := strings.Split(escaped, "/")
	if segs[0] != "-" {
		n, rest, err := nameAt(segs)
		if err != nil {
			return Route{}, err
		}
		return nameRoute(n, rest)
	}
	switch {
	case len(segs) == 2 && strings.HasPrefix(segs[1], "npm-") && strings.HasSuffix(segs[1], ".tgz"):
		// arborist leaves npmjs's /npm/-/npm-<v>.tgz alone: it already starts
		// with the registry path.
		file, err := url.PathUnescape(segs[1])
		if err != nil || strings.Contains(file, "/") {
			return Route{}, errNoRoute
		}
		return Route{Kind: RouteTarball, Name: Name{Exact: "npm", Norm: "npm", Base: "npm"}, File: file}, nil
	case len(segs) >= 4 && segs[1] == "package":
		n, rest, err := nameAt(segs[2:])
		if err != nil || len(rest) == 0 || rest[0] != "dist-tags" {
			return Route{}, errNoRoute
		}
		switch len(rest) {
		case 1:
			return Route{Kind: RouteDistTags, Name: n}, nil
		case 2:
			tag, err := url.PathUnescape(rest[1])
			if err != nil || tag == "" {
				return Route{}, errNoRoute
			}
			return Route{Kind: RouteDistTag, Name: n, Tag: tag}, nil
		}
	case escaped == "-/npm/v1/keys":
		return Route{Kind: RouteKeys}, nil
	case len(segs) >= 5 && segs[1] == "npm" && segs[2] == "v1" && segs[3] == "attestations":
		spec, err := url.PathUnescape(strings.Join(segs[4:], "/"))
		if err != nil {
			return Route{}, errNoRoute
		}
		i := strings.LastIndex(spec, "@")
		if i <= 0 || i == len(spec)-1 {
			return Route{}, errNoRoute
		}
		n, err := ParseName(spec[:i])
		if err != nil {
			return Route{}, err
		}
		return Route{Kind: RouteAttestations, Name: n, Version: spec[i+1:]}, nil
	}
	return Route{}, errNoRoute
}

// nameAt parses the name at the start of segs: one segment, or two when the
// first decodes to a bare "@scope". It returns the segments after it.
func nameAt(segs []string) (Name, []string, error) {
	s, err := url.PathUnescape(segs[0])
	if err != nil {
		return Name{}, nil, err
	}
	rest := segs[1:]
	if strings.HasPrefix(s, "@") && !strings.Contains(s, "/") && len(rest) > 0 {
		base, err := url.PathUnescape(rest[0])
		if err != nil {
			return Name{}, nil, err
		}
		s, rest = s+"/"+base, rest[1:]
	}
	n, err := ParseName(s)
	return n, rest, err
}

// nameRoute is the route of the segments after a name.
func nameRoute(n Name, rest []string) (Route, error) {
	switch {
	case len(rest) == 0:
		return Route{Kind: RoutePackument, Name: n}, nil
	case len(rest) == 1 && rest[0] != "-" && rest[0] != "-rev" && rest[0] != "":
		v, err := url.PathUnescape(rest[0])
		if err != nil {
			return Route{}, errNoRoute
		}
		return Route{Kind: RouteVersion, Name: n, Version: v}, nil
	case len(rest) == 2 && rest[0] == "-rev":
		return Route{Kind: RouteRev, Name: n}, nil
	case len(rest) == 2 && rest[0] == "-":
		file, err := url.PathUnescape(rest[1])
		if err != nil || !strings.HasSuffix(file, ".tgz") || strings.Contains(file, "/") {
			return Route{}, errNoRoute
		}
		return Route{Kind: RouteTarball, Name: n, File: file}, nil
	case len(rest) == 4 && rest[0] == "-" && rest[2] == "-rev":
		return Route{Kind: RouteRev, Name: n}, nil
	}
	return Route{}, errNoRoute
}
