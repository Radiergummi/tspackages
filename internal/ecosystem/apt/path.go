package apt

import (
	"fmt"
	"regexp"
	"strings"
)

// Kind says what a request path addresses.
type Kind int

const (
	KindKey         Kind = iota // key.asc
	KindPreferences             // preferences
	KindRelease                 // <source>/dists/<suite>/{InRelease,Release,Release.gpg}
	KindDist                    // another file below dists/<suite>/
	KindByHash                  // <rel>/by-hash/SHA256/<hash> below dists/<suite>/
	KindPool                    // any other path below the source
	KindUpload                  // PUT <source>/<suite>/<component>/<file>.deb
)

const (
	maxSegments   = 16
	maxSegmentLen = 255
)

var (
	sourceRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Path is a parsed request path below "/apt/".
type Path struct {
	Kind      Kind
	Source    string // all but KindKey, KindPreferences
	Suite     string // KindRelease, KindDist, KindByHash, KindUpload
	Rel       string // KindRelease: "InRelease", "Release" or "Release.gpg"; KindDist, KindByHash: the path below dists/<suite>/; KindPool: the path from the repository root ("pool/...")
	Component string // KindUpload
	Hash      string // KindByHash: lowercase sha256 hex
	Deb       Deb    // KindUpload; KindPool when the base name parses as a Deb file name
}

// ParsePath parses p, the decoded path after "/apt/". put says the request is
// a PUT: then only an upload path parses, otherwise never an upload. An error
// means 404.
func ParsePath(p string, put bool) (Path, error) {
	segs := strings.Split(p, "/")
	if len(segs) > maxSegments {
		return Path{}, errNotFound
	}
	for _, s := range segs {
		if s == "" || s[0] == '.' || len(s) > maxSegmentLen {
			return Path{}, errNotFound
		}
	}
	if len(segs) == 1 && !put {
		switch p {
		case "key.asc":
			return Path{Kind: KindKey}, nil
		case "preferences":
			return Path{Kind: KindPreferences}, nil
		}
	}
	if len(segs) < 2 || !sourceRE.MatchString(segs[0]) {
		return Path{}, errNotFound
	}
	out := Path{Source: segs[0]}
	if put {
		if len(segs) != 4 || !ValidSuite(segs[1]) || !ValidSuite(segs[2]) {
			return Path{}, fmt.Errorf("%w: uploads go to <source>/<suite>/<component>/<file>.deb", errNotFound)
		}
		d, err := ParseFileName(segs[3])
		if err != nil {
			return Path{}, err
		}
		out.Kind, out.Suite, out.Component, out.Deb = KindUpload, segs[1], segs[2], d
		return out, nil
	}
	if segs[1] != "dists" {
		out.Kind, out.Rel = KindPool, strings.Join(segs[1:], "/")
		out.Deb, _ = ParseFileName(segs[len(segs)-1])
		return out, nil
	}
	if len(segs) < 4 || !ValidSuite(segs[2]) {
		return Path{}, errNotFound
	}
	out.Suite = segs[2]
	rest := segs[3:]
	out.Rel = strings.Join(rest, "/")
	switch {
	case len(rest) == 1 && (rest[0] == "InRelease" || rest[0] == "Release" || rest[0] == "Release.gpg"):
		out.Kind = KindRelease
	case len(rest) >= 4 && rest[len(rest)-3] == "by-hash" && rest[len(rest)-2] == "SHA256":
		if !sha256Hex.MatchString(rest[len(rest)-1]) {
			return Path{}, errNotFound
		}
		out.Kind, out.Hash = KindByHash, rest[len(rest)-1]
	default:
		out.Kind = KindDist
	}
	return out, nil
}
