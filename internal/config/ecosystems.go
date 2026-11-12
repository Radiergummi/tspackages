package config

import (
	"errors"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/module"

	"github.com/radiergummi/tspackages/internal/gitmirror"
)

// ecosystemRules is what validation knows about one ecosystem.
type ecosystemRules struct {
	types      []string               // allowed source types
	validClaim func(string) bool      // claim grammar
	hint       string                 // claim grammar hint in errors
	overlap    func(a, b string) bool // some name matches both valid claims
	// source checks ecosystem-only keys of one source; earlier are the
	// sources before it, in order.
	source func(s Source, earlier []Source, opts ValidateOptions, add func(format string, a ...any))
}

var ecosystems = map[string]ecosystemRules{
	"composer": {
		types:      []string{"git", "storage", "registry"},
		validClaim: func(c string) bool { return validClaim("composer", c) },
		hint:       `use "*" or "<vendor>/<name>" in lowercase [a-z0-9_.*-]`,
		overlap:    func(a, b string) bool { return claimsOverlap("composer", a, b) },
		source:     composerSource,
	},
	"pypi": {
		types:      []string{"git", "storage", "registry"},
		validClaim: func(c string) bool { return validClaim("pypi", c) },
		hint:       `use "*" or a normalised name pattern of [a-z0-9-] and "*"`,
		overlap:    func(a, b string) bool { return claimsOverlap("pypi", a, b) },
		source:     pypiSource,
	},
	"go": {
		types:      []string{"git", "registry"},
		validClaim: ValidGoPattern,
		hint:       `use "*" or "/"-separated segments of [a-z0-9._~-] and "*"`,
		overlap:    goClaimsOverlap,
		source:     goSource,
	},
}

// SupportedEcosystems returns the ecosystems with validation rules, sorted.
func SupportedEcosystems() []string { return slices.Sorted(maps.Keys(ecosystems)) }

func composerSource(s Source, _ []Source, opts ValidateOptions, add func(string, ...any)) {
	if len(s.Modules) > 0 {
		add("modules is only supported on go git sources")
	}
	if len(s.Tags) > 0 {
		add("tags is only supported on pypi git sources")
	}
	if s.Type == "git" {
		if len(s.Remotes) == 0 {
			add("remotes is required")
		}
		checkRemotes(s, s.Remotes, opts, add)
	}
}

func pypiSource(s Source, _ []Source, opts ValidateOptions, add func(string, ...any)) {
	if len(s.Modules) > 0 {
		add("modules is only supported on go git sources")
	}
	if len(s.Tags) > 0 && s.Type != "git" {
		add("tags is only supported on pypi git sources")
	} else {
		validateTags(s, add)
	}
	switch s.Type {
	case "git":
		if len(s.Remotes) == 0 {
			add("remotes is required")
		}
		checkRemotes(s, s.Remotes, opts, add)
		if len(s.Branches) > 0 {
			add("branches are not supported for pypi (Python indexes have no branch versions)")
		}
	case "registry":
		if u, err := url.Parse(s.URL); s.URL != "" && err == nil && u.Host != "" &&
			!strings.HasSuffix(strings.TrimSuffix(u.Path, "/"), "/simple") {
			add("url %q must point at a simple index (ending in /simple/)", s.URL)
		}
	}
}

// checkRemotes runs the remote checks (RemoteKind, no credentials,
// known_hosts for SSH) on remotes.
func checkRemotes(s Source, remotes []string, opts ValidateOptions, add func(string, ...any)) {
	ssh := false
	for _, r := range remotes {
		kind, err := gitmirror.RemoteKind(r, opts.AllowFileRemotes)
		switch {
		case errors.Is(err, gitmirror.ErrRemoteCredentials):
			add("remote must not contain credentials; use token")
		case err != nil:
			add("unsupported remote scheme in %q (use https:// or ssh)", r)
		case kind == "ssh":
			ssh = true
		}
	}
	if ssh && s.KnownHosts == "" {
		add("known_hosts is required for SSH remotes")
	}
}

// goPublicHosts are the hosts whose claims must name an owner: a claim of a
// whole public host would switch off checksum verification for it on every
// client (git claims become GONOSUMDB).
var goPublicHosts = []string{"github.com", "gitlab.com", "bitbucket.org"}

var goSegmentRe = regexp.MustCompile(`^[a-z0-9._~*-]+$`)

// ValidGoPattern reports whether p is a Go claim or rule: "*", or
// "/"-separated non-empty segments of [a-z0-9._~-] and "*". It is
// goproxy.ValidPattern; config keeps its own copy because it can't import
// goproxy.
func ValidGoPattern(p string) bool {
	if p == "*" {
		return true
	}
	return !slices.ContainsFunc(strings.Split(p, "/"), func(seg string) bool { return !goSegmentRe.MatchString(seg) })
}

// goOpen reports whether segs end in a segment that is exactly "*" after at
// least one other segment; such a pattern matches one or more segments there.
func goOpen(segs []string) bool { return len(segs) > 1 && segs[len(segs)-1] == "*" }

// GoMatch reports whether the lowercased module path matches the valid
// pattern. It is goproxy.Match.
func GoMatch(pattern, p string) bool {
	if pattern == "*" {
		return true
	}
	ps, xs := strings.Split(pattern, "/"), strings.Split(p, "/")
	if goOpen(ps) {
		n := len(ps)
		if len(xs) < n {
			return false
		}
		ps, xs = ps[:n-1], xs[:n-1]
	}
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if ok, err := path.Match(ps[i], xs[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// goClaimsOverlap reports whether some module path matches both valid
// claims.
func goClaimsOverlap(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	ao, bo := goOpen(as), goOpen(bs)
	prefixes := func(n int) bool {
		for i := range n {
			if !globsOverlap(as[i], bs[i]) {
				return false
			}
		}
		return true
	}
	switch {
	case ao && bo:
		return prefixes(min(len(as), len(bs)) - 1)
	case ao:
		return len(bs) >= len(as) && prefixes(len(as)-1)
	case bo:
		return len(as) >= len(bs) && prefixes(len(bs)-1)
	}
	return len(as) == len(bs) && prefixes(len(as))
}

// goGitClaimProblem returns why a git claim or module key would disable
// checksum verification too widely, or "".
func goGitClaimProblem(c string) string {
	segs := strings.Split(c, "/")
	switch {
	case c == "*":
		return "covers every module"
	case strings.Contains(segs[0], "*"):
		return "has a wildcard in the host"
	case slices.Contains(goPublicHosts, segs[0]) && (len(segs) < 2 || strings.Contains(segs[1], "*")):
		return "must name the owner under " + segs[0]
	}
	return ""
}

// GoHostWideClaims returns s's claims that cover one whole host
// ("<host>/*"), for the startup warning.
func GoHostWideClaims(s Source) []string {
	var out []string
	for _, c := range s.Claims {
		if segs := strings.Split(c, "/"); len(segs) == 2 && segs[1] == "*" && ValidGoPattern(c) && goGitClaimProblem(c) == "" {
			out = append(out, c)
		}
	}
	return out
}

func goSource(s Source, earlier []Source, opts ValidateOptions, add func(string, ...any)) {
	if len(s.Tags) > 0 {
		add("tags is only supported on pypi git sources")
	}
	if s.Type == "registry" {
		if u, err := url.Parse("https://sum.golang.org/"); err == nil && !HostAllowed(s.FetchHosts, u) {
			add("fetch_hosts must contain sum.golang.org: the checksum database verifier fetches through this source")
		}
		if len(s.Modules) > 0 {
			add("modules is only supported on go git sources")
		}
		if len(s.Branches) > 0 {
			add("branches is only supported on go git sources")
		}
		return
	}
	if len(s.Remotes) > 0 {
		add("remotes is not used by go sources; list modules")
	}
	if len(s.Claims) == 0 {
		add("claims are required for go git sources")
	}
	if len(s.Modules) == 0 {
		add("modules is required")
	}
	for _, c := range s.Claims {
		if !ValidGoPattern(c) {
			continue // reported as an invalid claim
		}
		if why := goGitClaimProblem(c); why != "" {
			add("claim %q %s; a git claim becomes GONOSUMDB on every client", c, why)
		}
		for _, e := range earlier {
			if e.Type != "registry" {
				continue
			}
			if i := slices.IndexFunc(e.Claims, func(ec string) bool { return ValidGoPattern(ec) && goClaimsOverlap(c, ec) }); i >= 0 {
				add("claim %q overlaps claim %q of earlier registry source %q; list the git source first", c, e.Claims[i], e.Name)
			}
		}
	}
	var remotes []string
	for _, key := range slices.Sorted(maps.Keys(s.Modules)) {
		m := s.Modules[key]
		if !slices.Contains(remotes, m.Remote) {
			remotes = append(remotes, m.Remote)
		}
		if err := module.CheckPath(key); err != nil {
			add("modules: %v", err)
			continue
		}
		if _, major, ok := module.SplitPathVersion(key); !ok || major != "" {
			add("modules: %q must not end in a major-version suffix (/vN or .vN); an entry serves every major version", key)
		}
		if strings.HasPrefix(key, "gopkg.in/") {
			add("modules: %q is not supported (gopkg.in paths use .vN)", key)
		}
		if why := goGitClaimProblem(strings.ToLower(key)); why != "" {
			add("modules: key %q %s", key, why)
		}
		if !slices.ContainsFunc(s.Claims, func(c string) bool { return ValidGoPattern(c) && GoMatch(c, strings.ToLower(key)) }) {
			add("modules: %q is matched by no claim of this source", key)
		}
		if d := m.Dir; d != "" && (path.IsAbs(d) || path.Clean(d) != d || d == ".." || strings.HasPrefix(d, "../")) {
			add("modules: dir %q of %q must be a clean relative path", d, key)
		}
	}
	checkRemotes(s, remotes, opts, add)
}
