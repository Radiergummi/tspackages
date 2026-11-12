package config

import (
	"errors"
	"maps"
	"net/url"
	"slices"
	"strings"

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
}

// SupportedEcosystems returns the ecosystems with validation rules, sorted.
func SupportedEcosystems() []string { return slices.Sorted(maps.Keys(ecosystems)) }

func composerSource(s Source, _ []Source, opts ValidateOptions, add func(string, ...any)) {
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
