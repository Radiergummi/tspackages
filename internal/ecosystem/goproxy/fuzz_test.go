package goproxy

import (
	"strings"
	"testing"

	"golang.org/x/mod/module"

	"github.com/radiergummi/tspackages/internal/config"
)

// FuzzParseRoute: any input parses without panic, and a parsed route
// re-escapes to the input.
func FuzzParseRoute(f *testing.F) {
	for _, s := range []string{
		"github.com/!acme/x/@v/list", "a.b/c/v2/@v/v2.0.0.info", "a.b/c/@v/v1.0.0-!r!c1.mod",
		"a.b/c/@v/v1.zip", "a.b/c/@latest", "a.b/c/@v/", "a.b/@v/@v/x.info", "sumdb/x/y", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		r, err := ParseRoute(in)
		if err != nil {
			return
		}
		p, err := module.EscapePath(r.Path)
		if err != nil {
			t.Fatalf("%q: path %q does not escape: %v", in, r.Path, err)
		}
		var got string
		switch r.Kind {
		case KindLatest:
			got = p + "/@latest"
		case KindList:
			got = p + "/@v/list"
		default:
			v, err := module.EscapeVersion(r.Version)
			if err != nil {
				t.Fatalf("%q: version %q does not escape: %v", in, r.Version, err)
			}
			got = p + "/@v/" + v + map[Kind]string{KindInfo: ".info", KindMod: ".mod", KindZip: ".zip"}[r.Kind]
		}
		if got != in {
			t.Fatalf("%q parsed to %+v, which re-escapes to %q", in, r, got)
		}
	})
}

// FuzzMatch: Match agrees with config.GoMatch on the lowercased path, and
// ValidPattern with config.ValidGoPattern.
func FuzzMatch(f *testing.F) {
	for _, s := range [][2]string{
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v2"}, {"go.acme.dev/*", "go.acme.dev/x/v2"},
		{"a/b*", "a/b/v10"}, {"*", "x"}, {"a/b", "a/b/v1"}, {"gopkg.in/y", "gopkg.in/y.v3"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, p string) {
		if ValidPattern(pattern) != config.ValidGoPattern(pattern) {
			t.Fatalf("ValidPattern(%q) disagrees with config", pattern)
		}
		if !ValidPattern(pattern) {
			if Match(pattern, p) {
				t.Fatalf("invalid pattern %q matches %q", pattern, p)
			}
			return
		}
		if got, want := Match(pattern, p), config.GoMatch(pattern, strings.ToLower(p)); got != want {
			t.Fatalf("Match(%q, %q) = %v, config says %v", pattern, p, got, want)
		}
	})
}
