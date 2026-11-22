package goproxy

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

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

// FuzzTagVersion: no panic; a returned version is the rest of the tag after
// the prefix, canonical, not a pseudo-version, and of the requested major.
func FuzzTagVersion(f *testing.F) {
	for _, s := range [][3]string{
		{"v1.2.3", "", ""}, {"tools/v1.0.0", "tools/", ""}, {"v2.0.0", "", "/v2"},
		{"v0.0.0-20260101000000-abcdefabcdef", "", ""}, {"v1.2.3+meta", "", ""}, {"v2.0.0", "", ".v2"},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, tag, prefix, pathMajor string) {
		v, ok := TagVersion(tag, prefix, pathMajor)
		if !ok {
			return
		}
		if prefix+v != tag || v != semver.Canonical(v) || module.IsPseudoVersion(v) {
			t.Fatalf("TagVersion(%q, %q, %q) = %q", tag, prefix, pathMajor, v)
		}
		if err := module.CheckPathMajor(v, pathMajor); err != nil {
			t.Fatalf("TagVersion(%q, %q, %q) = %q: %v", tag, prefix, pathMajor, v, err)
		}
	})
}

// FuzzFindModule: arbitrary go.mod bytes at d/go.mod and d/v2/go.mod never
// panic, a found go.mod declares the requested path, and the go directive
// and retraction checks accept anything.
func FuzzFindModule(f *testing.F) {
	f.Add([]byte("module github.com/acme/sdk/v2\ngo 1.22\n"), []byte("module github.com/acme/sdk/v2\n"))
	f.Add([]byte("module \"github.com/acme/sdk\"\nretract [v1.0.0, v1.1.0]\n"), []byte(nil))
	f.Add([]byte("module ("), []byte("go banana\n"))
	f.Fuzz(func(t *testing.T, gomod1, gomod2 []byte) {
		files := map[string]string{"sdk/go.mod": string(gomod1)}
		if gomod2 != nil {
			files["sdk/v2/go.mod"] = string(gomod2)
		}
		mod := Module{Path: "github.com/acme/sdk", Dir: "sdk"}
		for _, p := range []string{mod.Path, mod.Path + "/v2"} {
			found, reason, err := findModule(readMap(files), mod, p)
			if _, ok := errors.AsType[*RefusalError](err); ok { // readMap's too-large marker
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			if reason == "" && modfile.ModulePath(found.GoMod) != p {
				t.Fatalf("%s: found %q declaring %q", p, found.Dir, modfile.ModulePath(found.GoMod))
			}
		}
		_ = checkGoDirective(gomod1)
		_ = retracted(gomod1)
	})
}
