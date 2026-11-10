package composer

import (
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/storage"
)

// A normalised name is a fixed point and a valid storage key.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"Matchory/SDK-php", "a/b", "vendor/pkg--name", "a/../b", "matchory/Kit", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		n, err := Normalize(name)
		if err != nil {
			return
		}
		if again, err := Normalize(n); err != nil || again != n {
			t.Fatalf("Normalize(%q) = %q, then %q, %v", name, n, again, err)
		}
		if err := storage.ValidKey("composer/" + n); err != nil {
			t.Fatalf("Normalize(%q) = %q is not a valid key: %v", name, n, err)
		}
	})
}

// A normalised version normalises to itself, as composer/semver's does.
func FuzzNormalizeVersion(f *testing.F) {
	for _, s := range []string{"1.0.0", "v1.0.0-rc1", "1.0.0RC1dev", "1.x-dev", "dev-main", "20100102.203040", "1.0.0-RC0", " 1.0 "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		n, err := NormalizeVersion(v)
		if err != nil {
			return
		}
		if again, err := NormalizeVersion(n); err != nil || again != n {
			t.Fatalf("NormalizeVersion(%q) = %q, then %q, %v", v, n, again, err)
		}
	})
}

// Match never accepts a name for a pattern outside the grammar, and a valid
// pattern without "*" matches only its own name.
func FuzzMatch(f *testing.F) {
	for _, s := range [][2]string{{"a/*", "a/b"}, {"a/[b]", "a/b"}, {"A/B", "a/b"}, {"*", "x"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		ok := Match(pattern, name)
		if ok && pattern != "*" && !ValidPattern(pattern) {
			t.Fatalf("invalid pattern %q matched %q", pattern, name)
		}
		if ValidPattern(pattern) && !strings.Contains(pattern, "*") && ok != strings.EqualFold(pattern, name) {
			t.Fatalf("Match(%q, %q) = %v", pattern, name, ok)
		}
	})
}
