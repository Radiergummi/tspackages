package config

import (
	"path"
	"testing"
)

// claimsOverlap must never miss a name that both claims match, or uploads
// to that name would be shadowed without a config error.
func FuzzClaimsOverlap(f *testing.F) {
	for _, s := range [][3]string{{"acme/*", "acme/x", "acme/x"}, {"a*b/c", "*ab/c", "aab/c"}, {"*/x", "acme/*", "acme/x"}, {"matchory-*", "*-core", "matchory-core"}} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, a, b, name string) {
		for _, eco := range []string{"composer", "pypi"} {
			if !validClaim(eco, a) || !validClaim(eco, b) || a == "*" || b == "*" {
				continue
			}
			ma, _ := path.Match(a, name)
			mb, _ := path.Match(b, name)
			if ma && mb && !claimsOverlap(eco, a, b) {
				t.Fatalf("%s: %q and %q both match %q, but claimsOverlap is false", eco, a, b, name)
			}
		}
	})
}
