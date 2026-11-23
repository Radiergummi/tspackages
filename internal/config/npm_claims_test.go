package config_test

import (
	"testing"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/npm"
)

// TestNPMClaimGrammarMatchesNPM keeps the npm claim grammar here and in
// package npm in step: config cannot import npm, so each has its own copy.
func TestNPMClaimGrammarMatchesNPM(t *testing.T) {
	for _, p := range []string{
		"*", "**", "pkg", "left-pad", "a.b_c~d", "a~b", "p*", "*-utils", "@s/x", "@s/*", "@*/x", "@*/*", "@s*/x*",
		"PKG", "@S/x", "@s/X", "@/x", "@s/", "@s", "@", "a/b", "@a/b/c", "a!", "@s/x!", "", "/", "@s//x",
		"a b", "a?", "a[b]", "@s/x/", "-", ".", "_",
	} {
		if got, want := config.ValidClaim("npm", p), npm.ValidPattern(p); got != want {
			t.Errorf("%q: config accepts %v, npm accepts %v", p, got, want)
		}
	}
}
