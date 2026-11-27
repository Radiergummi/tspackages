package config_test

import (
	"testing"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/apt"
)

// TestAptClaimGrammarMatchesApt keeps the apt claim grammar here and in
// package apt in step: config cannot import apt, so each has its own copy.
func TestAptClaimGrammarMatchesApt(t *testing.T) {
	for _, p := range []string{
		"*", "**", "acme", "acme-*", "*-dev", "lib+x.y-2", "a*b", "Acme", "Acme-*", "", "a b", "a/b", "a_b", "a:b",
		"[a]", "a?", "-", "+", ".", "acme-*-dev", "libc6", "é", "a\\b", "@a/b",
	} {
		if got, want := config.ValidClaim("apt", p), apt.ValidPattern(p); got != want {
			t.Errorf("%q: config accepts %v, apt accepts %v", p, got, want)
		}
	}
}
