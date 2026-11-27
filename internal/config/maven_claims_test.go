package config_test

import (
	"testing"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/maven"
)

// TestMavenClaimGrammarMatchesMaven keeps the Maven claim grammar here and in
// package maven in step: config cannot import maven, so each has its own copy.
func TestMavenClaimGrammarMatchesMaven(t *testing.T) {
	for _, p := range []string{
		"*", "**", "com.matchory.*", "com.matchory", "com.matchory:lib-*", "com.matchory.x:a", "com.matchory.*:lib",
		"com.Matchory", "Com.Matchory.*", "*.matchory", "com..x", "com.matchory.*.x", ":a", "*:a", "com.matchory:",
		"", "com.", ".com", "com.*.", "a_b-c", "a_b-c:x.y_z", "com.m:a:b", "com/m", "com.m:a/b", "a b", "a?", "[a]",
		"com.m*", "co*.m", "com.matchory.*:", "*:*", "com:*", "-", "_", ".", "com.*:*",
	} {
		if got, want := config.ValidClaim("maven", p), maven.ValidPattern(p); got != want {
			t.Errorf("%q: config accepts %v, maven accepts %v", p, got, want)
		}
	}
}
