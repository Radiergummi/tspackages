package composer

import (
	"slices"
	"testing"

	"github.com/radiergummi/tspackages/internal/authz"
)

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		"Matchory/SDK-php":    "matchory/sdk-php",
		"a/b":                 "a/b",
		"foo.bar/baz_qux":     "foo.bar/baz_qux",
		"vendor/pkg--name":    "vendor/pkg--name",
		"matchory-internal/x": "matchory-internal/x",
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"matchory", "matchory/../x", "", "/x", "x/", "a/b/c", "a b/c", "-a/b", "a/b-", "a//b", "a/b---c", "a__b/c", "a/.b", "a/b..c", "matchory/\u212Ait", "m\u00e4/x"} {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want error", in, got)
		}
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "any/thing", true},
		{"*", "", true},
		{"matchory/*", "Matchory/Foo", true},
		{"Matchory/*", "matchory/foo", true},
		{"matchory/*", "other/foo", false},
		{"matchory/foo", "matchory/foo", true},
		{"matchory-*/*", "matchory-internal/x", true},
		{"[", "a/b", false},
		// Only "*" is special; other path.Match syntax never matches.
		{"a/?", "a/b", false},
		{"a/[b]", "a/b", false},
		{`a/\b`, "a/b", false},
		{"a", "a", false},
		{"a/b/c", "a/b/c", false},
		{"\u212A/x", "k/x", false},
	}
	for _, tc := range tests {
		if got := Match(tc.pattern, tc.name); got != tc.want {
			t.Errorf("Match(%q,%q) = %v", tc.pattern, tc.name, got)
		}
	}
}

func TestMalformedRules(t *testing.T) {
	rules := []authz.Rule{{
		Read:  []string{"*", "composer:a/*", "composer:A/B", "composer", "composer:a/[b]", "pypi:anything?"},
		Write: []string{"composer:*", "composer:a/b/c", ":a/b"},
	}}
	got := malformedRules(rules)
	want := []string{"composer", "composer:a/[b]", "composer:a/b/c", ":a/b"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
