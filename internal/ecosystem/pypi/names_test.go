package pypi

import "testing"

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"Matchory_Utils": "matchory-utils",
		"a.b--c":         "a-b-c",
		"A":              "a",
		"zope.interface": "zope-interface",
		"foo__Bar.._baz": "foo-bar-baz",
	} {
		if got, err := Normalize(in); err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-bad", "bad-", "a b", "a/b", "ä", ".x"} {
		if got, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) = %q, want error", bad, got)
		}
	}
}

func TestPatterns(t *testing.T) {
	for p, valid := range map[string]bool{"*": true, "matchory-*": true, "foo": true, "*-utils": true, "Matchory-*": false, "a_b": false, "a.b": false, "**": false, "": false, "a/b": false, "acme--internal": false, "-acme": false, "acme-": false, "-*": false, "*-": false, "a-*-b": true, "*-*": true} {
		if ValidPattern(p) != valid {
			t.Errorf("ValidPattern(%q) = %v", p, !valid)
		}
	}
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"matchory-*", "matchory-core", true},
		{"matchory-*", "matchory", false},
		{"*", "anything", true},
		{"foo", "foo", true},
		{"foo", "foo-bar", false},
		{"Matchory-*", "matchory-core", true}, // capability rules are case-insensitive
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v", c.pattern, c.name, got)
		}
	}
}
