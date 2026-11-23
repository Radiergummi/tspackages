package maven

import "testing"

func TestValidPattern(t *testing.T) {
	for _, p := range []string{"*", "com.matchory.*", "com.matchory", "com.matchory:lib-*", "a_b-c:x.y_z"} {
		if !ValidPattern(p) {
			t.Errorf("%q rejected", p)
		}
	}
	for _, p := range []string{"", "com.Matchory", "*.matchory", "com..x", "com.matchory.*.x", ":a", "*:a", "com.matchory:", "com/m", "com.m:a:b"} {
		if ValidPattern(p) {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		c       Coords
		want    bool
	}{
		{"com.matchory.*", Coords{"com.matchory.x", "a", "1"}, true},
		{"com.matchory.*", Coords{"com.matchory.x.y", "a", "1"}, true},
		{"com.matchory.*", Coords{"com.matchory", "a", "1"}, false},
		{"com.matchory.*", Coords{"com.matcho", "a", "1"}, false},
		{"com.matchory.*", Coords{"com.matchoryx", "a", "1"}, false},
		{"com.matchory", Coords{"com.matchory", "a", "1"}, true},
		{"com.matchory", Coords{"com.matchory.x", "a", "1"}, false},
		{"com.matchory:lib-*", Coords{"com.matchory", "lib-core", "1"}, true},
		{"com.matchory:lib-*", Coords{"com.matchory", "app", "1"}, false},
		{"com.matchory.*:lib", Coords{"com.matchory.x", "lib", "1"}, true},
		{"com.matchory.*:lib", Coords{"com.matchory.x", "lib2", "1"}, false},
		{"*", Coords{"anything", "at-all", "1"}, true},
		{"Com.Matchory.*", Coords{"com.matchory.x", "a", "1"}, false},
		{"com.matchory.*", Coords{"Com.Matchory.X", "A", "1"}, true},
		{"com.matchory:lib", Coords{"Com.Matchory", "LIB", "1"}, true},
	} {
		if got := Match(tc.pattern, tc.c); got != tc.want {
			t.Errorf("Match(%q, %+v) = %v", tc.pattern, tc.c, got)
		}
	}
}

func TestMatchGroup(t *testing.T) {
	for _, tc := range []struct {
		pattern, group string
		want           bool
	}{
		{"com.matchory.*", "com.matchory.plugins", true},
		{"com.matchory.*", "com.matchory", false},
		{"com.matchory:lib", "com.matchory", true},
		{"com.matchory:lib", "com.matchory.x", false},
		{"com.matchory", "Com.Matchory", true},
		{"*", "x", true},
		{"Com.Matchory", "com.matchory", false},
	} {
		if got := MatchGroup(tc.pattern, tc.group); got != tc.want {
			t.Errorf("MatchGroup(%q, %q) = %v", tc.pattern, tc.group, got)
		}
	}
}
