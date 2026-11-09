package authz

import (
	"path"
	"testing"
)

func TestAllowed(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
		eco   string
		pkg   string
		act   Action
		want  bool
	}{
		{"star allows write", []Rule{{Write: []string{"*"}}}, "composer", "x/y", Write, true},
		{"star write does not imply read", []Rule{{Write: []string{"*"}}}, "composer", "x/y", Read, false},
		{"pattern read allows match", []Rule{{Read: []string{"composer:matchory/*"}}}, "composer", "matchory/sdk", Read, true},
		{"pattern read denies other", []Rule{{Read: []string{"composer:matchory/*"}}}, "composer", "other/sdk", Read, false},
		{"read does not allow write", []Rule{{Read: []string{"composer:matchory/*"}}}, "composer", "matchory/sdk", Write, false},
		{"other ecosystem denied", []Rule{{Read: []string{"pypi:*"}}}, "composer", "matchory/sdk", Read, false},
		{"rule without colon ignored", []Rule{{Read: []string{"composer"}}}, "composer", "matchory/sdk", Read, false},
		{"no rules denies", nil, "composer", "matchory/sdk", Read, false},
		{"empty ecosystem denied", []Rule{{Read: []string{"*"}}}, "", "x/y", Read, false},
		{"empty name denied", []Rule{{Read: []string{"*"}}}, "composer", "", Read, false},
		{"second rule matches", []Rule{{}, {Read: []string{"composer:a/*"}}}, "composer", "a/b", Read, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Allowed(tt.rules, tt.eco, tt.pkg, tt.act, match); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func match(pattern, name string) bool {
	ok, _ := path.Match(pattern, name)
	return ok
}
