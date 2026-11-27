package apt

import "testing"

func TestMatch(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"acme-*", "acme-tool", true}, {"acme-*", "acme", false}, {"*", "anything", true}, {"Acme-*", "acme-tool", false},
		{"Acme-*", "Acme-tool", false}, {"acme", "acme", true}, {"lib*-dev", "libssl-dev", true}, {"lib?", "libx", false},
		{"[a]cme", "acme", false}, {"", "acme", false},
	} {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
