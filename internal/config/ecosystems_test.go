package config

import (
	"slices"
	"strings"
	"testing"
)

func TestEveryEcosystemHasRules(t *testing.T) {
	if got := SupportedEcosystems(); !slices.Equal(got, []string{"composer", "go", "pypi"}) {
		t.Fatalf("SupportedEcosystems = %v", got)
	}
	for name, r := range ecosystems {
		want := []string{"git", "storage", "registry"}
		if name == "go" {
			want = []string{"git", "registry"} // Go hosts nothing: no uploads
		}
		for _, typ := range want {
			if !slices.Contains(r.types, typ) {
				t.Errorf("%s: type %s missing", name, typ)
			}
		}
		if r.validClaim == nil || r.overlap == nil || r.source == nil || r.hint == "" {
			t.Errorf("%s: incomplete rules", name)
		}
	}
}

func TestTypeNotListedForEcosystem(t *testing.T) {
	ecosystems["fake"] = ecosystemRules{
		types:      []string{"git"},
		validClaim: func(string) bool { return true },
		hint:       "any",
		overlap:    func(a, b string) bool { return true },
		source:     func(Source, []Source, ValidateOptions, func(string, ...any)) {},
	}
	t.Cleanup(func() { delete(ecosystems, "fake") })

	c := &Config{Ecosystems: map[string]Ecosystem{"fake": {Sources: []Source{
		{Name: "r", Type: "registry", URL: "https://x/", FetchHosts: []string{"x"}},
	}}}}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), `type "registry" is not supported for fake`) {
		t.Fatalf("err = %v", err)
	}
}
