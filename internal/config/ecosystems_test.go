package config

import (
	"slices"
	"strings"
	"testing"
)

func TestEveryEcosystemHasRules(t *testing.T) {
	if got := SupportedEcosystems(); !slices.Equal(got, []string{"composer", "go", "npm", "pypi"}) {
		t.Fatalf("SupportedEcosystems = %v", got)
	}
	for name, r := range ecosystems {
		want := []string{"git", "storage", "registry"}
		if name == "go" {
			want = []string{"git", "registry"} // Go hosts nothing: no uploads
		}
		if name == "npm" {
			want = []string{"registry", "storage"} // npm has no git source
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

func npmCfg(sources ...Source) *Config {
	return &Config{
		Storage:    Storage{Stores: map[string]StoreConfig{"hosted": {Driver: "fs", Path: "/tmp/x"}}},
		Ecosystems: map[string]Ecosystem{"npm": {Sources: sources}},
	}
}

func npmStore(name string, claims ...string) Source {
	return Source{Name: name, Type: "storage", Store: "hosted", Claims: claims}
}

func npmReg(url string, claims ...string) Source {
	return Source{Name: "npmjs", Type: "registry", URL: url, FetchHosts: []string{"registry.npmjs.org"}, Claims: claims}
}

func npmErrs(sources ...Source) string {
	err := ValidateWith(npmCfg(sources...), ValidateOptions{})
	if err == nil {
		return ""
	}
	var out []string
	for m := range strings.SplitSeq(err.Error(), "\n") {
		if strings.HasPrefix(m, "npm") {
			out = append(out, m)
		}
	}
	return strings.Join(out, "\n")
}

func TestNPMClaims(t *testing.T) {
	for _, c := range []string{"*", "@matchory/*", "@m*/x", "left-pad", "a.b_c", "@a/b"} {
		if got := npmErrs(npmStore("own", c)); got != "" {
			t.Errorf("claim %q rejected: %s", c, got)
		}
	}
	for _, c := range []string{"@Matchory/*", "@/x", "a/b", "@a/b/c", "a!", "@a", "", "@a/", "[a]", "a?"} {
		if got := npmErrs(npmStore("own", c)); !strings.Contains(got, "invalid claim") {
			t.Errorf("claim %q accepted: %q", c, got)
		}
	}
}

func TestNPMOverlap(t *testing.T) {
	ok := func(name string, sources ...Source) {
		t.Helper()
		if got := npmErrs(sources...); got != "" {
			t.Errorf("%s: %s", name, got)
		}
	}
	ok("storage before unclaimed registry", npmStore("own", "@matchory/*"), npmReg("https://registry.npmjs.org/"))
	ok("scoped vs unscoped", npmStore("a", "foo*"), npmStore("b", "@foo/*"))
	ok("disjoint scopes", npmStore("a", "@a/*"), npmStore("b", "@b/*"))
	for name, sources := range map[string][]Source{
		"scope globs":   {npmStore("a", "@match*/*"), npmStore("b", "@matchory/*")},
		"star":          {npmReg("https://registry.npmjs.org/", "*"), npmStore("b", "@matchory/x")},
		"unscoped":      {npmStore("a", "foo*"), npmStore("b", "*bar")},
		"scoped inside": {npmStore("a", "@m*/x"), npmStore("b", "@matchory/*")},
	} {
		if got := npmErrs(sources...); !strings.Contains(got, "overlaps claim") {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestNPMSourceKeys(t *testing.T) {
	if got := npmErrs(npmReg("https://registry.npmjs.org")); !strings.Contains(got, "trailing") {
		t.Errorf("registry url without slash: %q", got)
	}
	if got := npmErrs(npmReg("https://registry.npmjs.org/")); got != "" {
		t.Errorf("registry url with slash: %q", got)
	}
	for name, mod := range map[string]func(*Source){
		"remotes":  func(s *Source) { s.Remotes = []string{"https://x/y.git"} },
		"branches": func(s *Source) { s.Branches = []string{"main"} },
		"tags":     func(s *Source) { s.Tags = map[string]map[string][]string{"r": {"a": {"v*"}}} },
		"modules":  func(s *Source) { s.Modules = map[string]GoModule{"a": {Remote: "r"}} },
	} {
		s := npmStore("own", "@a/*")
		mod(&s)
		if got := npmErrs(s); !strings.Contains(got, name) {
			t.Errorf("%s: %q", name, got)
		}
	}
	g := Source{Name: "g", Type: "git", Claims: []string{"@a/*"}, Remotes: []string{"https://x/y.git"}}
	if got := npmErrs(g); !strings.Contains(got, `type "git" is not supported for npm`) {
		t.Errorf("git: %q", got)
	}
}
