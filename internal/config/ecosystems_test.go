package config

import (
	"slices"
	"strings"
	"testing"
)

func TestEveryEcosystemHasRules(t *testing.T) {
	if got := SupportedEcosystems(); !slices.Equal(got, []string{"composer", "go", "maven", "npm", "pypi"}) {
		t.Fatalf("SupportedEcosystems = %v", got)
	}
	for name, r := range ecosystems {
		want := []string{"git", "storage", "registry"}
		if name == "go" {
			want = []string{"git", "registry"} // Go hosts nothing: no uploads
		}
		if name == "maven" {
			want = []string{"registry", "storage"} // Maven has no git source
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

func mavenErrs(sources ...Source) string {
	c := npmCfg(sources...)
	c.Ecosystems = map[string]Ecosystem{"maven": {Sources: sources}}
	err := ValidateWith(c, ValidateOptions{})
	if err == nil {
		return ""
	}
	var out []string
	for m := range strings.SplitSeq(err.Error(), "\n") {
		if strings.HasPrefix(m, "maven") {
			out = append(out, m)
		}
	}
	return strings.Join(out, "\n")
}

func mavenReg(url string, claims ...string) Source {
	return Source{Name: "central", Type: "registry", URL: url, FetchHosts: []string{"repo.maven.apache.org"}, Claims: claims}
}

func TestMavenClaims(t *testing.T) {
	for _, c := range []string{"*", "com.matchory.*", "com.matchory", "com.matchory:lib-*", "com.matchory.*:lib"} {
		if got := mavenErrs(npmStore("own", c)); got != "" {
			t.Errorf("claim %q rejected: %s", c, got)
		}
	}
	for _, c := range []string{"com.Matchory", "*.matchory", "com..x", "com.matchory.*.x", ":a", "*:a", "", "com.matchory:", "com/matchory"} {
		if got := mavenErrs(npmStore("own", c)); !strings.Contains(got, "invalid claim") {
			t.Errorf("claim %q accepted: %q", c, got)
		}
	}
}

func TestMavenOverlap(t *testing.T) {
	ok := func(name string, sources ...Source) {
		t.Helper()
		if got := mavenErrs(sources...); got != "" {
			t.Errorf("%s: %s", name, got)
		}
	}
	ok("exact vs open", npmStore("a", "com.matchory"), npmStore("b", "com.matchory.*"))
	ok("disjoint groups", npmStore("a", "com.a.*"), npmStore("b", "com.b.*"))
	ok("disjoint artifacts", npmStore("a", "com.m:lib-*"), npmStore("b", "com.m:app-*"))
	ok("storage before unclaimed registry", npmStore("own", "com.matchory.*"), mavenReg("https://repo.maven.apache.org/maven2/"))
	for name, sources := range map[string][]Source{
		"open vs exact":     {npmStore("a", "com.matchory.*"), npmStore("b", "com.matchory.x")},
		"open vs open":      {npmStore("a", "com.*"), npmStore("b", "com.matchory.*")},
		"star":              {mavenReg("https://repo.maven.apache.org/maven2/", "*"), npmStore("b", "com.m")},
		"group vs artifact": {npmStore("a", "com.m"), npmStore("b", "com.m:lib")},
		"artifact globs":    {npmStore("a", "com.m:lib-*"), npmStore("b", "com.m:*-core")},
	} {
		if got := mavenErrs(sources...); !strings.Contains(got, "overlaps claim") {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestMavenSourceKeys(t *testing.T) {
	if got := mavenErrs(mavenReg("https://repo.maven.apache.org/maven2")); !strings.Contains(got, "trailing") {
		t.Errorf("registry url without slash: %q", got)
	}
	if got := mavenErrs(mavenReg("https://repo.maven.apache.org/maven2/")); got != "" {
		t.Errorf("registry url with slash: %q", got)
	}
	for name, mod := range map[string]func(*Source){
		"remotes":  func(s *Source) { s.Remotes = []string{"https://x/y.git"} },
		"branches": func(s *Source) { s.Branches = []string{"main"} },
		"tags":     func(s *Source) { s.Tags = map[string]map[string][]string{"r": {"a": {"v*"}}} },
		"modules":  func(s *Source) { s.Modules = map[string]GoModule{"a": {Remote: "r"}} },
	} {
		s := npmStore("own", "com.a.*")
		mod(&s)
		if got := mavenErrs(s); !strings.Contains(got, name) {
			t.Errorf("%s: %q", name, got)
		}
	}
	g := Source{Name: "g", Type: "git", Claims: []string{"com.a.*"}, Remotes: []string{"https://x/y.git"}}
	if got := mavenErrs(g); !strings.Contains(got, `type "git" is not supported for maven`) {
		t.Errorf("git: %q", got)
	}
}
