package config

import (
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func goCfg(sources ...Source) *Config {
	return &Config{Ecosystems: map[string]Ecosystem{"go": {Sources: sources}}}
}

func goGit(claims []string, modules map[string]GoModule) Source {
	return Source{
		Name: "acme", Type: "git", Claims: claims, Modules: modules,
		MetadataTTL: 1, PollInterval: 1,
	}
}

func goReg(name string, claims ...string) Source {
	return Source{
		Name: name, Type: "registry", Claims: claims, URL: "https://proxy.golang.org",
		FetchHosts: []string{"proxy.golang.org", "sum.golang.org"},
	}
}

// goErrs returns the go ecosystem's validation errors.
func goErrs(t *testing.T, sources ...Source) string {
	t.Helper()
	var out []string
	if err := ValidateWith(goCfg(sources...), ValidateOptions{}); err != nil {
		for m := range strings.SplitSeq(err.Error(), "\n") {
			if strings.HasPrefix(m, "go") {
				out = append(out, m)
			}
		}
	}
	return strings.Join(out, "\n")
}

func mods(kv ...string) map[string]GoModule {
	m := map[string]GoModule{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = GoModule{Remote: kv[i+1]}
	}
	return m
}

func TestGoModulesYAML(t *testing.T) {
	var got map[string]GoModule
	in := "a/x: https://h/x.git\nb/y: {remote: https://h/y.git, dir: tools}\n"
	if err := yaml.Unmarshal([]byte(in), &got); err != nil {
		t.Fatal(err)
	}
	if got["a/x"] != (GoModule{Remote: "https://h/x.git"}) || got["b/y"] != (GoModule{Remote: "https://h/y.git", Dir: "tools"}) {
		t.Fatalf("got %+v", got)
	}
	err := yaml.Unmarshal([]byte("b/y: {remote: x, dir: tools, extra: 1}\n"), &got)
	if err == nil || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("err = %v", err)
	}
	if err := yaml.Unmarshal([]byte("b/y: [x]\n"), &got); err == nil {
		t.Fatal("sequence accepted")
	}
}

func TestGoClaims(t *testing.T) {
	for _, c := range []string{"*", "github.com/acme", "github.com/acme/*", "go.acme.dev/*", "github.com/acme/x~y"} {
		if !ValidGoPattern(c) {
			t.Errorf("%q rejected", c)
		}
	}
	for _, c := range []string{"GitHub.com/acme", "github.com//x", "github.com/acme/", "github.com/[a]", "github.com/a?", ""} {
		if ValidGoPattern(c) {
			t.Errorf("%q accepted", c)
		}
	}
}

func TestGoGitClaimRestrictions(t *testing.T) {
	for _, tc := range []struct{ claim, key, reason string }{
		{"*", "github.com/acme/x", "covers every module"},
		{"*.com/x", "a.com/x", "has a wildcard in the host"},
		{"github.com", "github.com", "must name the owner under github.com"},
		{"github.com/*", "github.com/acme/x", "must name the owner under github.com"},
		{"github.com/ac*", "github.com/acme", "must name the owner under github.com"},
		{"gitlab.com/*", "gitlab.com/acme/x", "must name the owner under gitlab.com"},
		{"bitbucket.org/x*", "bitbucket.org/xy", "must name the owner under bitbucket.org"},
	} {
		got := goErrs(t, goGit([]string{tc.claim}, mods(tc.key, "https://h/x.git")))
		if !strings.Contains(got, "claim "+strconv.Quote(tc.claim)+" "+tc.reason) {
			t.Errorf("claim %q: errors %q", tc.claim, got)
		}
		if strings.Contains(got, "matched by no claim") {
			t.Errorf("claim %q: fixture key %q is unclaimed: %q", tc.claim, tc.key, got)
		}
	}
	got := goErrs(t, goGit([]string{"github.com/acme/*"}, mods("github.com/x*", "https://github.com/x.git")))
	if !strings.Contains(got, "github.com/x*") {
		t.Errorf("key: %q", got)
	}
	for _, c := range []string{"github.com/acme/*", "go.acme.dev/*"} {
		if got := goErrs(t, goGit([]string{c}, mods(strings.TrimSuffix(c, "*")+"x", "https://h/x.git"))); got != "" {
			t.Errorf("claim %q: %q", c, got)
		}
	}
	s := goGit([]string{"go.acme.dev/*", "github.com/acme/*", "go.acme.dev/a/*"}, nil)
	if got := GoHostWideClaims(s); len(got) != 1 || got[0] != "go.acme.dev/*" {
		t.Errorf("GoHostWideClaims = %v", got)
	}
}

func TestGoMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"github.com/acme/*", "github.com/acme/x", true},
		{"github.com/acme/*", "github.com/acme/x/v2", true},
		{"github.com/acme/*", "github.com/acme", false},
		{"github.com/ac*/x", "github.com/acme/x", true},
		{"github.com/ac*/x", "github.com/ac/me/x", false},
		{"*", "a/b/c", true},
		{"github.com/acme", "github.com/acme", true},
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v2", true},
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v10", true},
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v1", false},
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v2x", false},
		{"go.acme.dev/sdk", "go.acme.dev/sdkv2", false},
		{"go.acme.dev/sdk", "go.acme.dev/sdk/v2/x", false},
		{"go.acme.dev/*", "go.acme.dev/x/v2", true},
		{"gopkg.in/yaml", "gopkg.in/yaml.v3", false},
	} {
		if got := GoMatch(tc.pattern, tc.path); got != tc.want {
			t.Errorf("GoMatch(%q, %q) = %v", tc.pattern, tc.path, got)
		}
	}
}

func TestGoClaimsOverlap(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"github.com/acme/*", "github.com/acme/x/v2", true},
		{"github.com/acme", "github.com/acme/*", false},
		{"github.com/a*/x", "github.com/*", true},
		{"a/b/*", "a/*", true},
		{"a/b", "a/c", false},
		{"*", "a/b", true},
	} {
		if got := goClaimsOverlap(tc.a, tc.b); got != tc.want {
			t.Errorf("goClaimsOverlap(%q, %q) = %v", tc.a, tc.b, got)
		}
		if got := goClaimsOverlap(tc.b, tc.a); got != tc.want {
			t.Errorf("goClaimsOverlap(%q, %q) = %v", tc.b, tc.a, got)
		}
	}
}

func TestGoModuleKeys(t *testing.T) {
	claims := []string{"github.com/acme/*", "gopkg.in/*"}
	const remote = "https://github.com/acme/x.git"
	bad := map[string]Source{
		"major suffix": goGit(claims, mods("github.com/acme/sdk/v2", remote)),
		"gopkg.in":     goGit([]string{"github.com/acme/*"}, mods("gopkg.in/yaml.v3", remote)),
		"unclaimed":    goGit(claims, mods("github.com/other/x", remote)),
		"dir ..":       goGit(claims, map[string]GoModule{"github.com/acme/x": {Remote: remote, Dir: "../x"}}),
		"dir abs":      goGit(claims, map[string]GoModule{"github.com/acme/x": {Remote: remote, Dir: "/x"}}),
		"credentials":  goGit(claims, mods("github.com/acme/x", "https://u:p@github.com/acme/x.git")),
		"ssh":          goGit(claims, mods("github.com/acme/x", "git@github.com:acme/x.git")),
		"remotes set": func() Source {
			s := goGit(claims, mods("github.com/acme/x", remote))
			s.Remotes = []string{remote}
			return s
		}(),
		"no modules": goGit(claims, nil),
		"no claims":  goGit(nil, mods("github.com/acme/x", remote)),
		"tags": func() Source {
			s := goGit(claims, mods("github.com/acme/x", remote))
			s.Tags = map[string]map[string][]string{remote: {"v*": {"*"}}}
			return s
		}(),
	}
	for name, s := range bad {
		if goErrs(t, s) == "" {
			t.Errorf("%s: no error", name)
		}
	}
	if got := goErrs(t, goGit([]string{"github.com/acme/*"}, mods("github.com/Acme/SDK", remote))); got != "" {
		t.Errorf("mixed case key: %q", got)
	}
}

func TestGoRegistryBeforeGit(t *testing.T) {
	g := goGit([]string{"github.com/acme/*"}, mods("github.com/acme/x", "https://github.com/acme/x.git"))
	got := goErrs(t, goReg("proxy", "github.com/acme/*"), g)
	if !strings.Contains(got, `overlaps claim "github.com/acme/*" of earlier registry source "proxy"; list the git source first`) {
		t.Errorf("registry first: %q", got)
	}
	if got := goErrs(t, goReg("star", "*"), g); !strings.Contains(got, "earlier registry source") {
		t.Errorf("star registry first: %q", got)
	}
	if got := goErrs(t, g, goReg("proxy", "github.com/acme/*")); got != "" {
		t.Errorf("git first: %q", got)
	}
	if got := goErrs(t, goReg("proxy"), g); got != "" {
		t.Errorf("unclaimed registry first: %q", got)
	}
}

func TestGoRegistryNeedsSumDBHost(t *testing.T) {
	r := goReg("proxy")
	r.FetchHosts = []string{"proxy.golang.org"}
	if got := goErrs(t, r); !strings.Contains(got, "sum.golang.org") {
		t.Errorf("errors = %q", got)
	}
	r = goReg("proxy")
	r.Modules = mods("a/b", "x")
	r.Branches = []string{"main"}
	r.Tags = map[string]map[string][]string{"x": {}}
	r.Tags["x"]["v*"] = []string{"*"}
	for _, key := range []string{"modules", "branches", "tags"} {
		if got := goErrs(t, r); !strings.Contains(got, key) {
			t.Errorf("%s not rejected: %q", key, got)
		}
	}
}

func TestModulesRejectedOutsideGo(t *testing.T) {
	for _, eco := range []string{"composer", "pypi"} {
		s := Source{Name: "g", Type: "git", Claims: []string{"*"}, Remotes: []string{"https://h/x.git"}, Modules: mods("a/b", "x")}
		err := ValidateWith(&Config{Ecosystems: map[string]Ecosystem{eco: {Sources: []Source{s}}}}, ValidateOptions{})
		if err == nil || !strings.Contains(err.Error(), "modules is only supported on go git sources") {
			t.Errorf("%s: %v", eco, err)
		}
	}
}
