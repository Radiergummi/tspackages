package pypi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// tree is an in-memory repository: path → content.
type tree map[string]string

func (tr tree) read(p string) ([]byte, error) {
	b, ok := tr[p]
	if !ok {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, p)
	}
	return []byte(b), nil
}

func (tr tree) dirs() []string {
	seen := map[string]bool{}
	for p := range tr {
		for d := p; strings.Contains(d, "/"); {
			d = d[:strings.LastIndex(d, "/")]
			seen[d] = true
		}
	}
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

const buildSystem = "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n"

func discover(t *testing.T, tr tree) []Package {
	t.Helper()
	pkgs, err := DiscoverPackages(context.Background(), tr.read, tr.dirs())
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

func TestDiscoverSingle(t *testing.T) {
	pkgs := discover(t, tree{"pyproject.toml": "[project]\nname = \"Acme_Core\"\nversion = \"1.2.0\"\n" + buildSystem})
	if len(pkgs) != 1 || pkgs[0].Dir != "" || pkgs[0].Name != "acme-core" || pkgs[0].Version.String() != "1.2.0" || pkgs[0].Skip != "" {
		t.Fatalf("%+v", pkgs)
	}
	if got := discover(t, tree{"README.md": "x"}); len(got) != 0 {
		t.Fatalf("no pyproject: %+v", got)
	}
}

// Review Focus 4: globs that match directories without a pyproject, nested
// workspaces and excludes.
func TestDiscoverWorkspace(t *testing.T) {
	pkgs := discover(t, tree{
		"pyproject.toml":                      "[project]\nname = \"root\"\nversion = \"0.1.0\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\", \"tools/*\"]\nexclude = [\"packages/legacy\"]\n",
		"packages/core/pyproject.toml":        "[project]\nname = \"acme-core\"\nversion = \"1.0.0\"\n" + buildSystem,
		"packages/api/pyproject.toml":         "[project]\nname = \"acme-api\"\nversion = \"2.0.0\"\n" + buildSystem + "\n[tool.uv.workspace]\nmembers = [\"inner/*\"]\n",
		"packages/api/inner/x/pyproject.toml": "[project]\nname = \"inner\"\nversion = \"1\"\n" + buildSystem,
		"packages/legacy/pyproject.toml":      "[project]\nname = \"legacy\"\nversion = \"1\"\n" + buildSystem,
		"packages/docs/index.md":              "no pyproject here",
		"tools/README.md":                     "x",
	})
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if len(pkgs) != 3 || byName["acme-core"].Dir != "packages/core" || byName["acme-api"].Dir != "packages/api" {
		t.Fatalf("%+v", pkgs)
	}
	root := byName["root"]
	if root.Skip == "" || !strings.Contains(root.Skip, "not a package") {
		t.Fatalf("virtual root (no build-system) not skipped: %+v", root)
	}
	if !slices.Equal(root.Exclude, []string{"packages/api", "packages/core"}) {
		t.Fatalf("root excludes = %v", root.Exclude)
	}
}

func TestSkipReasons(t *testing.T) {
	for want, src := range map[string]string{
		"version is dynamic":            "[project]\nname = \"a\"\ndynamic = [\"version\"]\n" + buildSystem,
		"invalid version":               "[project]\nname = \"a\"\nversion = \"latest\"\n" + buildSystem,
		"not a package":                 "[project]\nname = \"a\"\nversion = \"1\"\n" + buildSystem + "\n[tool.uv]\npackage = false\n",
		"name missing or invalid":       "[project]\nversion = \"1\"\n" + buildSystem,
		"outside the package directory": "[project]\nname = \"a\"\nversion = \"1\"\nreadme = \"../README.md\"\n" + buildSystem,
		"does not exist":                "[project]\nname = \"a\"\nversion = \"1\"\nreadme = \"MISSING.md\"\n" + buildSystem,
	} {
		pkgs := discover(t, tree{"pyproject.toml": src})
		if len(pkgs) != 1 || !strings.Contains(pkgs[0].Skip, want) {
			t.Errorf("%s: %+v", want, pkgs)
		}
	}
	if pkgs := discover(t, tree{"pyproject.toml": "[tool.x]\na = 1\n" + buildSystem}); len(pkgs) != 0 {
		t.Errorf("a root without [project] is not a package: %+v", pkgs)
	}
	// A broken root pyproject.toml is content, reported like other refusals.
	if pkgs := discover(t, tree{"pyproject.toml": "not = toml = at all"}); len(pkgs) != 1 || pkgs[0].Skip != skipBadPyproject {
		t.Errorf("broken root pyproject: %+v", pkgs)
	}
}

// TestDiscoverReadErrors: a file that cannot be read is an error, not a
// refusal; a referenced file that is not a regular file is refused.
func TestDiscoverReadErrors(t *testing.T) {
	src := "[project]\nname = \"a\"\nversion = \"1\"\nreadme = \"README.md\"\n" + buildSystem
	failing := func(fail string, err error) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			if p == fail {
				return nil, err
			}
			return tree{"pyproject.toml": src}.read(p)
		}
	}
	for _, p := range []string{"pyproject.toml", "README.md"} {
		if pkgs, err := DiscoverPackages(context.Background(), failing(p, fmt.Errorf("git cat-file: exit status 128")), nil); err == nil {
			t.Errorf("unreadable %s: %+v", p, pkgs)
		}
	}
	pkgs, err := DiscoverPackages(context.Background(), failing("README.md", fmt.Errorf("%w: README.md", errNotRegular)), nil)
	if err != nil || len(pkgs) != 1 || !strings.Contains(pkgs[0].Skip, "regular file") {
		t.Errorf("symlinked readme: %+v %v", pkgs, err)
	}
	pkgs, err = DiscoverPackages(context.Background(), failing("README.md", fmt.Errorf("x: %w", gitmirror.ErrTooLarge)), nil)
	if err != nil || len(pkgs) != 1 || !strings.Contains(pkgs[0].Skip, "larger than") {
		t.Errorf("large readme: %+v %v", pkgs, err)
	}
}

func TestWritePKGINFO(t *testing.T) {
	tr := tree{
		"pyproject.toml": `[project]
name = "Acme_Core"
version = "1.2.0"
description = "Core library"
readme = "README.md"
requires-python = ">=3.10"
license = "MIT"
keywords = ["a", "b"]
authors = [{name = "Ada", email = "ada@example.com"}]
classifiers = ["Programming Language :: Python :: 3"]
dependencies = ["requests>=2", "rich; python_version >= '3.11'"]
[project.optional-dependencies]
CLI = ["click"]
[project.urls]
Homepage = "https://example.com"
` + buildSystem,
		"README.md": "# Acme\n\nHello.\n",
	}
	pkgs := discover(t, tr)
	out, err := WritePKGINFO(pkgs[0], tr.read)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"Metadata-Version: 2.2\n", "Name: Acme_Core\n", "Version: 1.2.0\n", "Summary: Core library\n",
		"Requires-Python: >=3.10\n", "Requires-Dist: requests>=2\n", "Requires-Dist: rich; python_version >= '3.11'\n",
		"Provides-Extra: cli\n", "Requires-Dist: click; extra == \"cli\"\n", "Keywords: a,b\n",
		"Author-email: Ada <ada@example.com>\n", "Classifier: Programming Language :: Python :: 3\n",
		"Project-URL: Homepage, https://example.com\n", "Description-Content-Type: text/markdown\n",
		"Dynamic: License\n", "Dynamic: License-Expression\n", "Dynamic: License-File\n",
		"\n\n# Acme\n\nHello.\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("PKG-INFO lacks %q:\n%s", want, got)
		}
	}
	m, err := ParseMetadata(out)
	if err != nil || m.Name != "Acme_Core" || len(m.RequiresDist) != 3 {
		t.Fatalf("does not parse back: %+v %v", m, err)
	}
}

func TestWritePKGINFODynamicDependencies(t *testing.T) {
	tr := tree{"pyproject.toml": "[project]\nname = \"a\"\nversion = \"1\"\ndynamic = [\"dependencies\", \"optional-dependencies\"]\n" + buildSystem}
	out, err := WritePKGINFO(discover(t, tr)[0], tr.read)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "Dynamic: Requires-Dist\n") || !strings.Contains(string(out), "Dynamic: Provides-Extra\n") || strings.Contains(string(out), "Requires-Dist:") {
		t.Fatalf("%s", out)
	}
}

// TestWritePKGINFODynamicExtrasOnly: an extra's requirements are
// Requires-Dist lines, so dynamic extras make Requires-Dist dynamic too, or
// resolvers would trust a list missing them.
func TestWritePKGINFODynamicExtrasOnly(t *testing.T) {
	tr := tree{"pyproject.toml": "[project]\nname = \"a\"\nversion = \"1\"\ndependencies = [\"requests\"]\ndynamic = [\"optional-dependencies\"]\n" + buildSystem}
	out, err := WritePKGINFO(discover(t, tr)[0], tr.read)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), "Dynamic: Requires-Dist\n") != 1 || !strings.Contains(string(out), "Dynamic: Provides-Extra\n") {
		t.Fatalf("%s", out)
	}
	m, err := ParseMetadata(out)
	if err != nil {
		t.Fatal(err)
	}
	if staticMetadata(distribution{sdist: true}, m) {
		t.Fatal("metadata with dynamic extras is offered as static")
	}
}

// TestPyprojectShapeLimits: a pyproject.toml whose nesting or key segments
// would make the TOML decoder take time and memory quadratic in its size,
// or one over the size cap, is refused quickly; brackets, braces and dots
// inside strings and comments do not count.
func TestPyprojectShapeLimits(t *testing.T) {
	head := "[project]\nname = \"a\"\nversion = \"1\"\n"
	const n = 10000
	for name, src := range map[string]string{
		"inline tables": head + "x = " + strings.Repeat("{a=", n) + "1" + strings.Repeat("}", n) + "\n",
		"arrays":        head + "x = " + strings.Repeat("[", n) + strings.Repeat("]", n) + "\n",
		"dotted header": head + "[" + strings.Repeat("a.", n) + "a]\n",
		"dotted key":    head + strings.Repeat("a.", n) + "a = 1\n",
		"size":          head + "# " + strings.Repeat("x", 300<<10) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			pkgs, err := DiscoverPackages(context.Background(), tree{"pyproject.toml": src + buildSystem}.read, nil)
			if err != nil || len(pkgs) != 1 || pkgs[0].Skip != skipBadPyproject {
				t.Fatalf("%+v %v", pkgs, err)
			}
			if d := time.Since(start); d > time.Second {
				t.Fatalf("took %v", d)
			}
		})
	}
	quoted := head + "description = \"" + strings.Repeat("[{a.", 200) + "\"\n" +
		"keywords = ['''" + strings.Repeat("{[.", 200) + "''']\n" +
		"# " + strings.Repeat("[{.", 200) + "\n" + buildSystem
	if pkgs := discover(t, tree{"pyproject.toml": quoted}); len(pkgs) != 1 || pkgs[0].Skip != "" {
		t.Fatalf("strings and comments counted: %+v", pkgs)
	}
}

// TestNestedMemberRefused: a workspace member inside another member is
// refused, as uv does; it would otherwise share the outer member's entries.
func TestNestedMemberRefused(t *testing.T) {
	pkgs := discover(t, tree{
		"pyproject.toml":                  "[tool.uv.workspace]\nmembers = [\"packages/*\", \"packages/a/*\"]\n",
		"packages/a/pyproject.toml":       pyproject("acme-a", "1.0.0"),
		"packages/a/inner/pyproject.toml": pyproject("acme-inner", "1.0.0"),
	})
	skips := map[string]string{}
	for _, p := range pkgs {
		skips[p.Dir] = p.Skip
	}
	if skips["packages/a"] != "" || !strings.Contains(skips["packages/a/inner"], "nested") {
		t.Fatalf("packages = %+v", pkgs)
	}
}

// TestWorkspaceGlobLimits: globs and directories past the matching caps
// refuse the commit instead of being matched pairwise.
func TestWorkspaceGlobLimits(t *testing.T) {
	many := "[tool.uv.workspace]\nmembers = [" + strings.Repeat("\"x/*\", ", 1001) + "]\n"
	long := "[tool.uv.workspace]\nmembers = [\"" + strings.Repeat("*a", 2100) + "\"]\n"
	deep := strings.Repeat("d/", 2100) + "p"
	for name, tr := range map[string]tree{
		"many globs": {"pyproject.toml": many, "x/a/pyproject.toml": pyproject("a", "1")},
		"long glob":  {"pyproject.toml": long, "x/a/pyproject.toml": pyproject("a", "1")},
		"long dir":   {"pyproject.toml": "[tool.uv.workspace]\nmembers = [\"*\"]\n", deep + "/pyproject.toml": pyproject("a", "1")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DiscoverPackages(context.Background(), tr.read, tr.dirs()); !errors.Is(err, errWorkspaceTooLarge) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// TestPKGINFOCarriageReturn: a bare "\r" in a field would end the header
// for Python's email parser.
func TestPKGINFOCarriageReturn(t *testing.T) {
	tr := tree{"pyproject.toml": "[project]\nname = \"a\"\nversion = \"1\"\ndescription = \"one\\rLicense: evil\"\n" + buildSystem}
	out, err := WritePKGINFO(discover(t, tr)[0], tr.read)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "\r") || !strings.Contains(string(out), "Summary: one License: evil\n") {
		t.Fatalf("PKG-INFO = %q", out)
	}
}
