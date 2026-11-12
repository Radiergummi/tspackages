package goproxy

import (
	"bytes"
	"errors"
	"fmt"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/resolve"
)

func TestTagVersion(t *testing.T) {
	for _, c := range []struct {
		tag, prefix, major string
		want               string
		ok                 bool
	}{
		{"v1.2.3", "", "", "v1.2.3", true},
		{"tools/v1.0.0", "tools/", "", "v1.0.0", true},
		{"v1.2", "", "", "", false},
		{"1.2.3", "", "", "", false},
		{"v1.2.3+meta", "", "", "", false},
		{"v0.0.0-20260101000000-abcdefabcdef", "", "", "", false},
		{"v2.0.0", "", "", "", false},
		{"v2.0.0", "", "/v2", "v2.0.0", true},
		{"v1.0.0", "", "/v2", "", false},
		{"tools/v1.0.0", "", "", "", false},
		{"tools/", "tools/", "", "", false},
		{"v1.0.0-rc.1", "", "", "v1.0.0-rc.1", true},
		{"v3.1.0", "", "/v2", "", false},
	} {
		got, ok := TagVersion(c.tag, c.prefix, c.major)
		if got != c.want || ok != c.ok {
			t.Errorf("TagVersion(%q, %q, %q) = %q, %v; want %q, %v", c.tag, c.prefix, c.major, got, ok, c.want, c.ok)
		}
	}
}

// readMap returns a read func over files: a missing name is
// resolve.ErrNotFound, a nil value gitmirror.ErrTooLarge.
func readMap(files map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		s, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("read %s: %w", name, resolve.ErrNotFound)
		}
		if s == "\x00too-large" {
			return nil, fmt.Errorf("read %s: %w", name, gitmirror.ErrTooLarge)
		}
		return []byte(s), nil
	}
}

func TestFindModule(t *testing.T) {
	const tooLarge = "\x00too-large"
	sdk := Module{Path: "github.com/acme/sdk", Remote: "https://example.test/sdk.git"}
	tools := Module{Path: "github.com/acme/mono/tools", Remote: "https://example.test/mono.git", Dir: "tools"}
	for _, c := range []struct {
		name    string
		mod     Module
		path    string
		files   map[string]string
		dir     string // Found.Dir, also with a reason
		gomod   string // Found.GoMod on success
		reason  string
		refusal string // a *RefusalError's reason
	}{
		{
			name: "root", mod: sdk, path: "github.com/acme/sdk",
			files: map[string]string{"go.mod": "module github.com/acme/sdk\n"},
			gomod: "module github.com/acme/sdk\n",
		},
		{
			name: "dir", mod: tools, path: "github.com/acme/mono/tools",
			files: map[string]string{"tools/go.mod": "module github.com/acme/mono/tools\n", "go.mod": "module github.com/acme/mono\n"},
			dir:   "tools", gomod: "module github.com/acme/mono/tools\n",
		},
		{
			name: "v2 branch style", mod: sdk, path: "github.com/acme/sdk/v2",
			files: map[string]string{"go.mod": "module github.com/acme/sdk/v2\n"},
			gomod: "module github.com/acme/sdk/v2\n",
		},
		{
			name: "v2 branch style in dir", mod: tools, path: "github.com/acme/mono/tools/v2",
			files: map[string]string{"tools/go.mod": "module github.com/acme/mono/tools/v2\n"},
			dir:   "tools", gomod: "module github.com/acme/mono/tools/v2\n",
		},
		{
			name: "v2 subdirectory style", mod: sdk, path: "github.com/acme/sdk/v2",
			files: map[string]string{"go.mod": "module github.com/acme/sdk\n", "v2/go.mod": "module github.com/acme/sdk/v2\n"},
			dir:   "v2", gomod: "module github.com/acme/sdk/v2\n",
		},
		{
			name: "v2 subdirectory style in dir", mod: tools, path: "github.com/acme/mono/tools/v2",
			files: map[string]string{"tools/v2/go.mod": "module github.com/acme/mono/tools/v2\n"},
			dir:   "tools/v2", gomod: "module github.com/acme/mono/tools/v2\n",
		},
		{
			name: "both styles", mod: tools, path: "github.com/acme/mono/tools/v2",
			files: map[string]string{
				"tools/go.mod":    "module github.com/acme/mono/tools/v2\n",
				"tools/v2/go.mod": "module github.com/acme/mono/tools/v2\n",
			},
			dir: "tools", reason: "go.mod found in both tools and tools/v2",
		},
		{
			name: "both styles at the root", mod: sdk, path: "github.com/acme/sdk/v2",
			files:  map[string]string{"go.mod": "module github.com/acme/sdk/v2\n", "v2/go.mod": "module github.com/acme/sdk/v2\n"},
			reason: "go.mod found in both . and ./v2",
		},
		{
			name: "no go.mod", mod: sdk, path: "github.com/acme/sdk",
			files:  map[string]string{"main.go": "package main\n"},
			reason: "no go.mod",
		},
		{
			name: "no go.mod for v2", mod: sdk, path: "github.com/acme/sdk/v2",
			files:  map[string]string{},
			reason: "no go.mod",
		},
		{
			name: "other path", mod: sdk, path: "github.com/acme/sdk",
			files:  map[string]string{"go.mod": "module github.com/acme/other\n"},
			reason: "module declares its path as github.com/acme/other",
		},
		{
			name: "other case", mod: sdk, path: "github.com/acme/sdk",
			files:  map[string]string{"go.mod": "module github.com/ACME/sdk\n"},
			reason: "module declares its path as github.com/ACME/sdk",
		},
		{
			name: "v2 path requested as v1", mod: sdk, path: "github.com/acme/sdk",
			files:  map[string]string{"go.mod": "module github.com/acme/sdk/v2\n"},
			reason: "module declares its path as github.com/acme/sdk/v2",
		},
		{
			name: "other path at v2", mod: sdk, path: "github.com/acme/sdk/v2",
			files:  map[string]string{"go.mod": "module github.com/acme/other/v2\n"},
			reason: "module declares its path as github.com/acme/other/v2",
		},
		{
			name: "v2 subdirectory declares wrong major", mod: sdk, path: "github.com/acme/sdk/v2",
			files:  map[string]string{"go.mod": "module github.com/acme/sdk/v2\n", "v2/go.mod": "module github.com/acme/sdk/v3\n"},
			dir:    "v2",
			reason: "module declares its path as github.com/acme/sdk/v3",
		},
		{
			name: "no module line", mod: sdk, path: "github.com/acme/sdk",
			files:  map[string]string{"go.mod": "go 1.22\n"},
			reason: `module declares its path as ""`,
		},
		{
			name: "major version not in the module path", mod: sdk, path: "github.com/acme/sdk/v2",
			files:  map[string]string{"go.mod": "module github.com/acme/sdk\n"},
			reason: "major version not in the module path",
		},
		{
			name: "v3 declared for v2", mod: sdk, path: "github.com/acme/sdk/v2",
			files:  map[string]string{"go.mod": "module github.com/acme/sdk/v3\n"},
			reason: "module declares its path as github.com/acme/sdk/v3",
		},
		{
			name: "too large", mod: sdk, path: "github.com/acme/sdk",
			files:   map[string]string{"go.mod": tooLarge},
			refusal: "go.mod over 16 MiB",
		},
		{
			name: "too large in the v2 subdirectory", mod: tools, path: "github.com/acme/mono/tools/v2",
			files:   map[string]string{"tools/go.mod": "module github.com/acme/mono/tools/v2\n", "tools/v2/go.mod": tooLarge},
			dir:     "tools/v2",
			refusal: "go.mod over 16 MiB",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, reason, err := findModule(readMap(c.files), c.mod, c.path)
			if c.refusal != "" {
				var re *RefusalError
				if !errors.As(err, &re) || re.Reason != c.refusal {
					t.Fatalf("err = %v; want refusal %q", err, c.refusal)
				}
				if f.Dir != c.dir {
					t.Errorf("Dir = %q; want %q", f.Dir, c.dir)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if reason != c.reason {
				t.Fatalf("reason = %q; want %q", reason, c.reason)
			}
			if f.Dir != c.dir {
				t.Errorf("Dir = %q; want %q", f.Dir, c.dir)
			}
			if reason == "" && string(f.GoMod) != c.gomod {
				t.Errorf("GoMod = %q; want %q", f.GoMod, c.gomod)
			}
			if reason != "" && f.GoMod != nil {
				t.Errorf("GoMod = %q with a reason; want nil", f.GoMod)
			}
		})
	}
}

func TestFindModuleIOError(t *testing.T) {
	boom := errors.New("boom")
	read := func(string) ([]byte, error) { return nil, boom }
	_, reason, err := findModule(read, Module{Path: "github.com/acme/sdk"}, "github.com/acme/sdk/v2")
	var re *RefusalError
	if !errors.Is(err, boom) || errors.As(err, &re) || reason != "" {
		t.Fatalf("reason %q, err %v; want the read error", reason, err)
	}
}

func TestFindModuleWrongModule(t *testing.T) {
	for _, p := range []string{"github.com/acme/other", "github.com/acme/sdk/v1", "github.com/acme/sdkv2", "github.com/acme/sdk/x"} {
		_, _, err := findModule(readMap(nil), Module{Path: "github.com/acme/sdk"}, p)
		if err == nil {
			t.Errorf("%s: no error", p)
		}
	}
}

func TestCheckGoDirective(t *testing.T) {
	for _, c := range []struct{ gomod, want string }{
		{"module m\ngo 1.27.4\n", ""},
		{"module m\ngo 1.27\n", ""},
		{"module m\ngo 1.21.0\n", ""},
		{"module m\n", ""},
		{"module m\ngo 1.27.5\n", "go 1.27.5 is newer than go1.27.4; upgrade tspackages"},
		{"module m\ngo 1.28rc1\n", "go 1.28rc1 is newer than go1.27.4; upgrade tspackages"},
		{"module m\ngo banana\n", "unparseable go directive banana"},
		{"module m\ngo 1.21.0rc1\n", "unparseable go directive 1.21.0rc1"}, // ParseLax accepts it, go/version does not
		{"module m\ngo 1.27 // comment\ngo 1.2\n", "unparseable go.mod: "},
		{"module m\ngo 1.2.3.4\n", ""},                                                    // ParseLax reads it as 1.2, as the go command does
		{"module m\ngo 1.99.0-x\n", "go 1.99 is newer than go1.27.4; upgrade tspackages"}, // likewise 1.99
		{"module m\n)(\n", "unparseable go.mod: "},
	} {
		got := checkGoDirective([]byte(c.gomod))
		if strings.HasSuffix(c.want, ": ") && strings.HasPrefix(got, c.want) {
			continue
		}
		if got != c.want {
			t.Errorf("checkGoDirective(%q) = %q; want %q", c.gomod, got, c.want)
		}
	}
}

func TestMaxGoMatchesGoMod(t *testing.T) {
	data, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := "go" + f.Go.Version; got != maxGo {
		t.Fatalf("go.mod says %s; maxGo is %s", got, maxGo)
	}
}

// TestModzipMatchesToolchain keeps the imported x/mod zip package equal to
// the one vendored into the toolchain's cmd/go, apart from comments, so the
// vendoring rules modzip.Create applies are those of the go command at maxGo.
func TestModzipMatchesToolchain(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}
	goOut := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("go", args...).Output()
		if err != nil {
			t.Fatalf("go %s: %v", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out))
	}
	root := goOut("env", "GOROOT")
	mod := goOut("list", "-m", "-f", "{{.Dir}}", "golang.org/x/mod")
	norm := func(file string) string {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, f); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	vendored := norm(filepath.Join(root, "src", "cmd", "vendor", "golang.org", "x", "mod", "zip", "zip.go"))
	imported := norm(filepath.Join(mod, "zip", "zip.go"))
	if vendored != imported {
		t.Fatalf("golang.org/x/mod/zip in %s differs from the toolchain's vendored copy; align the x/mod version with maxGo's toolchain", mod)
	}
}

func TestRetracted(t *testing.T) {
	got := retracted([]byte("module m\nretract [v1.0.0, v1.1.0]\n"))
	if len(got) != 1 || got[0].Low != "v1.0.0" || got[0].High != "v1.1.0" {
		t.Fatalf("retracted = %+v", got)
	}
	if got := retracted([]byte("module m\nretract v1.2.0 // broken\n")); len(got) != 1 || got[0].Low != "v1.2.0" || got[0].High != "v1.2.0" {
		t.Fatalf("single retraction = %+v", got)
	}
	if got := retracted([]byte("module m\nretract [v1.0.0\n")); got != nil {
		t.Fatalf("malformed = %+v; want nil", got)
	}
	if got := retracted([]byte("module m\n")); got != nil {
		t.Fatalf("no retractions = %+v; want nil", got)
	}
}
