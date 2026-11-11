package pypi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/gitmirror"
)

var update = flag.Bool("update", false, "print new golden digests (changing them requires bumping SdistFormat)")

// gitTar builds what `git archive --format=tar` would emit for files (path →
// content; a "->" prefix makes a symlink).
func gitTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "deadbeef"}})
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range files {
			if !yield(k) {
				return
			}
		}
	}) {
		body := files[name]
		if target, ok := strings.CutPrefix(body, "->"); ok {
			tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777})
			continue
		}
		mode := int64(0o644)
		if strings.HasSuffix(name, ".sh") {
			mode = 0o755
		}
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(body)), ModTime: time.Unix(1700000000, 0)})
		tw.Write([]byte(body))
	}
	tw.Close()
	return buf.Bytes()
}

func entriesOf(t *testing.T, sdist []byte) map[string]*tar.Header {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(sdist))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string]*tar.Header{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = h
	}
}

var basicPkg = func() Package {
	v, _ := ParseVersion("1.2.0")
	return Package{Dir: "packages/core", Name: "acme-core", Version: v}
}()

func basicTar(t *testing.T) []byte {
	return gitTar(t, map[string]string{
		"packages/core/pyproject.toml":            "[project]\nname = \"acme-core\"\n",
		"packages/core/src/acme_core/__init__.py": "",
		"packages/core/run.sh":                    "#!/bin/sh\n",
		"packages/core/link":                      "->src",
		"packages/core/nested/pyproject.toml":     "[project]\n",
	})
}

func TestSdistGolden(t *testing.T) {
	p := basicPkg
	p.Exclude = []string{"packages/core/nested"}
	got, err := BuildSdist(bytes.NewReader(basicTar(t)), p, []byte("Metadata-Version: 2.2\n"), time.Unix(1731300000, 0))
	if err != nil {
		t.Fatal(err)
	}
	const golden = "da366ae383771229ef0671c8550f39cc5ed5ed3dfadadd759e28cf265fb3d4aa"
	if sum := sum256(got); sum != golden {
		if *update {
			t.Logf("new golden digest: %s", sum)
		} else {
			t.Errorf("sdist bytes changed: sha256 %s, golden %s. If intended, bump SdistFormat and update the golden with -update.", sum, golden)
		}
	}
	e := entriesOf(t, got)
	var names []string
	for n := range e {
		names = append(names, n)
	}
	slices.Sort(names)
	want := []string{"acme_core-1.2.0/PKG-INFO", "acme_core-1.2.0/pyproject.toml", "acme_core-1.2.0/run.sh", "acme_core-1.2.0/src/acme_core/__init__.py"}
	if !slices.Equal(names, want) {
		t.Fatalf("entries = %v, want %v (symlink and excluded member dropped)", names, want)
	}
	h := e["acme_core-1.2.0/run.sh"]
	if h.Mode != 0o755 || h.Uid != 0 || h.Uname != "" || !h.ModTime.Equal(time.Unix(1731300000, 0)) {
		t.Fatalf("header = %+v", h)
	}
	if e["acme_core-1.2.0/pyproject.toml"].Mode != 0o644 {
		t.Fatal("regular file mode")
	}
}

func TestSdistDeterministic(t *testing.T) {
	a, err := BuildSdist(bytes.NewReader(basicTar(t)), basicPkg, []byte("x"), time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildSdist(bytes.NewReader(basicTar(t)), basicPkg, []byte("x"), time.Unix(1, 0))
	if !bytes.Equal(a, b) {
		t.Fatal("same input, different bytes")
	}
}

func TestSdistRootPackage(t *testing.T) {
	v, _ := ParseVersion("0.1")
	p := Package{Name: "root-pkg", Version: v, Exclude: []string{"packages/core"}}
	in := gitTar(t, map[string]string{"pyproject.toml": "[project]\n", "root_pkg/__init__.py": "", "packages/core/pyproject.toml": "x"})
	got, err := BuildSdist(bytes.NewReader(in), p, []byte("x"), time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	e := entriesOf(t, got)
	if _, ok := e["root_pkg-0.1/root_pkg/__init__.py"]; !ok || len(e) != 3 {
		t.Fatalf("entries = %v", e)
	}
}

// Review Focus 5: long and non-ASCII paths survive (PAX headers).
func TestSdistLongAndUnicodePaths(t *testing.T) {
	long := "packages/core/" + strings.Repeat("d", 60) + "/" + strings.Repeat("f", 90) + ".py"
	in := gitTar(t, map[string]string{"packages/core/pyproject.toml": "x", long: "long", "packages/core/ü.txt": "u"})
	got, err := BuildSdist(bytes.NewReader(in), basicPkg, []byte("x"), time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	e := entriesOf(t, got)
	wantLong := "acme_core-1.2.0/" + strings.TrimPrefix(long, "packages/core/")
	if _, ok := e[wantLong]; !ok {
		t.Fatalf("long path missing: %v", e)
	}
	if _, ok := e["acme_core-1.2.0/ü.txt"]; !ok {
		t.Fatalf("unicode path missing: %v", e)
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	f := filepath.Join(t.TempDir(), "s.tar.gz")
	os.WriteFile(f, got, 0o644)
	out, err := exec.Command(py, "-I", "-c", "import sys, tarfile; print('\\n'.join(tarfile.open(sys.argv[1]).getnames()))", f).CombinedOutput()
	if err != nil || !strings.Contains(string(out), wantLong) || !strings.Contains(string(out), "ü.txt") {
		t.Fatalf("python tarfile: %v\n%s", err, out)
	}
}

func TestSdistRefusesLFSPointer(t *testing.T) {
	in := gitTar(t, map[string]string{"packages/core/pyproject.toml": "x", "packages/core/model.bin": "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n"})
	_, err := BuildSdist(bytes.NewReader(in), basicPkg, []byte("x"), time.Unix(1, 0))
	var re *RefusedError
	if !errors.As(err, &re) || !strings.Contains(re.Reason, "LFS") {
		t.Fatalf("err = %v", err)
	}
}

func TestIdentity(t *testing.T) {
	entries := []gitmirror.TreeEntry{
		{Mode: "100644", Type: "blob", Object: "a1", Path: "pyproject.toml"},
		{Mode: "100644", Type: "blob", Object: "b1", Path: "packages/core/x.py"},
	}
	attrs := []gitmirror.TreeEntry{{Mode: "100644", Type: "blob", Object: "c1", Path: ".gitattributes"}}
	base := Identity(entries, []string{"packages/core"}, attrs)
	changedMember := slices.Clone(entries)
	changedMember[1].Object = "b2"
	if Identity(changedMember, []string{"packages/core"}, attrs) != base {
		t.Error("a change under an excluded member changed the root identity")
	}
	changedRoot := slices.Clone(entries)
	changedRoot[0].Object = "a2"
	if Identity(changedRoot, []string{"packages/core"}, attrs) == base {
		t.Error("a change to the root did not change its identity")
	}
	if Identity(entries, []string{"packages/core"}, []gitmirror.TreeEntry{{Mode: "100644", Type: "blob", Object: "c2", Path: ".gitattributes"}}) == base {
		t.Error("a changed .gitattributes did not change the identity")
	}
	if Identity(entries, []string{"packages/core/"}, attrs) != base {
		t.Error("exclude with a trailing slash differs")
	}
	if !strings.HasPrefix(base, "") || len(base) != 64 {
		t.Errorf("identity %q is not a sha256 hex", base)
	}
}

func TestRefuseSubmodules(t *testing.T) {
	if r := RefuseTree([]gitmirror.TreeEntry{{Type: "blob", Path: "a"}}); r != "" {
		t.Errorf("plain tree refused: %q", r)
	}
	if r := RefuseTree([]gitmirror.TreeEntry{{Type: "commit", Path: "vendor/x"}}); !strings.Contains(r, "submodule") {
		t.Errorf("submodule: %q", r)
	}
}

// TestRefuseAmbiguousPaths: a path listed twice, or both a file and a
// directory, has no single content, so metadata could disagree with the
// sdist.
func TestRefuseAmbiguousPaths(t *testing.T) {
	for name, entries := range map[string][]gitmirror.TreeEntry{
		"duplicate":        {{Type: "blob", Path: "pyproject.toml"}, {Type: "blob", Path: "pyproject.toml"}},
		"file and dir":     {{Type: "blob", Path: "a"}, {Type: "blob", Path: "a/b"}},
		"file and dir too": {{Type: "blob", Path: "x/a/b/c"}, {Type: "blob", Path: "x/a"}},
	} {
		if r := RefuseTree(entries); !strings.Contains(r, "more than once") {
			t.Errorf("%s: %q", name, r)
		}
	}
	if r := RefuseTree([]gitmirror.TreeEntry{{Type: "blob", Path: "a/b"}, {Type: "blob", Path: "a/c"}, {Type: "blob", Path: "ab"}}); r != "" {
		t.Errorf("plain tree refused: %q", r)
	}
}

// TestSdistRefusesDuplicateEntries: a git archive with a name twice is
// refused rather than built with one of them.
func TestSdistRefusesDuplicateEntries(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, body := range []string{"one", "two"} {
		tw.WriteHeader(&tar.Header{Name: "a.py", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	v, _ := ParseVersion("1.0")
	_, err := BuildSdist(&buf, Package{Name: "a", Version: v}, []byte("Metadata-Version: 2.2\n"), time.Unix(1700000000, 0))
	if !errors.As(err, new(*RefusedError)) {
		t.Fatalf("err = %v", err)
	}
}
