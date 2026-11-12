package goproxy

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/module"

	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/testutil"
)

const goldenPath = "git.test/acme/m.git"

// goldenGit runs git in dir as testutil.Git does, with author and committer
// dates fixed to date.
func goldenGit(t *testing.T, dir, date string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main", "-c", "core.symlinks=true"}, args...)
	cmd := exec.CommandContext(t.Context(), "git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// goldenRepo builds the fixture repository at <root>/acme/m and returns root.
// Tags: v1.0.0 (go 1.23), tools/v0.1.0, tools2/v0.1.0 (whose LICENSE is a
// symlink) and v2.0.0 on the first commit,
// v1.1.0 (go 1.24) on the second, and a third commit on main.
func goldenRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "acme", "m")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const d1, d2, d3 = "2026-01-02T03:04:05Z", "2026-02-03T04:05:06Z", "2026-03-04T05:06:07Z"
	goldenGit(t, dir, d1, "init", "--quiet")
	writeFiles(t, dir, map[string]string{
		"go.mod":             "module " + goldenPath + "\n\ngo 1.23\n",
		"LICENSE":            "Root licence.\n",
		"a.go":               "package m\n\nconst A = 1\n",
		".gitattributes":     "secret.txt export-ignore\nsubst.txt export-subst\n*.bat eol=crlf\n",
		"secret.txt":         "kept: export-ignore is off\n",
		"subst.txt":          "commit $Format:%H$\n",
		"win.bat":            "echo one\necho two\n",
		"empty.txt":          "",
		"zeros.bin":          strings.Repeat("\x00", 4096),
		"nested/go.mod":      "module " + goldenPath + "/nested\n\ngo 1.23\n",
		"nested/n.go":        "package nested\n",
		"vendor/modules.txt": "# example.com/x v1.0.0\n## explicit\nexample.com/x/y\n",
		"vendor/x/y.go":      "package y\n",
		"tools/go.mod":       "module " + goldenPath + "/tools\n\ngo 1.23\n",
		"tools/t.go":         "package tools\n",
		"tools2/go.mod":      "module " + goldenPath + "/tools2\n\ngo 1.23\n",
		"tools2/t.go":        "package tools2\n",
		"v2/go.mod":          "module " + goldenPath + "/v2\n\ngo 1.23\n",
		"v2/v.go":            "package m\n\nconst V = 2\n",
	})
	for target, link := range map[string]string{"go.mod": "link", "../LICENSE": "tools2/LICENSE"} {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(link))); err != nil {
			t.Fatal(err)
		}
	}
	goldenGit(t, dir, d1, "add", "-A")
	// A submodule entry (gitlink) whose commit isn't in the repository.
	goldenGit(t, dir, d1, "update-index", "--add", "--cacheinfo", "160000,1111111111111111111111111111111111111111,sub")
	goldenGit(t, dir, d1, "commit", "--quiet", "-m", "one")
	for _, tag := range []string{"v1.0.0", "tools/v0.1.0", "tools2/v0.1.0", "v2.0.0"} {
		goldenGit(t, dir, d1, "tag", tag)
	}

	writeFiles(t, dir, map[string]string{"go.mod": "module " + goldenPath + "\n\ngo 1.24\n"})
	goldenGit(t, dir, d2, "commit", "--quiet", "-am", "two")
	goldenGit(t, dir, d2, "tag", "v1.1.0")

	writeFiles(t, dir, map[string]string{"a.go": "package m\n\nconst A = 3\n"})
	goldenGit(t, dir, d3, "commit", "--quiet", "-am", "three")
	return root
}

// goldenMirror mirrors the fixture and returns it with its refs by short name.
func goldenMirror(t *testing.T, root string) (*gitmirror.Mirror, map[string]string) {
	t.Helper()
	m, err := gitmirror.New(gitmirror.Options{
		Remote:                     "file://" + filepath.Join(root, "acme", "m"),
		BaseDir:                    t.TempDir(),
		AllowFileRemotesForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	refs, err := m.Refs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	commits := map[string]string{}
	for _, r := range refs {
		commits[r.Short] = r.Commit
	}
	return m, commits
}

// goldenBuild builds modPath@version from commit as the git source does:
// findModule, then BuildZip with the mirror's archive and root LICENSE.
func goldenBuild(t *testing.T, m *gitmirror.Mirror, mod Module, modPath, version, commit string) ZipResult {
	t.Helper()
	ctx := t.Context()
	read := func(file string) ([]byte, error) { return m.ReadFileMax(ctx, commit, file, MaxGoMod) }
	found, reason, err := findModule(read, mod, modPath)
	if err != nil || reason != "" {
		t.Fatalf("findModule(%s@%s): %q %v", modPath, version, reason, err)
	}
	path, res, err := BuildZip(ctx, BuildInput{
		Version: module.Version{Path: modPath, Version: version},
		Subdir:  found.Dir,
		GoMod:   found.GoMod,
		Archive: func(ctx context.Context, w io.Writer) error {
			return m.ArchiveModuleZip(ctx, commit, found.Dir, w)
		},
		License: func(ctx context.Context) ([]byte, error) {
			return m.ReadFileMax(ctx, commit, "LICENSE", MaxLICENSE)
		},
		TmpDir:   t.TempDir(),
		MaxBytes: MaxArchiveBytes,
	})
	if err != nil {
		t.Fatalf("BuildZip(%s@%s): %v", modPath, version, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestGoldenZipHashes(t *testing.T) {
	root := goldenRepo(t)
	m, commits := goldenMirror(t, root)
	pseudo, _ := testutil.GoListModule(t, root, goldenPath+"@main")
	if !module.IsPseudoVersion(pseudo) {
		t.Fatalf("go list resolved @main to %s, not a pseudo-version", pseudo)
	}
	for _, c := range []struct {
		mod          Module
		modPath, ref string
		version      string
	}{
		{Module{Path: goldenPath}, goldenPath, "v1.0.0", "v1.0.0"},
		{Module{Path: goldenPath}, goldenPath, "v1.1.0", "v1.1.0"},
		{Module{Path: goldenPath + "/tools", Dir: "tools"}, goldenPath + "/tools", "tools/v0.1.0", "v0.1.0"},
		// A LICENSE symlink counts as the module's LICENSE: no root copy, and
		// modzip drops the symlink.
		{Module{Path: goldenPath + "/tools2", Dir: "tools2"}, goldenPath + "/tools2", "tools2/v0.1.0", "v0.1.0"},
		{Module{Path: goldenPath}, goldenPath + "/v2", "v2.0.0", "v2.0.0"},
		{Module{Path: goldenPath}, goldenPath, "main", pseudo},
	} {
		t.Run(c.modPath+"@"+c.version, func(t *testing.T) {
			t.Parallel()
			sum, goModSum := testutil.GoModDownload(t, root, c.modPath, c.version)
			res := goldenBuild(t, m, c.mod, c.modPath, c.version, commits[c.ref])
			t.Logf("go: %s %s; tspackages: %s %s", sum, goModSum, res.ZipHash, res.ModHash)
			if res.ZipHash != sum {
				t.Errorf("ZipHash = %s, go mod download says %s", res.ZipHash, sum)
			}
			if res.ModHash != goModSum {
				t.Errorf("ModHash = %s, go mod download says %s", res.ModHash, goModSum)
			}
		})
	}
}

// User attributes (`*.go eol=crlf` in $XDG_CONFIG_HOME/git/attributes and
// ~/.config/git/attributes) must not reach module archives.
func TestGoldenZipIgnoresUserAttributes(t *testing.T) {
	root := goldenRepo(t)
	sum, _ := testutil.GoModDownload(t, root, goldenPath, "v1.0.0")

	tmp := t.TempDir()
	for _, p := range []string{
		filepath.Join(tmp, "xdg", "git", "attributes"),
		filepath.Join(tmp, "home", ".config", "git", "attributes"),
	} {
		writeFiles(t, filepath.Dir(p), map[string]string{filepath.Base(p): "*.go eol=crlf\n"})
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "xdg"))
	t.Setenv("HOME", filepath.Join(tmp, "home"))

	m, commits := goldenMirror(t, root)
	// The attributes file is live: a plain git archive applies it.
	out := goldenGit(t, root, "", "--git-dir="+m.Dir(), "archive", "--format=tar", commits["v1.0.0"], "a.go")
	if !strings.Contains(out, "package m\r\n") {
		t.Fatal("user attributes did not apply to a plain git archive; the test proves nothing")
	}
	res := goldenBuild(t, m, Module{Path: goldenPath}, goldenPath, "v1.0.0", commits["v1.0.0"])
	if res.ZipHash != sum {
		t.Errorf("ZipHash with user attributes = %s, go mod download says %s", res.ZipHash, sum)
	}
}
