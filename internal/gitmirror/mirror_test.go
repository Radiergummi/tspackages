package gitmirror

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radiergummi/tspackages/internal/resolve"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// makeRepo builds a work tree with a commit and returns its path.
func makeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	write(t, dir, "composer.json", `{"name":"a/b"}`)
	write(t, dir, "src/a.php", "<?php")
	write(t, dir, "tests/t.php", "<?php")
	write(t, dir, ".gitattributes", "tests/ export-ignore\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "one")
	return dir
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newMirror(t *testing.T, remote string) *Mirror {
	t.Helper()
	m, err := New(Options{Remote: remote, BaseDir: t.TempDir(), AllowFileRemotesForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSyncAndRefs(t *testing.T) {
	src := makeRepo(t)
	commit := git(t, src, "rev-parse", "HEAD")
	git(t, src, "tag", "-a", "v1.0.0", "-m", "rel")
	git(t, src, "tag", "v1.1.0")
	git(t, src, "tag", "-a", "treetag", "-m", "x", "HEAD^{tree}")

	m := newMirror(t, src)
	if m.LastSync().IsZero() {
		t.Error("LastSync not set")
	}
	refs, err := m.Refs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Ref{}
	for _, r := range refs {
		got[r.Name] = r
	}
	if len(got) != 3 {
		t.Fatalf("want 3 refs, got %+v", refs)
	}
	for _, n := range []string{"refs/tags/v1.0.0", "refs/tags/v1.1.0", "refs/heads/main"} {
		r, ok := got[n]
		if !ok || r.Commit != commit {
			t.Errorf("%s: %+v want commit %s", n, r, commit)
		}
	}
	if !got["refs/tags/v1.0.0"].IsTag || got["refs/heads/main"].IsTag {
		t.Error("IsTag wrong")
	}
	if got["refs/tags/v1.0.0"].Short != "v1.0.0" || got["refs/heads/main"].Short != "main" {
		t.Error("Short wrong")
	}
	b, err := m.DefaultBranch(context.Background())
	if err != nil || b != "main" {
		t.Errorf("DefaultBranch = %q, %v", b, err)
	}
}

func TestResyncSeesMovedTag(t *testing.T) {
	src := makeRepo(t)
	git(t, src, "tag", "v1.0.0")
	m := newMirror(t, src)
	write(t, src, "x", "x")
	git(t, src, "add", ".")
	git(t, src, "commit", "-q", "-m", "two")
	git(t, src, "tag", "-f", "v1.0.0")
	want := git(t, src, "rev-parse", "HEAD")
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	refs, _ := m.Refs(context.Background())
	for _, r := range refs {
		if r.Short == "v1.0.0" && r.Commit != want {
			t.Errorf("tag not updated: %s", r.Commit)
		}
	}
}

func TestRefsWithSlashTag(t *testing.T) {
	src := makeRepo(t)
	git(t, src, "tag", "release/2026-01")
	m := newMirror(t, src)
	refs, _ := m.Refs(context.Background())
	for _, r := range refs {
		if r.Name == "refs/tags/release/2026-01" {
			if r.Short != "release/2026-01" {
				t.Errorf("Short = %q", r.Short)
			}
			return
		}
	}
	t.Fatal("tag missing")
}

func TestReadFile(t *testing.T) {
	src := makeRepo(t)
	commit := git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)
	ctx := context.Background()
	b, err := m.ReadFile(ctx, commit, "composer.json")
	if err != nil || string(b) != `{"name":"a/b"}` {
		t.Fatalf("got %q, %v", b, err)
	}
	if _, err := m.ReadFile(ctx, commit, "nope.json"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	for _, p := range []string{"../x", "a/../b", "/etc/passwd", ""} {
		if _, err := m.ReadFile(ctx, commit, p); err == nil || errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("path %q: %v", p, err)
		}
	}
	for _, c := range []string{"HEAD", "main", commit[:39], commit + "; rm", "--help"} {
		if _, err := m.ReadFile(ctx, c, "composer.json"); err == nil {
			t.Errorf("commit %q accepted", c)
		}
	}
	zeros := strings.Repeat("0", 40)
	if _, err := m.ReadFile(ctx, zeros, "composer.json"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unknown commit: %v", err)
	}
}

func TestArchiveExportIgnore(t *testing.T) {
	src := makeRepo(t)
	commit := git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)
	var buf bytes.Buffer
	if err := m.ArchiveZip(context.Background(), commit, &buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		if strings.HasPrefix(f.Name, "tests/") {
			t.Errorf("tests/ not ignored: %s", f.Name)
		}
	}
	if !contains(names, "composer.json") || !contains(names, "src/a.php") {
		t.Errorf("entries: %v", names)
	}
	if err := m.ArchiveZip(context.Background(), "main", &buf); err == nil {
		t.Error("non-sha commit accepted")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestNewRemoteValidation(t *testing.T) {
	bad := []string{"file:///tmp/x", "/tmp/x", "ext::sh -c id", "http://example.com/x.git", "-oProxyCommand=x", "relative/path"}
	for _, r := range bad {
		if _, err := New(Options{Remote: r, BaseDir: t.TempDir()}); err == nil {
			t.Errorf("remote %q accepted", r)
		}
	}
	if _, err := New(Options{Remote: "ext::sh -c id", BaseDir: t.TempDir(), AllowFileRemotesForTesting: true}); err == nil {
		t.Error("ext:: accepted even with test hatch")
	}
	kh := filepath.Join(t.TempDir(), "kh")
	key := filepath.Join(t.TempDir(), "key")
	good := []Options{
		{Remote: "https://github.com/a/b.git"},
		{Remote: "https://github.com/a/b.git", Token: "tok"},
		{Remote: "ssh://git@github.com/a/b.git", SSHKeyPath: key, KnownHostsPath: kh},
		{Remote: "git@github.com:a/b.git", SSHKeyPath: key, KnownHostsPath: kh},
	}
	for _, o := range good {
		o.BaseDir = filepath.Join(t.TempDir(), "nested", "base")
		if _, err := New(o); err != nil {
			t.Errorf("%q: %v", o.Remote, err)
		}
	}
	// ssh needs known_hosts; unsafe paths are rejected
	if _, err := New(Options{Remote: "git@github.com:a/b.git", SSHKeyPath: key, BaseDir: t.TempDir()}); err == nil {
		t.Error("ssh without known_hosts accepted")
	}
	for _, p := range []string{"/a b/key", `/a"b/key`, "/a'b/key"} {
		if _, err := New(Options{Remote: "git@github.com:a/b.git", SSHKeyPath: p, KnownHostsPath: kh, BaseDir: t.TempDir()}); err == nil {
			t.Errorf("key path %q accepted", p)
		}
	}
}

func TestBaseDirPerms(t *testing.T) {
	base := filepath.Join(t.TempDir(), "b")
	if _, err := New(Options{Remote: "https://x.example/a.git", BaseDir: base}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(base)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("base: %v %v", st, err)
	}
}

func TestTokenNotInArgv(t *testing.T) {
	bin := t.TempDir()
	rec := filepath.Join(t.TempDir(), "rec")
	script := "#!/bin/sh\n{ echo \"ARGV: $*\"; env; } >> " + rec + "\necho 'fatal: token=s3cret-tok' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GIT_DIR", "/should/be/dropped")

	m, err := New(Options{Remote: "https://example.com/a/b.git", BaseDir: t.TempDir(), Token: "s3cret-tok"})
	if err != nil {
		t.Fatal(err)
	}
	err = m.Sync(context.Background())
	if err == nil {
		t.Fatal("fake git exits 1; want error")
	}
	if strings.Contains(err.Error(), "s3cret-tok") {
		t.Errorf("token leaked in error: %v", err)
	}
	if !strings.Contains(err.Error(), "***") {
		t.Errorf("expected redaction marker: %v", err)
	}
	b, _ := os.ReadFile(rec)
	out := string(b)
	var argv, env []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "ARGV: ") {
			argv = append(argv, l)
		} else {
			env = append(env, l)
		}
	}
	if strings.Contains(strings.Join(argv, "\n"), "s3cret-tok") {
		t.Errorf("token in argv: %v", argv)
	}
	e := strings.Join(env, "\n")
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic "} {
		if !strings.Contains(e, want) {
			t.Errorf("env missing %q", want)
		}
	}
	if strings.Contains(e, "GIT_DIR=") {
		t.Error("inherited GIT_DIR not dropped")
	}
	a := strings.Join(argv, "\n")
	for _, want := range []string{"protocol.file.allow=never", "protocol.ext.allow=never", "core.hooksPath=/dev/null", "credential.helper=", " -- "} {
		if !strings.Contains(a, want) {
			t.Errorf("argv missing %q: %s", want, a)
		}
	}
}

func TestSSHCommandEnv(t *testing.T) {
	bin := t.TempDir()
	rec := filepath.Join(t.TempDir(), "rec")
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nenv >> "+rec+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	m, err := New(Options{Remote: "git@github.com:a/b.git", BaseDir: t.TempDir(), SSHKeyPath: "/k/id", KnownHostsPath: "/k/kh"})
	if err != nil {
		t.Fatal(err)
	}
	_ = m.Sync(context.Background())
	b, _ := os.ReadFile(rec)
	want := "GIT_SSH_COMMAND=ssh -i /k/id -o IdentitiesOnly=yes -o UserKnownHostsFile=/k/kh -o StrictHostKeyChecking=yes -o BatchMode=yes"
	if !strings.Contains(string(b), want) {
		t.Errorf("env:\n%s", b)
	}
}
