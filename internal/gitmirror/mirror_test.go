package gitmirror

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/testutil"
)

// makeRepo builds a work tree with a commit and returns its path.
func makeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	testutil.Git(t, dir, "init", "-q")
	write(t, dir, "composer.json", `{"name":"a/b"}`)
	write(t, dir, "src/a.php", "<?php")
	write(t, dir, "tests/t.php", "<?php")
	write(t, dir, ".gitattributes", "tests/ export-ignore\n")
	testutil.Git(t, dir, "add", ".")
	testutil.Git(t, dir, "commit", "-q", "-m", "one")
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
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
	testutil.Git(t, src, "tag", "-a", "v1.0.0", "-m", "rel")
	testutil.Git(t, src, "tag", "v1.1.0")
	testutil.Git(t, src, "tag", "-a", "treetag", "-m", "x", "HEAD^{tree}")
	testutil.Git(t, src, "-c", "advice.nestedTag=false", "tag", "-a", "nested", "-m", "n", "v1.0.0")

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
	if len(got) != 4 {
		t.Fatalf("want 4 refs (tree tag skipped), got %+v", refs)
	}
	for _, n := range []string{"refs/tags/v1.0.0", "refs/tags/v1.1.0", "refs/heads/main", "refs/tags/nested"} {
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
	testutil.Git(t, src, "tag", "v1.0.0")
	m := newMirror(t, src)
	write(t, src, "x", "x")
	testutil.Git(t, src, "add", ".")
	testutil.Git(t, src, "commit", "-q", "-m", "two")
	testutil.Git(t, src, "tag", "-f", "v1.0.0")
	want := testutil.Git(t, src, "rev-parse", "HEAD")
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
	testutil.Git(t, src, "tag", "release/2026-01")
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
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)
	ctx := context.Background()
	b, err := m.ReadFile(ctx, commit, "composer.json")
	if err != nil || string(b) != `{"name":"a/b"}` {
		t.Fatalf("got %q, %v", b, err)
	}
	if _, err := m.ReadFile(ctx, commit, "nope.json"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	for _, p := range []string{"../x", "a/../b", "/etc/passwd", "", "./composer.json", "a/./b", "a//b", "a\nb"} {
		if _, err := m.ReadFile(ctx, commit, p); err == nil || errors.Is(err, resolve.ErrNotFound) {
			t.Errorf("path %q: %v", p, err)
		}
	}
	for _, c := range []string{"HEAD", "main", commit[:39], commit + "; rm", "--help"} {
		if _, err := m.ReadFile(ctx, c, "composer.json"); err == nil {
			t.Errorf("commit %q accepted", c)
		}
	}
	if _, err := m.ReadFile(ctx, commit, "src"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("directory: %v", err)
	}
	zeros := strings.Repeat("0", 40)
	if _, err := m.ReadFile(ctx, zeros, "composer.json"); !errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("unknown commit: %v", err)
	}
}

func TestArchiveExportIgnore(t *testing.T) {
	src := makeRepo(t)
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
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
	if !slices.Contains(names, "composer.json") || !slices.Contains(names, "src/a.php") {
		t.Errorf("entries: %v", names)
	}
	if err := m.ArchiveZip(context.Background(), "main", &buf); err == nil {
		t.Error("non-sha commit accepted")
	}
}

func TestNewRemoteValidation(t *testing.T) {
	bad := []string{"https://u:p@example.com/x.git", "https://tok@example.com/x.git", "ssh://u:p@example.com/x.git", "file:///tmp/x", "/tmp/x", "ext::sh -c id", "http://example.com/x.git", "-oProxyCommand=x", "relative/path"}
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
	for _, p := range []string{"/a b/key", `/a"b/key`, "/a'b/key", "/k/kh#", "/k/id;id", "/k/*", "/k/a|b", "rel/key", "-oFoo"} {
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
	for l := range strings.SplitSeq(out, "\n") {
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
	for _, want := range []string{"LC_ALL=C", "LANGUAGE=", "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic "} {
		if !strings.Contains(e, want) {
			t.Errorf("env missing %q", want)
		}
	}
	if strings.Contains(e, "GIT_DIR=") {
		t.Error("inherited GIT_DIR not dropped")
	}
	a := strings.Join(argv, "\n")
	for _, want := range []string{"protocol.file.allow=never", "protocol.ext.allow=never", "core.hooksPath=/dev/null",
		"credential.helper=", "http.followRedirects=false", "protocol.allow=never", "protocol.https.allow=always",
		"protocol.ssh.allow=always", "gc.auto=0", "maintenance.auto=false", " -- "} {
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
	want := "GIT_SSH_COMMAND=ssh -F /dev/null -i /k/id -o IdentitiesOnly=yes -o UserKnownHostsFile=/k/kh -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes"
	if !strings.Contains(string(b), want) {
		t.Errorf("env:\n%s", b)
	}
}

func TestReadFileSizeCap(t *testing.T) {
	src := makeRepo(t)
	write(t, src, "big", strings.Repeat("x", maxReadFile+1))
	write(t, src, "ok", strings.Repeat("x", maxReadFile))
	testutil.Git(t, src, "add", ".")
	testutil.Git(t, src, "commit", "-q", "-m", "big")
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)
	if _, err := m.ReadFile(context.Background(), commit, "big"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Errorf("big: %v", err)
	}
	if b, err := m.ReadFile(context.Background(), commit, "ok"); err != nil || len(b) != maxReadFile {
		t.Errorf("ok: %d %v", len(b), err)
	}
}

func TestOnlyHeadsAndTagsAndDefaultBranchFollows(t *testing.T) {
	src := makeRepo(t)
	testutil.Git(t, src, "update-ref", "refs/pull/1/head", "HEAD")
	testutil.Git(t, src, "update-ref", "refs/merge-requests/1/head", "HEAD")
	testutil.Git(t, src, "checkout", "-q", "-b", "dev")
	m := newMirror(t, src)
	ctx := context.Background()
	if out := testutil.Git(t, m.dir, "for-each-ref", "refs/pull", "refs/merge-requests", "refs/remotes"); out != "" {
		t.Errorf("unexpected refs:\n%s", out)
	}
	if b, err := m.DefaultBranch(ctx); err != nil || b != "dev" {
		t.Errorf("DefaultBranch = %q, %v", b, err)
	}
	testutil.Git(t, src, "checkout", "-q", "main")
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if b, _ := m.DefaultBranch(ctx); b != "main" {
		t.Errorf("after switch DefaultBranch = %q", b)
	}
	if out := testutil.Git(t, m.dir, "for-each-ref", "refs/pull", "refs/merge-requests", "refs/remotes"); out != "" {
		t.Errorf("unexpected refs after resync:\n%s", out)
	}
}

func TestStaleLocksRemoved(t *testing.T) {
	src := makeRepo(t)
	m := newMirror(t, src)
	write(t, src, "x", "x")
	testutil.Git(t, src, "add", ".")
	testutil.Git(t, src, "commit", "-q", "-m", "two")
	// Locks left by a killed process: the next process's first Sync removes them.
	write(t, m.dir, "refs/heads/main.lock", "")
	write(t, m.dir, "packed-refs.lock", "")
	m, err := New(m.opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "refs/heads/main.lock")); !os.IsNotExist(err) {
		t.Errorf("lock remains: %v", err)
	}
}

func TestStaleLocksRemovedAfterFailedFetch(t *testing.T) {
	src := makeRepo(t)
	m := newMirror(t, src)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Sync(ctx); err == nil {
		t.Fatal("Sync with a cancelled context succeeded")
	}
	write(t, m.dir, "refs/heads/main.lock", "")
	testutil.Git(t, src, "commit", "-q", "--allow-empty", "-m", "two")
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "refs/heads/main.lock")); !os.IsNotExist(err) {
		t.Errorf("lock remains: %v", err)
	}
}

func TestDirDependsOnCredentials(t *testing.T) {
	base := t.TempDir()
	mk := func(tok string) string {
		m, err := New(Options{Remote: "https://x.example/a.git", BaseDir: base, Token: tok})
		if err != nil {
			t.Fatal(err)
		}
		return m.dir
	}
	a1, a2 := mk("a"), mk("a")
	if a1 != a2 || a1 == mk("b") || a1 == mk("") {
		t.Error("mirror dir does not track credential identity")
	}
}

func TestCancelKillsProcessGroup(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nsleep 30 &\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	m, err := New(Options{Remote: "https://example.com/a.git", BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := m.Sync(ctx); err == nil {
		t.Fatal("want error")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("cancel took %v", d)
	}
}

// A hung git that ignores SIGTERM (and has a child that does too) is ended by
// the per-Sync timeout and the group SIGKILL after killDelay.
func TestSyncTimeoutKillsHungGroup(t *testing.T) {
	bin := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "child")
	script := "#!/bin/sh\ntrap '' TERM\nsleep 30 &\necho $! > " + pidFile + "\nwait\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	m, err := New(Options{Remote: "https://example.com/a.git", BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	m.syncTimeout, m.killDelay = 300*time.Millisecond, 300*time.Millisecond
	start := time.Now()
	if err := m.Sync(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("hung sync took %v", d)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(2 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatal("child of hung git survived")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTransportTimeoutOptions(t *testing.T) {
	bin := t.TempDir()
	rec := filepath.Join(t.TempDir(), "rec")
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\n{ echo \"ARGV: $*\"; env; } >> "+rec+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	m, err := New(Options{Remote: "git@github.com:a/b.git", BaseDir: t.TempDir(), KnownHostsPath: "/k/kh"})
	if err != nil {
		t.Fatal(err)
	}
	if m.syncTimeout != 10*time.Minute {
		t.Errorf("syncTimeout = %v", m.syncTimeout)
	}
	_ = m.Sync(context.Background())
	b, _ := os.ReadFile(rec)
	for _, want := range []string{"http.lowSpeedLimit=1000", "http.lowSpeedTime=60",
		"-o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in:\n%s", want, b)
		}
	}
}

// A failing ls-remote after a successful fetch keeps the HEAD, warns and still
// counts as a sync.
func TestLsRemoteFailureKeepsHead(t *testing.T) {
	src := makeRepo(t)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	m, err := New(Options{Remote: src, BaseDir: t.TempDir(), AllowFileRemotesForTesting: true,
		Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := m.LastSync()
	bin := t.TempDir()
	script := "#!/bin/sh\nfor a; do [ \"$a\" = ls-remote ] && { echo 'fatal: unable to access' >&2; exit 128; }; done\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	time.Sleep(10 * time.Millisecond)
	if err := m.Sync(context.Background()); err != nil {
		t.Fatalf("transient ls-remote failure failed the sync: %v", err)
	}
	if !m.LastSync().After(first) {
		t.Error("lastSync not updated")
	}
	if b, err := m.DefaultBranch(context.Background()); err != nil || b != "main" {
		t.Errorf("default branch = %q, %v", b, err)
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("no warning logged: %s", logs.String())
	}
}

func TestSCPUserMustNotStartWithDash(t *testing.T) {
	if scpRe.MatchString("-u@github.com:a/b.git") {
		t.Error("user starting with - accepted")
	}
	if !scpRe.MatchString("git@github.com:a/b.git") || !scpRe.MatchString("_x.y-z@github.com:a/b.git") {
		t.Error("valid user rejected")
	}
}

func TestListTree(t *testing.T) {
	src := makeRepo(t)
	write(t, src, "packages/a/pyproject.toml", "[project]\n")
	testutil.Git(t, src, "add", ".")
	head := testutil.Git(t, src, "rev-parse", "HEAD")
	testutil.Git(t, src, "update-index", "--add", "--cacheinfo", "160000,"+head+",packages/a/vendored")
	testutil.Git(t, src, "commit", "-q", "-m", "two")
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)

	all, err := m.ListTree(context.Background(), commit, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(all, func(e TreeEntry) bool {
		return e.Path == "src/a.php" && e.Type == "blob" && e.Mode == "100644" && len(e.Object) == 40
	}) {
		t.Fatalf("whole tree: %+v", all)
	}
	sub, err := m.ListTree(context.Background(), commit, "packages/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 2 || !slices.ContainsFunc(sub, func(e TreeEntry) bool { return e.Path == "packages/a/vendored" && e.Type == "commit" }) {
		t.Fatalf("subdir: %+v", sub)
	}
}

func TestArchiveTar(t *testing.T) {
	src := makeRepo(t)
	write(t, src, "packages/a/x.py", "x")
	write(t, src, "packages/a/secret.txt", "s")
	write(t, src, ".gitattributes", "tests/ export-ignore\npackages/a/secret.txt export-ignore\n")
	testutil.Git(t, src, "add", ".")
	testutil.Git(t, src, "commit", "-q", "-m", "two")
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)
	var buf bytes.Buffer
	if err := m.ArchiveTar(context.Background(), commit, []string{"packages/a", "composer.json"}, &buf); err != nil {
		t.Fatal(err)
	}
	var names []string
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Typeflag == tar.TypeReg {
			names = append(names, h.Name)
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"composer.json", "packages/a/x.py"}) {
		t.Fatalf("entries: %v (secret.txt must be export-ignored, src/ not requested)", names)
	}
}

// Repository paths are literal: glob characters and ":" magic in a directory
// name select only that directory.
func TestPathsAreLiteral(t *testing.T) {
	src := makeRepo(t)
	write(t, src, "pkg[ab]/x.py", "x")
	write(t, src, "pkga/y.py", "y")
	write(t, src, ":(top)pkga/z.py", "z")
	testutil.Git(t, src, "add", ".")
	testutil.Git(t, src, "commit", "-q", "-m", "two")
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)
	for _, dir := range []string{"pkg[ab]", ":(top)pkga"} {
		entries, err := m.ListTree(context.Background(), commit, dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || !strings.HasPrefix(entries[0].Path, dir+"/") {
			t.Errorf("ListTree(%q): %+v", dir, entries)
		}
		var buf bytes.Buffer
		if err := m.ArchiveTar(context.Background(), commit, []string{dir}, &buf); err != nil {
			t.Fatal(err)
		}
		var names []string
		tr := tar.NewReader(&buf)
		for h, err := tr.Next(); err == nil; h, err = tr.Next() {
			if h.Typeflag == tar.TypeReg {
				names = append(names, h.Name)
			}
		}
		if len(names) != 1 || !strings.HasPrefix(names[0], dir+"/") {
			t.Errorf("ArchiveTar(%q): %v", dir, names)
		}
	}
}

func TestIsAncestorAndCommitTime(t *testing.T) {
	src := makeRepo(t)
	base := testutil.Git(t, src, "rev-parse", "HEAD")
	testutil.Git(t, src, "checkout", "-q", "-b", "left")
	write(t, src, "l", "l")
	testutil.Git(t, src, "add", ".")
	testutil.Git(t, src, "commit", "-q", "-m", "left")
	left := testutil.Git(t, src, "rev-parse", "HEAD")
	testutil.Git(t, src, "checkout", "-q", "-b", "right", base)
	write(t, src, "r", "r")
	testutil.Git(t, src, "add", ".")
	testutil.Git(t, src, "commit", "-q", "-m", "right")
	right := testutil.Git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)
	ctx := context.Background()
	for _, c := range []struct {
		a, b string
		want bool
	}{{base, left, true}, {left, base, false}, {left, right, false}, {right, left, false}, {base, base, true}} {
		got, err := m.IsAncestor(ctx, c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("IsAncestor(%.7s, %.7s) = %v, %v; want %v", c.a, c.b, got, err, c.want)
		}
	}
	ts, err := m.CommitTime(ctx, left)
	if err != nil || time.Since(ts) > time.Hour || ts.After(time.Now().Add(time.Minute)) {
		t.Fatalf("CommitTime = %v, %v", ts, err)
	}
}

func TestTreePathValidation(t *testing.T) {
	src := makeRepo(t)
	commit := testutil.Git(t, src, "rev-parse", "HEAD")
	m := newMirror(t, src)
	for _, p := range []string{"-x", "../x", "a/../b", "/abs", "a//b"} {
		if _, err := m.ListTree(context.Background(), commit, p); err == nil {
			t.Errorf("ListTree(%q) accepted", p)
		}
		if err := m.ArchiveTar(context.Background(), commit, []string{p}, io.Discard); err == nil {
			t.Errorf("ArchiveTar(%q) accepted", p)
		}
	}
	if _, err := m.IsAncestor(context.Background(), "main", commit); err == nil {
		t.Error("non-sha commit accepted")
	}
}

// TestDecomposedPaths: a path stored in NFD (as on Linux) is read and
// archived as listed; git on macOS would otherwise precompose it into a
// path the tree does not have.
func TestDecomposedPaths(t *testing.T) {
	src := makeRepo(t)
	run := func(in string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir, cmd.Stdin = src, strings.NewReader(in)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	dir := "pkg/é" // NFD
	blob := run("x\n", "hash-object", "-w", "--stdin")
	inner := run("100644 blob "+blob+"\tx.py\n", "mktree")
	mid := run("040000 tree "+inner+"\té\n", "mktree")
	top := run("040000 tree "+mid+"\tpkg\n", "mktree")
	commit := run("", "commit-tree", "-m", "nfd", top)
	run("", "update-ref", "refs/tags/nfd", commit)
	m := newMirror(t, src)
	if b, err := m.ReadFile(context.Background(), commit, dir+"/x.py"); err != nil || string(b) != "x\n" {
		t.Fatalf("ReadFile: %q %v", b, err)
	}
	var buf bytes.Buffer
	if err := m.ArchiveTar(context.Background(), commit, []string{dir}, &buf); err != nil {
		t.Fatalf("ArchiveTar: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(dir+"/x.py")) {
		t.Fatal("archive lacks the file")
	}
}

// TestListTreeBytesCapped: ls-tree repeats each entry's full path, so a
// small tree can list gigabytes; a path over 4KiB, or a listing over
// 64MiB, is ErrTreeTooLarge.
func TestListTreeBytesCapped(t *testing.T) {
	src := makeRepo(t)
	run := func(in string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir, cmd.Stdin = src, strings.NewReader(in)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	blob := run("x\n", "hash-object", "-w", "--stdin")
	var sb strings.Builder
	for i := range 17000 {
		fmt.Fprintf(&sb, "100644 blob %s\tf%05d\n", blob, i)
	}
	wide := run(sb.String(), "mktree")
	for name, top := range map[string]string{
		"long path": run("100644 blob "+blob+"\t"+strings.Repeat("n", 5000)+"\n", "mktree"),
		"listing":   run("040000 tree "+wide+"\t"+strings.Repeat("d", 4000)+"\n", "mktree"),
	} {
		t.Run(name, func(t *testing.T) {
			commit := run("", "commit-tree", "-m", name, top)
			run("", "update-ref", "refs/tags/"+strings.ReplaceAll(name, " ", "-"), commit)
			m := newMirror(t, src)
			if _, err := m.ListTree(context.Background(), commit, ""); !errors.Is(err, ErrTreeTooLarge) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
