// Package gitmirror keeps a bare mirror of one git remote and reads tags,
// files and archives from it by shelling out to the git binary. Credentials
// travel only in the environment of the child process, and only https, ssh
// (and, for tests, file) transports are allowed. It needs git >= 2.40 (for
// full peeling of nested tags by for-each-ref's %(*objectname)).
package gitmirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/radiergummi/tspackages/internal/digest"
	"github.com/radiergummi/tspackages/internal/resolve"
)

// Options configures a Mirror. Secrets arrive as file paths (SSH) or a token
// string (HTTPS).
type Options struct {
	Remote string
	// BaseDir holds the mirror; New creates it or tightens it to mode 0700.
	BaseDir string
	// SSHKeyPath is an absolute path matching sshPathRe. When empty, ssh
	// falls back to its default identity files (and, because the environment
	// is inherited, SSH_AUTH_SOCK); the ssh config is always ignored (-F /dev/null).
	SSHKeyPath     string
	KnownHostsPath string
	Token          string

	// Logger receives warnings; nil means slog.Default() as of New.
	Logger *slog.Logger

	// AllowFileRemotesForTesting permits file:// URLs and local paths as
	// remotes. Tests only; never set from configuration.
	AllowFileRemotesForTesting bool
}

// Ref is a tag or branch pointing at a commit.
type Ref struct {
	Name   string // "refs/tags/v1.0.0"
	Short  string // "v1.0.0"
	Commit string // peeled commit SHA
	IsTag  bool
}

// Mirror is a bare mirror of a remote's branches and tags.
type Mirror struct {
	opts        Options
	dir         string
	syncTimeout time.Duration // bounds one Sync; replaced in tests
	killDelay   time.Duration // SIGTERM to SIGKILL of a cancelled git's process group

	mu         sync.Mutex // serialises Sync; guards fetchClean
	fetchClean bool       // the last fetch in this process completed, so no stale locks are left

	lastSync      atomic.Pointer[time.Time]
	defaultBranch atomic.Pointer[string] // as last set from the remote by this process
}

const (
	// syncTimeout bounds one Sync (all its git runs together).
	syncTimeout = 10 * time.Minute
	// killDelay is how long a cancelled git's process group gets between
	// SIGTERM and SIGKILL.
	killDelay   = 5 * time.Second
	maxReadFile = 1 << 20
	headsSpec   = "+refs/heads/*:refs/heads/*"
	tagsSpec    = "+refs/tags/*:refs/tags/*"
)

var (
	scpRe     = regexp.MustCompile(`^(?:[A-Za-z0-9._][A-Za-z0-9._-]*@)?[A-Za-z0-9][A-Za-z0-9.-]*:[^:]`)
	sshPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@+=,-]+$`)
)

// New validates the options and prepares the mirror directory
// BaseDir/<first 16 hex of sha256(Remote, credential identity)>.git. The
// credential identity keeps mirrors fetched with different credentials apart.
// BaseDir is created with mode 0700, and an existing BaseDir that is group- or
// world-accessible is chmod-ed to 0700. It does not touch the network.
func New(o Options) (*Mirror, error) {
	kind, err := RemoteKind(o.Remote, o.AllowFileRemotesForTesting)
	if err != nil {
		return nil, err
	}
	if kind == "ssh" {
		if o.KnownHostsPath == "" {
			return nil, errors.New("gitmirror: ssh remotes require a known_hosts file")
		}
		for _, p := range []string{o.SSHKeyPath, o.KnownHostsPath} {
			if p != "" && !sshPathRe.MatchString(p) {
				return nil, fmt.Errorf("gitmirror: ssh path %q must be absolute and use only [A-Za-z0-9._/@+=,-]", p)
			}
		}
	}
	if o.BaseDir == "" {
		return nil, errors.New("gitmirror: BaseDir is required")
	}
	base, err := filepath.Abs(o.BaseDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("gitmirror: create base dir: %w", err)
	}
	if st, err := os.Stat(base); err != nil {
		return nil, err
	} else if st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(base, 0o700); err != nil { //nolint:gosec // a directory: 0700 is owner-only
			return nil, fmt.Errorf("gitmirror: chmod base dir: %w", err)
		}
	}
	o.BaseDir = base
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	identity := o.SSHKeyPath
	if o.Token != "" {
		t := sha256.Sum256([]byte(o.Token))
		identity = hex.EncodeToString(t[:])
	}
	sum := sha256.Sum256([]byte(o.Remote + "\x00" + identity))
	return &Mirror{opts: o, dir: filepath.Join(base, hex.EncodeToString(sum[:])[:16]+".git"), syncTimeout: syncTimeout, killDelay: killDelay}, nil
}

// ErrRemoteCredentials is returned by RemoteKind for a remote URL that embeds
// credentials.
var ErrRemoteCredentials = errors.New("gitmirror: remote must not embed credentials; use the token option")

// RemoteKind classifies a git remote as "https", "ssh" (ssh:// or scp-style
// [user@]host:path) or, only with allowFile, "file" (file:// or any other
// non-URL path). It returns ErrRemoteCredentials for an https remote with
// userinfo or any remote with a password, and an error for anything else.
func RemoteKind(r string, allowFile bool) (string, error) {
	if r == "" || strings.HasPrefix(r, "-") || strings.ContainsAny(r, "\x00\r\n\t ") || strings.Contains(r, "::") {
		return "", fmt.Errorf("gitmirror: unsupported remote %q", r)
	}
	switch {
	case strings.HasPrefix(r, "https://"), strings.HasPrefix(r, "ssh://"):
		u, err := url.Parse(r)
		if err != nil {
			return "", fmt.Errorf("gitmirror: invalid remote: %w", err)
		}
		if u.User != nil {
			if _, hasPw := u.User.Password(); hasPw || u.Scheme == "https" {
				return "", ErrRemoteCredentials
			}
		}
		return u.Scheme, nil
	case strings.Contains(r, "://"):
		if allowFile && strings.HasPrefix(r, "file://") {
			return "file", nil
		}
	case scpRe.MatchString(r):
		return "ssh", nil
	case allowFile:
		return "file", nil
	}
	return "", fmt.Errorf("gitmirror: unsupported remote %q (use https:// or ssh)", r)
}

// Remote returns the remote URL the mirror was configured with.
func (m *Mirror) Remote() string { return m.opts.Remote }

// Dir returns the bare mirror's directory.
func (m *Mirror) Dir() string { return m.dir }

// LastSync returns the time of the last successful Sync (zero if none).
func (m *Mirror) LastSync() time.Time {
	if t := m.lastSync.Load(); t != nil {
		return *t
	}
	return time.Time{}
}

// Sync creates the mirror on first use and fetches branches and tags
// (pruning, force-updating tags) afterwards. Only refs/heads and refs/tags
// are ever fetched. The mirror's HEAD follows the remote's default branch.
// One Sync is bounded by syncTimeout (10 minutes); transfers slower than
// 1000 B/s for 60 s and unresponsive SSH peers are abandoned earlier.
func (m *Mirror) Sync(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, m.syncTimeout)
	defer cancel()

	_, err := os.Stat(filepath.Join(m.dir, "HEAD"))
	switch {
	case err == nil:
		if !m.fetchClean {
			m.removeStaleLocks()
		}
		m.fetchClean = false
		if err := m.fetch(ctx, m.dir); err != nil {
			return err
		}
	case errors.Is(err, fs.ErrNotExist):
		if err := m.create(ctx); err != nil {
			return err
		}
	default:
		return err
	}
	m.fetchClean = true
	// The refs are fetched; a failure to learn the remote's default branch
	// only keeps the previous HEAD.
	if err := m.followRemoteHead(ctx); err != nil {
		if ctx.Err() != nil {
			return err
		}
		m.opts.Logger.Warn("gitmirror: could not read the remote's default branch; keeping the previous HEAD",
			"remote", m.opts.Remote, "error", err)
	}
	now := time.Now()
	m.lastSync.Store(&now)
	return nil
}

// create builds the mirror in a scratch dir so an interrupted first sync never
// leaves a half-built mirror behind.
func (m *Mirror) create(ctx context.Context) error {
	tmp := m.dir + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	fail := func(err error) error {
		_ = os.RemoveAll(tmp)
		return err
	}
	if _, err := m.git(ctx, "", nil, nil, "init", "--bare", "--quiet", "--", tmp); err != nil {
		return fail(err)
	}
	for _, a := range [][]string{
		{"remote", "add", "origin", "--", m.opts.Remote},
		// Only these refspecs: no refs/pull/*, refs/merge-requests/*, and no
		// remote-tracking refs.
		{"config", "--replace-all", "remote.origin.fetch", headsSpec},
		{"config", "--add", "remote.origin.fetch", tagsSpec},
	} {
		if _, err := m.git(ctx, tmp, nil, nil, a...); err != nil {
			return fail(err)
		}
	}
	if err := m.fetch(ctx, tmp); err != nil {
		return fail(err)
	}
	if err := os.RemoveAll(m.dir); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, m.dir); err != nil {
		return fail(err)
	}
	return nil
}

func (m *Mirror) fetch(ctx context.Context, gitDir string) error {
	_, err := m.git(ctx, gitDir, nil, nil, "fetch", "--prune", "--prune-tags", "--", "origin", headsSpec, tagsSpec)
	return err
}

// removeStaleLocks deletes leftover ref and packed-refs lock files from a
// killed fetch. Sync runs it before a fetch unless the previous fetch in this
// process completed. It removes all of them, regardless of age: Sync holds m.mu
// and the directory is private to this mirror (keyed by remote and
// credentials), so no live writer can own a lock when Sync starts.
func (m *Mirror) removeStaleLocks() {
	for _, f := range []string{"packed-refs.lock", "shallow.lock"} {
		_ = os.Remove(filepath.Join(m.dir, f))
	}
	_ = filepath.WalkDir(filepath.Join(m.dir, "refs"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".lock") {
			_ = os.Remove(p)
		}
		return nil
	})
}

// followRemoteHead points the mirror's HEAD at the remote's default branch,
// unless it already points there.
func (m *Mirror) followRemoteHead(ctx context.Context) error {
	out, err := m.git(ctx, m.dir, nil, nil, "ls-remote", "--symref", "--", "origin", "HEAD")
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "ref: refs/heads/"); ok {
			branch, _, _ := strings.Cut(rest, "\t")
			if branch == "" {
				continue
			}
			if cur := m.defaultBranch.Load(); cur != nil && *cur == branch {
				return nil
			}
			if _, err := m.git(ctx, m.dir, nil, nil, "symbolic-ref", "HEAD", "refs/heads/"+branch); err != nil {
				return err
			}
			m.defaultBranch.Store(&branch)
			return nil
		}
	}
	return nil
}

// Refs lists tags and branches whose target is a commit; annotated tags
// (including nested ones) are peeled to the commit.
func (m *Mirror) Refs(ctx context.Context) ([]Ref, error) {
	out, err := m.git(ctx, m.dir, nil, nil, "for-each-ref",
		"--format=%(refname)%00%(objecttype)%00%(objectname)%00%(*objecttype)%00%(*objectname)",
		"refs/tags", "refs/heads")
	if err != nil {
		return nil, err
	}
	var refs []Ref
	for line := range strings.SplitSeq(string(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x00")
		if len(f) != 5 {
			return nil, fmt.Errorf("gitmirror: unexpected for-each-ref line %q", line)
		}
		name, typ, obj, ptyp, pobj := f[0], f[1], f[2], f[3], f[4]
		commit := obj
		if ptyp != "" { // annotated tag: use what it points at
			typ, commit = ptyp, pobj
		}
		if typ != "commit" {
			continue
		}
		r := Ref{Name: name, Commit: commit}
		switch {
		case strings.HasPrefix(name, "refs/tags/"):
			r.Short, r.IsTag = strings.TrimPrefix(name, "refs/tags/"), true
		case strings.HasPrefix(name, "refs/heads/"):
			r.Short = strings.TrimPrefix(name, "refs/heads/")
		default:
			continue
		}
		refs = append(refs, r)
	}
	return refs, nil
}

// DefaultBranch returns the branch the mirror's HEAD points to (the remote's
// default branch as of the last Sync).
func (m *Mirror) DefaultBranch(ctx context.Context) (string, error) {
	if b := m.defaultBranch.Load(); b != nil {
		return *b, nil
	}
	out, err := m.git(ctx, m.dir, nil, nil, "symbolic-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "refs/heads/"), nil
}

// ReadFile returns the content of the regular file path at commit. A missing
// path or commit wraps resolve.ErrNotFound; files over 1 MiB are an error
// (this is for small manifests such as composer.json and go.mod).
func (m *Mirror) ReadFile(ctx context.Context, commit, path string) ([]byte, error) {
	if err := checkCommit(commit); err != nil {
		return nil, err
	}
	if path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\n") {
		return nil, fmt.Errorf("gitmirror: invalid path %q", path)
	}
	for seg := range strings.SplitSeq(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return nil, fmt.Errorf("gitmirror: invalid path %q", path)
		}
	}
	// Existence is decided by batch-check's "missing" lines, not by parsing
	// git's (localised) error messages.
	in := commit + "^{commit}\n" + commit + ":" + path + "\n"
	out, err := m.git(ctx, m.dir, strings.NewReader(in), nil, "cat-file", "--batch-check")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		return nil, fmt.Errorf("gitmirror: unexpected cat-file output %q", out)
	}
	notFound := fmt.Errorf("gitmirror: %s:%s: %w", commit, path, resolve.ErrNotFound)
	if strings.HasSuffix(lines[0], " missing") || strings.HasSuffix(lines[1], " missing") {
		return nil, notFound
	}
	f := strings.Fields(lines[1]) // <sha> <type> <size>
	if len(f) != 3 || f[1] != "blob" {
		return nil, notFound // a directory or submodule, not a file
	}
	size, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("gitmirror: unexpected cat-file output %q", lines[1])
	}
	if size > maxReadFile {
		return nil, fmt.Errorf("gitmirror: %s:%s is %d bytes, over the %d byte limit", commit, path, size, maxReadFile)
	}
	return m.git(ctx, m.dir, nil, nil, "cat-file", "blob", commit+":"+path)
}

// ArchiveZip streams a zip of the tree at commit to w, honouring
// export-ignore. The caller must enforce size limits on what it receives, and
// must treat anything already written to w as invalid when an error is
// returned (the stream can be cut off part-way).
func (m *Mirror) ArchiveZip(ctx context.Context, commit string, w io.Writer) error {
	if err := checkCommit(commit); err != nil {
		return err
	}
	_, err := m.git(ctx, m.dir, nil, w, "archive", "--format=zip", commit)
	return err
}

// checkCommit accepts a full SHA-1 or SHA-256 commit id.
func checkCommit(commit string) error {
	if !digest.IsHex(commit, 40, 64) {
		return fmt.Errorf("gitmirror: invalid commit %q", commit)
	}
	return nil
}

type gitError struct {
	args   string
	err    error
	stderr string // redacted
}

func (e *gitError) Error() string {
	return fmt.Sprintf("git %s: %v: %s", e.args, e.err, strings.TrimSpace(e.stderr))
}
func (e *gitError) Unwrap() error { return e.err }

// git executes git. gitDir, when set, is passed as --git-dir (no repository
// discovery). With a non-nil stdout writer the output is streamed there and
// the returned bytes are nil.
func (m *Mirror) git(ctx context.Context, gitDir string, stdin io.Reader, stdout io.Writer, args ...string) ([]byte, error) {
	fileAllow := "never"
	if m.opts.AllowFileRemotesForTesting {
		fileAllow = "always"
	}
	full := []string{
		"-c", "protocol.allow=never",
		"-c", "protocol.https.allow=always",
		"-c", "protocol.ssh.allow=always",
		"-c", "protocol.file.allow=" + fileAllow,
		"-c", "protocol.ext.allow=never",
		"-c", "http.followRedirects=false",
		"-c", "http.lowSpeedLimit=1000",
		"-c", "http.lowSpeedTime=60",
		"-c", "core.hooksPath=/dev/null",
		"-c", "credential.helper=",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
	}
	if gitDir != "" {
		full = append(full, "--git-dir="+gitDir)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = m.opts.BaseDir
	cmd.Env = m.env()
	cmd.Stdin = stdin
	// Own process group, so cancellation also reaches ssh and remote helpers:
	// SIGTERM to the group, SIGKILL to the group killDelay later.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var kill *time.Timer
	cmd.Cancel = func() error {
		pgid := -cmd.Process.Pid
		kill = time.AfterFunc(m.killDelay, func() { _ = syscall.Kill(pgid, syscall.SIGKILL) })
		return syscall.Kill(pgid, syscall.SIGTERM)
	}
	// Past this, Wait stops waiting for pipes the group still holds.
	cmd.WaitDelay = m.killDelay + time.Second
	var out, errBuf bytes.Buffer
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = &out
	}
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if kill != nil {
		kill.Stop() // git has exited; do not signal a group id that may be reused
	}
	if err != nil {
		return nil, &gitError{args: args[0], err: err, stderr: m.redact(errBuf.String())}
	}
	return out.Bytes(), nil
}

func (m *Mirror) env() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	env = append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"LC_ALL=C",
		"LANGUAGE=",
	)
	if m.opts.Token != "" {
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http.extraHeader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+m.basic(),
		)
	}
	if m.opts.SSHKeyPath != "" || m.opts.KnownHostsPath != "" {
		cmd := "ssh -F /dev/null"
		if m.opts.SSHKeyPath != "" {
			cmd += " -i " + m.opts.SSHKeyPath
		}
		cmd += " -o IdentitiesOnly=yes -o UserKnownHostsFile=" + m.opts.KnownHostsPath + " -o GlobalKnownHostsFile=/dev/null" +
			" -o StrictHostKeyChecking=yes -o BatchMode=yes" +
			" -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"
		env = append(env, "GIT_SSH_COMMAND="+cmd)
	}
	return env
}

func (m *Mirror) basic() string {
	return base64.StdEncoding.EncodeToString([]byte("x-access-token:" + m.opts.Token))
}

func (m *Mirror) redact(s string) string {
	if m.opts.Token == "" {
		return s
	}
	return strings.NewReplacer(m.basic(), "***", m.opts.Token, "***").Replace(s)
}

// TreeEntry is one entry of a recursive tree listing. Type is "blob" for
// files and symlinks and "commit" for submodules (gitlinks).
type TreeEntry struct {
	Mode, Type, Object, Path string
}

// checkPath accepts a clean, relative, repository path that git cannot read
// as an option.
func checkPath(p string) error {
	if p == "" || strings.HasPrefix(p, "-") || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n") || path.Clean(p) != p {
		return fmt.Errorf("gitmirror: invalid path %q", p)
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == ".." {
			return fmt.Errorf("gitmirror: invalid path %q", p)
		}
	}
	return nil
}

// ListTree lists every file, symlink and submodule under dir ("" = the whole
// tree) at commit, with paths from the repository root.
func (m *Mirror) ListTree(ctx context.Context, commit, dir string) ([]TreeEntry, error) {
	if err := checkCommit(commit); err != nil {
		return nil, err
	}
	args := []string{"ls-tree", "-r", "-z", "--full-tree", commit}
	if dir != "" {
		if err := checkPath(dir); err != nil {
			return nil, err
		}
		args = append(args, "--", dir)
	}
	out, err := m.git(ctx, m.dir, nil, nil, args...)
	if err != nil {
		return nil, err
	}
	var entries []TreeEntry
	for rec := range strings.SplitSeq(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if rec == "" {
			continue
		}
		meta, p, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return nil, fmt.Errorf("gitmirror: unexpected ls-tree output %q", rec)
		}
		entries = append(entries, TreeEntry{Mode: f[0], Type: f[1], Object: f[2], Path: p})
	}
	return entries, nil
}

// ArchiveTar writes the tar archive of the given paths at commit, honouring
// export-ignore from the commit's attributes.
func (m *Mirror) ArchiveTar(ctx context.Context, commit string, paths []string, w io.Writer) error {
	if err := checkCommit(commit); err != nil {
		return err
	}
	args := []string{"archive", "--format=tar", commit, "--"}
	for _, p := range paths {
		if err := checkPath(p); err != nil {
			return err
		}
		args = append(args, p)
	}
	_, err := m.git(ctx, m.dir, nil, w, args...)
	return err
}

// IsAncestor reports whether commit a is an ancestor of (or equal to) b.
func (m *Mirror) IsAncestor(ctx context.Context, a, b string) (bool, error) {
	if err := checkCommit(a); err != nil {
		return false, err
	}
	if err := checkCommit(b); err != nil {
		return false, err
	}
	_, err := m.git(ctx, m.dir, nil, nil, "merge-base", "--is-ancestor", a, b)
	if ee, ok := errors.AsType[*exec.ExitError](err); ok && ee.ExitCode() == 1 {
		return false, nil
	}
	return err == nil, err
}

// CommitTime returns the committer time of commit.
func (m *Mirror) CommitTime(ctx context.Context, commit string) (time.Time, error) {
	if err := checkCommit(commit); err != nil {
		return time.Time{}, err
	}
	out, err := m.git(ctx, m.dir, nil, nil, "show", "-s", "--format=%ct", commit+"^{commit}")
	if err != nil {
		return time.Time{}, err
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("gitmirror: unexpected commit time %q", out)
	}
	return time.Unix(sec, 0).UTC(), nil
}
