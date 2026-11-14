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

	scratchMu sync.Mutex // guards creation of the module-archive scratch repository; never held with mu

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

// refFormat is the for-each-ref format parseRefs reads.
const refFormat = "--format=%(refname)%00%(objecttype)%00%(objectname)%00%(*objecttype)%00%(*objectname)"

// Refs lists tags and branches whose target is a commit; annotated tags
// (including nested ones) are peeled to the commit.
func (m *Mirror) Refs(ctx context.Context) ([]Ref, error) {
	out, err := m.git(ctx, m.dir, nil, nil, "for-each-ref", refFormat, "refs/tags", "refs/heads")
	if err != nil {
		return nil, err
	}
	return parseRefs(out)
}

// parseRefs reads for-each-ref output in refFormat: the tags and branches
// whose target, peeled, is a commit.
func parseRefs(out []byte) ([]Ref, error) {
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

// ErrTooLarge is wrapped by ReadFile and ReadFileMax for a file over the cap.
var ErrTooLarge = errors.New("file over the read limit")

// ErrNoCommit is wrapped, together with resolve.ErrNotFound, by ReadFile and
// ReadFileMax when the commit itself is missing, so callers can tell it from
// a missing path (a mirror re-created from a remote that dropped the commit
// is not the commit's content).
var ErrNoCommit = errors.New("commit not in the mirror")

// ReadFile returns the content of the regular file path at commit. A missing
// path or commit wraps resolve.ErrNotFound; files over 1 MiB wrap ErrTooLarge
// (this is for small manifests such as composer.json and go.mod).
func (m *Mirror) ReadFile(ctx context.Context, commit, path string) ([]byte, error) {
	return m.ReadFileMax(ctx, commit, path, maxReadFile)
}

// ReadFileMax is ReadFile with the cap max: a missing path or commit, or a
// path naming a tree or gitlink, wraps resolve.ErrNotFound (a missing commit
// also wraps ErrNoCommit); a blob over max wraps ErrTooLarge. A symlink's blob (its target text) is returned as is.
func (m *Mirror) ReadFileMax(ctx context.Context, commit, path string, max int64) ([]byte, error) {
	if err := checkCommit(commit); err != nil {
		return nil, err
	}
	// cat-file reads its input by line and drops a trailing "\r", so such
	// a path would be looked up as another one.
	if path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\n\r") {
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
	if strings.HasSuffix(lines[0], " missing") {
		return nil, fmt.Errorf("gitmirror: %s: %w: %w", commit, ErrNoCommit, resolve.ErrNotFound)
	}
	notFound := fmt.Errorf("gitmirror: %s:%s: %w", commit, path, resolve.ErrNotFound)
	if strings.HasSuffix(lines[1], " missing") {
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
	if size > max {
		return nil, fmt.Errorf("gitmirror: %s:%s is %d bytes: %w of %d bytes", commit, path, size, ErrTooLarge, max)
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

// ErrArchiveFailed is wrapped by ArchiveModuleZip when git archive exits
// non-zero for a reason in the commit's content (an unknown commit or
// subdirectory, an unreadable object), as opposed to a cancelled context or a
// failing writer.
var ErrArchiveFailed = errors.New("git archive failed")

// moduleArchiveCmd returns the arguments (after --git-dir) and environment of
// the module archive command. The -c options and GIT_ATTR_NOSYSTEM keep user
// and system configuration and attributes out of the archive.
func (m *Mirror) moduleArchiveCmd(commit, subdir string) (args, env []string) {
	args = []string{
		"-c", "core.autocrlf=input",
		"-c", "core.eol=lf",
		"-c", "core.attributesFile=/dev/null",
		"archive", "--format=zip", "-0", "--prefix=prefix/", commit,
	}
	if subdir != "" {
		args = append(args, "--", subdir)
	}
	return args, append(m.env(), "GIT_ATTR_NOSYSTEM=1")
}

// scratchDir is the module-archive scratch repository of this mirror.
func (m *Mirror) scratchDir() string {
	return strings.TrimSuffix(m.dir, ".git") + ".go-archive"
}

// ensureScratch creates the scratch repository if it is missing or lacks its
// alternates file. It takes scratchMu, never mu: Sync can hold mu for minutes.
// Its info/attributes switch export-subst and export-ignore off, which the
// shared mirror must not do for other archives; alternates make the mirror's
// objects readable (safe because the mirror runs with gc.auto=0 and fetch
// --prune drops refs, not objects).
func (m *Mirror) ensureScratch(ctx context.Context) (string, error) {
	m.scratchMu.Lock()
	defer m.scratchMu.Unlock()
	dir := m.scratchDir()
	if _, err := os.Stat(filepath.Join(dir, "objects", "info", "alternates")); err == nil {
		return dir, nil
	}
	tmp := dir + ".tmp"
	for _, d := range []string{tmp, dir} {
		if err := os.RemoveAll(d); err != nil {
			return "", fmt.Errorf("gitmirror: clear scratch repository: %w", err)
		}
	}
	if _, err := m.git(ctx, "", nil, nil, "init", "--bare", "--quiet", tmp); err != nil {
		return "", err
	}
	for name, content := range map[string]string{
		filepath.Join("objects", "info", "alternates"): filepath.Join(m.dir, "objects") + "\n",
		filepath.Join("info", "attributes"):            "* -export-subst -export-ignore\n",
	} {
		p := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return "", err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		return "", err
	}
	return dir, nil
}

// failWriter remembers the first error of the wrapped writer.
type failWriter struct {
	w   io.Writer
	err error
}

func (f *failWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if err != nil && f.err == nil {
		f.err = err
	}
	return n, err
}

// ArchiveModuleZip writes `git archive --format=zip -0 --prefix=prefix/
// <commit> [-- <subdir>]` to w, run in a scratch repository with export-ignore
// and export-subst off and no user or system attributes. It never takes mu.
// A writer error (such as the caller's size cap) is returned as is; a git
// failure caused by content wraps ErrArchiveFailed. Anything already written
// to w is invalid when an error is returned.
func (m *Mirror) ArchiveModuleZip(ctx context.Context, commit, subdir string, w io.Writer) error {
	if err := checkCommit(commit); err != nil {
		return err
	}
	if subdir != "" {
		if err := checkPath(subdir); err != nil {
			return err
		}
	}
	dir, err := m.ensureScratch(ctx)
	if err != nil {
		return err
	}
	args, env := m.moduleArchiveCmd(commit, subdir)
	fw := &failWriter{w: w}
	_, err = m.gitEnv(ctx, dir, env, nil, fw, args...)
	switch {
	case err == nil:
		return nil
	case fw.err != nil:
		return fw.err
	case ctx.Err() != nil:
		return err
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.Exited() {
		return fmt.Errorf("%w: %w", ErrArchiveFailed, err)
	}
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
	return m.gitEnv(ctx, gitDir, m.env(), stdin, stdout, args...)
}

// gitEnv is git with an explicit environment.
func (m *Mirror) gitEnv(ctx context.Context, gitDir string, env []string, stdin io.Reader, stdout io.Writer, args ...string) ([]byte, error) {
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
		// Paths go to git as the tree lists them; on macOS git would
		// otherwise turn a decomposed (NFD) path into one the tree lacks.
		"-c", "core.precomposeunicode=false",
	}
	if gitDir != "" {
		full = append(full, "--git-dir="+gitDir)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = m.opts.BaseDir
	cmd.Env = env
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
		return nil, &gitError{args: subcommand(args), err: err, stderr: m.redact(errBuf.String())}
	}
	return out.Bytes(), nil
}

// subcommand names the git command in args, skipping leading "-c <config>"
// pairs.
func subcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" {
			i++
			continue
		}
		return args[i]
	}
	return ""
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
		"GIT_LITERAL_PATHSPECS=1", // repository paths carry no ":" magic or globs
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

// MaxTreeEntries caps a ListTree: a few tree objects can name millions of
// paths.
const MaxTreeEntries = 100_000

// ErrTreeTooLarge is wrapped by ListTree for a tree with more than
// MaxTreeEntries entries, a path over MaxTreePath bytes or MaxTreeDepth
// levels, or a listing over maxTreeListing bytes.
var ErrTreeTooLarge = errors.New("tree too large to list")

// MaxTreePath caps a ListTree path, which ls-tree repeats in full for every
// entry under it, MaxTreeDepth its levels, and maxTreeListing the whole
// listing.
const (
	MaxTreePath    = 4 << 10
	MaxTreeDepth   = 256
	maxTreeListing = 64 << 20
)

// ListTree lists every file, symlink and submodule under dir ("" = the whole
// tree) at commit, with paths from the repository root. The listing is parsed
// while git writes it and stops at MaxTreeEntries, a path over MaxTreePath
// bytes or MaxTreeDepth levels, or a listing over maxTreeListing bytes
// (ErrTreeTooLarge).
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
	tp := &treeParser{}
	_, err := m.git(ctx, m.dir, nil, tp, args...)
	if tp.err != nil {
		return nil, tp.err // git died of the closed pipe; the cause is ours
	}
	if err != nil {
		return nil, err
	}
	if len(tp.buf) > 0 {
		return nil, fmt.Errorf("gitmirror: unexpected ls-tree output %q", tp.buf)
	}
	return tp.entries, nil
}

// treeParser parses `ls-tree -z` output as it is written.
type treeParser struct {
	buf     []byte
	entries []TreeEntry
	read    int
	err     error
}

func (tp *treeParser) Write(b []byte) (int, error) {
	if tp.err != nil {
		return 0, tp.err
	}
	if tp.read += len(b); tp.read > maxTreeListing {
		tp.err = fmt.Errorf("gitmirror: %w: a listing over %d bytes", ErrTreeTooLarge, maxTreeListing)
		return 0, tp.err
	}
	tp.buf = append(tp.buf, b...)
	start := 0
	for {
		i := bytes.IndexByte(tp.buf[start:], 0)
		if i < 0 {
			break
		}
		rec := string(tp.buf[start : start+i])
		start += i + 1
		if rec == "" {
			continue
		}
		meta, p, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		switch {
		case !ok || len(f) != 3:
			tp.err = fmt.Errorf("gitmirror: unexpected ls-tree output %q", rec)
		case len(p) > MaxTreePath:
			tp.err = fmt.Errorf("gitmirror: %w: a path over %d bytes", ErrTreeTooLarge, MaxTreePath)
		case strings.Count(p, "/") >= MaxTreeDepth:
			tp.err = fmt.Errorf("gitmirror: %w: a path over %d levels", ErrTreeTooLarge, MaxTreeDepth)
		case len(tp.entries) == MaxTreeEntries:
			tp.err = fmt.Errorf("gitmirror: %w: more than %d entries", ErrTreeTooLarge, MaxTreeEntries)
		}
		if tp.err != nil {
			return 0, tp.err
		}
		tp.entries = append(tp.entries, TreeEntry{Mode: f[0], Type: f[1], Object: f[2], Path: p})
	}
	tp.buf = append(tp.buf[:0], tp.buf[start:]...)
	if len(tp.buf) > MaxTreePath+256 { // a record: mode, type, object, path
		tp.err = fmt.Errorf("gitmirror: %w: a path over %d bytes", ErrTreeTooLarge, MaxTreePath)
		return 0, tp.err
	}
	return len(b), nil
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

// StoredRefPrefix names the hidden refs that keep stored commits in the
// mirror. Sync fetches only refs/heads and refs/tags, so its pruning never
// removes them, and Refs does not list them.
const StoredRefPrefix = "refs/tspackages/stored/"

// revisionLens are the accepted lengths of a commit id prefix.
var revisionLens = func() []int {
	var l []int
	for n := 7; n <= 64; n++ {
		l = append(l, n)
	}
	return l
}()

// ResolveCommit returns the one commit whose id starts with hex (7 to 64
// lowercase hex digits); none or several wrap resolve.ErrNotFound.
func (m *Mirror) ResolveCommit(ctx context.Context, hex string) (string, error) {
	if !digest.IsHex(hex, revisionLens...) {
		return "", fmt.Errorf("gitmirror: invalid revision %q", hex)
	}
	res, err := m.commitsOf(ctx, []string{hex})
	if err != nil {
		return "", err
	}
	if res[0] == "" {
		return "", fmt.Errorf("gitmirror: revision %s: %w", hex, resolve.ErrNotFound)
	}
	return res[0], nil
}

// HasCommit reports whether commit exists in the mirror.
func (m *Mirror) HasCommit(ctx context.Context, commit string) (bool, error) {
	if err := checkCommit(commit); err != nil {
		return false, err
	}
	res, err := m.commitsOf(ctx, []string{commit})
	if err != nil {
		return false, err
	}
	return res[0] == commit, nil
}

// commitsOf peels each of revs (validated hex) to a commit with cat-file
// --batch-check; a missing, ambiguous or non-commit one is "".
func (m *Mirror) commitsOf(ctx context.Context, revs []string) ([]string, error) {
	var in strings.Builder
	for _, r := range revs {
		in.WriteString(r + "^{commit}\n")
	}
	out, err := m.git(ctx, m.dir, strings.NewReader(in.String()), nil, "cat-file", "--batch-check")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != len(revs) {
		return nil, fmt.Errorf("gitmirror: cat-file answered %d lines for %d revisions", len(lines), len(revs))
	}
	res := make([]string, len(revs))
	for i, line := range lines {
		c, err := parseBatchCheck(line)
		switch {
		case errors.Is(err, resolve.ErrNotFound):
		case err != nil:
			return nil, err
		default:
			res[i] = c
		}
	}
	return res, nil
}

// parseBatchCheck reads one line of cat-file --batch-check output for a
// <rev>^{commit} query: the commit id, or resolve.ErrNotFound for a missing
// or ambiguous revision.
func parseBatchCheck(line string) (string, error) {
	f := strings.Fields(line)
	switch {
	case len(f) == 2 && (f[1] == "missing" || f[1] == "ambiguous"):
		return "", fmt.Errorf("gitmirror: %s %s: %w", f[0], f[1], resolve.ErrNotFound)
	case len(f) == 3 && f[1] == "commit" && checkCommit(f[0]) == nil:
		return f[0], nil
	}
	return "", fmt.Errorf("gitmirror: unexpected cat-file line %q", line)
}

// ContainingRefs lists the refs under refs/heads and StoredRefPrefix that
// contain commit, sorted by name.
func (m *Mirror) ContainingRefs(ctx context.Context, commit string) ([]string, error) {
	if err := checkCommit(commit); err != nil {
		return nil, err
	}
	out, err := m.git(ctx, m.dir, nil, nil, "for-each-ref", "--contains", commit, "--format=%(refname)",
		"refs/heads", strings.TrimSuffix(StoredRefPrefix, "/"))
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// MergedTags lists the tags merged into commit (reachable from it), peeled
// as Refs does.
func (m *Mirror) MergedTags(ctx context.Context, commit string) ([]Ref, error) {
	if err := checkCommit(commit); err != nil {
		return nil, err
	}
	out, err := m.git(ctx, m.dir, nil, nil, "for-each-ref", "--merged", commit, refFormat, "refs/tags")
	if err != nil {
		return nil, err
	}
	return parseRefs(out)
}

// EnsureStoredRefs creates StoredRefPrefix+<commit> for every listed commit
// present in the mirror that lacks one, and skips absent commits. It
// removes nothing, and holds the lock Sync holds.
func (m *Mirror) EnsureStoredRefs(ctx context.Context, commits []string) error {
	for _, c := range commits {
		if err := checkCommit(c); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := m.git(ctx, m.dir, nil, nil, "for-each-ref", "--format=%(refname)", strings.TrimSuffix(StoredRefPrefix, "/"))
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for name := range strings.FieldsSeq(string(out)) {
		have[strings.TrimPrefix(name, StoredRefPrefix)] = true
	}
	var missing []string
	for _, c := range commits {
		if !have[c] {
			have[c] = true
			missing = append(missing, c)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	present, err := m.commitsOf(ctx, missing)
	if err != nil {
		return err
	}
	var in strings.Builder
	for i, c := range missing {
		if present[i] == c {
			fmt.Fprintf(&in, "create %s%s %s\n", StoredRefPrefix, c, c)
		}
	}
	if in.Len() == 0 {
		return nil
	}
	_, err = m.git(ctx, m.dir, strings.NewReader(in.String()), nil, "update-ref", "--stdin")
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

// ErrBadCommitTime is wrapped by CommitTime for a committer time git prints
// but an int64 of seconds does not hold: the commit's content, not I/O.
var ErrBadCommitTime = errors.New("unusable commit time")

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
		return time.Time{}, fmt.Errorf("gitmirror: %w %q", ErrBadCommitTime, out)
	}
	return time.Unix(sec, 0).UTC(), nil
}
