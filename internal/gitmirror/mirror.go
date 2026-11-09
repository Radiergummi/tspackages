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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/radiergummi/tspackages/internal/resolve"
)

// Options configures a Mirror. Secrets arrive as file paths (SSH) or a token
// string (HTTPS).
type Options struct {
	Remote  string
	BaseDir string
	// SSHKeyPath is an absolute path matching sshPathRe. When empty, ssh
	// falls back to its default identity files (and, because the environment
	// is inherited, SSH_AUTH_SOCK); the ssh config is always ignored (-F /dev/null).
	SSHKeyPath     string
	KnownHostsPath string
	Token          string

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
	opts Options
	dir  string

	mu       sync.Mutex // serialises Sync
	stateMu  sync.RWMutex
	lastSync time.Time // guarded by stateMu
}

const (
	maxReadFile = 1 << 20
	headsSpec   = "+refs/heads/*:refs/heads/*"
	tagsSpec    = "+refs/tags/*:refs/tags/*"
)

var (
	commitRe  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	scpRe     = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:[^:]`)
	sshPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@+=,-]+$`)
)

// New validates the options and prepares the mirror directory
// BaseDir/<first 16 hex of sha256(Remote, credential identity)>.git. The
// credential identity keeps mirrors fetched with different credentials apart.
// It does not touch the network.
func New(o Options) (*Mirror, error) {
	kind, err := remoteKind(o.Remote, o.AllowFileRemotesForTesting)
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
		if err := os.Chmod(base, 0o700); err != nil {
			return nil, fmt.Errorf("gitmirror: chmod base dir: %w", err)
		}
	}
	o.BaseDir = base
	identity := o.SSHKeyPath
	if o.Token != "" {
		t := sha256.Sum256([]byte(o.Token))
		identity = hex.EncodeToString(t[:])
	}
	sum := sha256.Sum256([]byte(o.Remote + "\x00" + identity))
	return &Mirror{opts: o, dir: filepath.Join(base, hex.EncodeToString(sum[:])[:16]+".git")}, nil
}

func remoteKind(r string, allowFile bool) (string, error) {
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
				return "", errors.New("gitmirror: remote must not embed credentials; use the token option")
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

// LastSync returns the time of the last successful Sync (zero if none).
func (m *Mirror) LastSync() time.Time {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.lastSync
}

// Sync creates the mirror on first use and fetches branches and tags
// (pruning, force-updating tags) afterwards. Only refs/heads and refs/tags
// are ever fetched. The mirror's HEAD follows the remote's default branch.
func (m *Mirror) Sync(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := os.Stat(filepath.Join(m.dir, "HEAD"))
	switch {
	case err == nil:
		m.removeStaleLocks()
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
	if err := m.followRemoteHead(ctx); err != nil {
		return err
	}
	m.stateMu.Lock()
	m.lastSync = time.Now()
	m.stateMu.Unlock()
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
// killed fetch. All of them, regardless of age: Sync holds m.mu and the
// directory is private to this mirror (keyed by remote and credentials), so no
// live writer can own a lock when Sync starts.
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

// followRemoteHead points the mirror's HEAD at the remote's default branch.
func (m *Mirror) followRemoteHead(ctx context.Context) error {
	out, err := m.git(ctx, m.dir, nil, nil, "ls-remote", "--symref", "--", "origin", "HEAD")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "ref: refs/heads/"); ok {
			branch, _, _ := strings.Cut(rest, "\t")
			if branch == "" {
				continue
			}
			_, err := m.git(ctx, m.dir, nil, nil, "symbolic-ref", "HEAD", "refs/heads/"+branch)
			return err
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
	for _, line := range strings.Split(string(out), "\n") {
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
	if !commitRe.MatchString(commit) {
		return nil, fmt.Errorf("gitmirror: invalid commit %q", commit)
	}
	if path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\n") {
		return nil, fmt.Errorf("gitmirror: invalid path %q", path)
	}
	for _, seg := range strings.Split(path, "/") {
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
	if !commitRe.MatchString(commit) {
		return fmt.Errorf("gitmirror: invalid commit %q", commit)
	}
	_, err := m.git(ctx, m.dir, nil, w, "archive", "--format=zip", commit)
	return err
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
	// Own process group, so cancellation also reaches ssh and remote helpers.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	var out, errBuf bytes.Buffer
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = &out
	}
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
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
		cmd += " -o IdentitiesOnly=yes -o UserKnownHostsFile=" + m.opts.KnownHostsPath +
			" -o StrictHostKeyChecking=yes -o BatchMode=yes"
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
