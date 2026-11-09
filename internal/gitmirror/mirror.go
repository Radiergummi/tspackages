// Package gitmirror keeps a bare mirror of one git remote and reads tags,
// files and archives from it by shelling out to the git binary. Credentials
// travel only in the environment of the child process, and only https, ssh
// (and, for tests, file) transports are allowed.
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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/radiergummi/tspackages/internal/resolve"
)

// Options configures a Mirror. Secrets arrive as file paths (SSH) or a token
// string (HTTPS).
type Options struct {
	Remote         string
	BaseDir        string
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

// Mirror is a bare clone of a remote.
type Mirror struct {
	opts Options
	dir  string

	mu       sync.Mutex // serialises Sync
	lastSync time.Time  // guarded by stateMu
	stateMu  sync.RWMutex
}

var (
	commitRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	scpRe    = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:[^:]`)
)

// New validates the options and prepares the mirror directory
// BaseDir/<first 16 hex of sha256(Remote)>.git. It does not touch the network.
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
			if strings.ContainsAny(p, " \t\r\n\"'\\$`") {
				return nil, fmt.Errorf("gitmirror: ssh path %q contains whitespace or quote characters", p)
			}
		}
	}
	if o.BaseDir == "" {
		return nil, errors.New("gitmirror: BaseDir is required")
	}
	if err := os.MkdirAll(o.BaseDir, 0o700); err != nil {
		return nil, fmt.Errorf("gitmirror: create base dir: %w", err)
	}
	sum := sha256.Sum256([]byte(o.Remote))
	return &Mirror{opts: o, dir: filepath.Join(o.BaseDir, hex.EncodeToString(sum[:])[:16]+".git")}, nil
}

func remoteKind(r string, allowFile bool) (string, error) {
	if r == "" || strings.HasPrefix(r, "-") || strings.ContainsAny(r, "\x00\r\n\t ") || strings.Contains(r, "::") {
		return "", fmt.Errorf("gitmirror: unsupported remote %q", r)
	}
	switch {
	case strings.HasPrefix(r, "https://"):
		return "https", nil
	case strings.HasPrefix(r, "ssh://"):
		return "ssh", nil
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

// LastSync returns the time of the last successful Sync (zero if none).
func (m *Mirror) LastSync() time.Time {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.lastSync
}

// Sync clones the remote on first use and fetches (pruning, force-updating
// tags) afterwards.
func (m *Mirror) Sync(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := os.Stat(filepath.Join(m.dir, "HEAD")); err != nil {
		// Clone into a scratch dir so an interrupted clone never leaves a
		// half-built mirror behind.
		tmp := m.dir + ".tmp"
		if err := os.RemoveAll(tmp); err != nil {
			return err
		}
		if _, err := m.run(ctx, m.opts.BaseDir, nil, "clone", "--mirror", "--", m.opts.Remote, tmp); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
		if err := os.RemoveAll(m.dir); err != nil {
			return err
		}
		if err := os.Rename(tmp, m.dir); err != nil {
			return err
		}
	} else if _, err := m.run(ctx, m.dir, nil, "fetch", "--prune", "--prune-tags", "--",
		"origin", "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"); err != nil {
		return err
	}
	m.stateMu.Lock()
	m.lastSync = time.Now()
	m.stateMu.Unlock()
	return nil
}

// Refs lists tags and branches whose target is a commit; annotated tags are
// peeled.
func (m *Mirror) Refs(ctx context.Context) ([]Ref, error) {
	out, err := m.run(ctx, m.dir, nil, "for-each-ref",
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

// DefaultBranch returns the branch the mirror's HEAD points to.
func (m *Mirror) DefaultBranch(ctx context.Context) (string, error) {
	out, err := m.run(ctx, m.dir, nil, "symbolic-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "refs/heads/"), nil
}

// ReadFile returns the content of path at commit. A missing path or commit
// wraps resolve.ErrNotFound.
func (m *Mirror) ReadFile(ctx context.Context, commit, path string) ([]byte, error) {
	if !commitRe.MatchString(commit) {
		return nil, fmt.Errorf("gitmirror: invalid commit %q", commit)
	}
	if path == "" || strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("gitmirror: invalid path %q", path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return nil, fmt.Errorf("gitmirror: invalid path %q", path)
		}
	}
	out, err := m.run(ctx, m.dir, nil, "cat-file", "blob", commit+":"+path)
	if err != nil {
		var ge *gitError
		if errors.As(err, &ge) && notFoundRe.MatchString(ge.stderr) {
			return nil, fmt.Errorf("gitmirror: %s:%s: %w", commit, path, resolve.ErrNotFound)
		}
		return nil, err
	}
	return out, nil
}

var notFoundRe = regexp.MustCompile(`does not exist|invalid object name|Not a valid object name|bad file|not a blob|exists on disk, but not in`)

// ArchiveZip streams a zip of the tree at commit to w, honouring
// export-ignore.
func (m *Mirror) ArchiveZip(ctx context.Context, commit string, w io.Writer) error {
	if !commitRe.MatchString(commit) {
		return fmt.Errorf("gitmirror: invalid commit %q", commit)
	}
	_, err := m.run(ctx, m.dir, w, "archive", "--format=zip", commit)
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

// run executes git. With a non-nil stdout writer the output is streamed there
// and the returned bytes are nil.
func (m *Mirror) run(ctx context.Context, dir string, stdout io.Writer, args ...string) ([]byte, error) {
	fileAllow := "never"
	if m.opts.AllowFileRemotesForTesting {
		fileAllow = "always"
	}
	full := append([]string{
		"-c", "protocol.file.allow=" + fileAllow,
		"-c", "protocol.ext.allow=never",
		"-c", "core.hooksPath=/dev/null",
		"-c", "credential.helper=",
	}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	cmd.Env = m.env()
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
	)
	if m.opts.Token != "" {
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http.extraHeader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+m.basic(),
		)
	}
	if m.opts.SSHKeyPath != "" || m.opts.KnownHostsPath != "" {
		cmd := "ssh"
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
