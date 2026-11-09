// Package server assembles tspackages' components into one HTTP handler.
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/ecosystem/composer"
	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/limits"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
	"github.com/radiergummi/tspackages/internal/web"
	"golang.org/x/sys/unix"
	"tailscale.com/tailcfg"
)

// Hooks are test-only escape hatches. main passes the zero value.
type Hooks struct {
	AllowPrivateUpstreams bool // upstream.Options.AllowPrivateForTesting
	AllowFileRemotes      bool // gitmirror.Options.AllowFileRemotesForTesting
}

// probeKey is read to check that a store is reachable; ErrNotFound counts as
// reachable.
const probeKey = ".tspackages-probe"

// onMirror is called for every mirror Build creates. Replaced in tests.
var onMirror = func(*gitmirror.Mirror) {}

type namedStore struct {
	name string
	d    storage.Driver
}

// Build validates cfg, opens and probes every store, builds the sources in
// config order and returns the handler (identity → rate limits → routes) and a
// function that runs the background loops until its ctx ends and returns once
// they have stopped (run it in a goroutine). Git mirrors live in
// <work_dir>/git, and directories there that belong to no configured mirror
// are removed; SSH key material is rewritten to <work_dir>/keys
// (<source>.key, <source>.known_hosts) at every start.
func Build(ctx context.Context, cfg *config.Config, who identity.Whoiser, log *slog.Logger, h Hooks) (http.Handler, func(context.Context), error) {
	config.ApplyDefaults(cfg)
	if err := config.ValidateWith(cfg, config.ValidateOptions{
		AllowFileRemotes:   h.AllowFileRemotes,
		AllowHTTPUpstreams: h.AllowPrivateUpstreams,
	}); err != nil {
		return nil, nil, err
	}
	gitDir, keyDir, err := prepareWorkDir(cfg.Storage.WorkDir)
	if err != nil {
		return nil, nil, err
	}

	stores, err := openStores(ctx, cfg.Storage)
	if err != nil {
		return nil, nil, err
	}
	ready := func(ctx context.Context) error {
		for _, s := range stores {
			if _, err := s.d.Stat(ctx, probeKey); err != nil && !errors.Is(err, storage.ErrNotFound) {
				return fmt.Errorf("%s: %w", s.name, err)
			}
		}
		return nil
	}
	if err := ready(ctx); err != nil {
		return nil, nil, fmt.Errorf("store unreachable: %w", err)
	}
	cacheDriver, stateDriver := stores[0].d, stores[1].d
	named := map[string]storage.Driver{}
	for _, s := range stores[2:] {
		named[strings.TrimPrefix(s.name, "storage.stores.")] = s.d
	}
	cache, err := storage.NewCache(ctx, cacheDriver, int64(cfg.Storage.Cache.MaxSize), log)
	if err != nil {
		return nil, nil, fmt.Errorf("storage.cache: %w", err)
	}
	pinStore := pins.New(stateDriver)
	rec := records.New(stateDriver)

	l := cfg.Limits
	archiveLimits := archive.Limits{
		MaxBytes:        int64(l.MaxUploadBytes),
		MaxDecompressed: int64(l.MaxDecompressedBytes),
		MaxEntries:      l.MaxArchiveEntries,
	}

	var (
		sources    []composer.Source
		gitSources []*composer.GitSource
		status     []web.StatusSource
		mirrors    = mirrorSet{}
	)
	fail := func(err error) (http.Handler, func(context.Context), error) { return nil, nil, err }
	eco, hasComposer := cfg.Ecosystems["composer"]
	for _, s := range eco.Sources {
		switch s.Type {
		case "storage":
			src := composer.NewStorageSource(s.Name, s.Claims, named[s.Store], rec, archiveLimits, log)
			sources, status = append(sources, src), append(status, src)
		case "registry":
			creds := maps.Clone(s.DownloadCredentials)
			if s.Credentials != nil {
				u, err := url.Parse(s.URL)
				if err != nil {
					return fail(fmt.Errorf("composer source %q: url: %w", s.Name, err))
				}
				if creds == nil {
					creds = map[string]config.Credential{}
				}
				creds[u.Host] = *s.Credentials
			}
			client := upstream.New(upstream.Options{
				FetchHosts:             s.FetchHosts,
				Credentials:            creds,
				AllowPrivateForTesting: h.AllowPrivateUpstreams,
			})
			src := composer.NewRegistrySource(s.Name, s.Claims, s.URL, client, cache, rec,
				s.MetadataTTL, int64(l.MaxArtifactBytes), 0, limits.UpstreamWait, log)
			sources, status = append(sources, src), append(status, src)
		case "git":
			opts := gitmirror.Options{
				BaseDir:                    gitDir,
				Token:                      s.Token,
				Logger:                     log,
				AllowFileRemotesForTesting: h.AllowFileRemotes,
			}
			// One key per source, under a fixed name, so the mirror directory
			// (derived from the key path) is stable across restarts.
			prefix := filepath.Join(keyDir, s.Name)
			if opts.SSHKeyPath, err = writeSecret(prefix+".key", s.SSHKey); err != nil {
				return fail(fmt.Errorf("composer source %q: %w", s.Name, err))
			}
			if opts.KnownHostsPath, err = writeSecret(prefix+".known_hosts", s.KnownHosts); err != nil {
				return fail(fmt.Errorf("composer source %q: %w", s.Name, err))
			}
			var ms []*gitmirror.Mirror
			for _, remote := range s.Remotes {
				opts.Remote = remote
				m, err := mirrors.get(opts)
				if err != nil {
					return fail(fmt.Errorf("composer source %q: %w", s.Name, err))
				}
				ms = append(ms, m)
			}
			src, err := composer.NewGitSource(s.Name, s.Claims, s.Branches, ms, pinStore, rec, stateDriver,
				s.PollInterval, log, int64(l.MaxArtifactBytes))
			if err != nil {
				return fail(err)
			}
			sources, status = append(sources, src), append(status, src)
			gitSources = append(gitSources, src)
		}
	}

	if err := pruneMirrorDirs(gitDir, mirrors); err != nil {
		return fail(err)
	}

	limiter := limits.New(cfg.Limits)
	mux := http.NewServeMux()
	var ecos []ecosystem.Ecosystem
	if hasComposer {
		c := composer.New(sources, archiveLimits, log)
		c.Mount(mux)
		ecos = append(ecos, c)
	}
	conflicts := func() []composer.Conflict {
		var out []composer.Conflict
		for _, g := range gitSources {
			out = append(out, g.Conflicts()...)
		}
		return out
	}
	w := web.New(cfg.Tailscale.Hostname, ecos, status, pinStore.Moved, conflicts, ready)
	w.SetRejected(limiter.Rejected)
	w.SetMovedPackage(func(m pins.MovedTag) string {
		for _, g := range gitSources {
			if p := g.MovedPackage(m); p != "" {
				return p
			}
		}
		return ""
	})
	w.Mount(mux)

	handler := identity.Middleware(who, tailcfg.PeerCapability(cfg.Tailscale.Capability), log)(limiter.Middleware()(mux))
	start := func(ctx context.Context) {
		var wg sync.WaitGroup
		for _, g := range gitSources {
			wg.Go(func() { g.Run(ctx) })
		}
		<-ctx.Done()
		wg.Wait()
		limiter.Close()
	}
	return handler, start, nil
}

// openStores opens cache, state and the named stores (sorted), in that order.
func openStores(ctx context.Context, s config.Storage) ([]namedStore, error) {
	all := []struct {
		name string
		sc   config.StoreConfig
	}{{"storage.cache", s.Cache}, {"storage.state", s.State}}
	for _, name := range slices.Sorted(maps.Keys(s.Stores)) {
		all = append(all, struct {
			name string
			sc   config.StoreConfig
		}{"storage.stores." + name, s.Stores[name]})
	}
	out := make([]namedStore, 0, len(all))
	for _, a := range all {
		d, err := storage.Open(ctx, a.sc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.name, err)
		}
		out = append(out, namedStore{a.name, d})
	}
	return out, nil
}

// mirrorSet shares one Mirror per mirror directory, which gitmirror derives
// from the remote and the credential (token or SSH key path).
type mirrorSet map[[3]string]*gitmirror.Mirror

func (s mirrorSet) get(o gitmirror.Options) (*gitmirror.Mirror, error) {
	k := [3]string{o.Remote, o.Token, o.SSHKeyPath}
	if m, ok := s[k]; ok {
		return m, nil
	}
	m, err := gitmirror.New(o)
	if err != nil {
		return nil, err
	}
	onMirror(m)
	s[k] = m
	return m, nil
}

// pruneMirrorDirs removes everything in gitDir that is not the directory of a
// configured mirror (old remotes, credentials or scratch dirs). It runs before
// any Sync.
func pruneMirrorDirs(gitDir string, mirrors mirrorSet) error {
	keep := map[string]bool{}
	for _, m := range mirrors {
		keep[filepath.Base(m.Dir())] = true
	}
	entries, err := os.ReadDir(gitDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if keep[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(gitDir, e.Name())); err != nil {
			return fmt.Errorf("prune %s: %w", gitDir, err)
		}
	}
	return nil
}

// prepareWorkDir makes work_dir and its git/ and keys/ subdirectories
// private, and empties keys/ so only the current key material remains.
func prepareWorkDir(dir string) (gitDir, keyDir string, err error) {
	gitDir, keyDir = filepath.Join(dir, "git"), filepath.Join(dir, "keys")
	for _, d := range []string{dir, gitDir, keyDir} {
		if err := EnsurePrivateDir(d); err != nil {
			return "", "", err
		}
	}
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		return "", "", err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(keyDir, e.Name())); err != nil {
			return "", "", fmt.Errorf("clear %s: %w", keyDir, err)
		}
	}
	return gitDir, keyDir, nil
}

// EnsurePrivateDir creates dir with mode 0700 if it is missing, then checks
// that it is a real directory (not a symlink) owned by the current user with
// mode 0700.
func EnsurePrivateDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s must be a directory, not a symlink or file", dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s must be owned by uid %d", dir, os.Getuid())
	}
	if st.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s has mode %04o, want 0700", dir, st.Mode().Perm())
	}
	return nil
}

// writeSecret writes content plus a newline (ssh rejects a key without one)
// to a 0600 file and returns its path, or "" for empty content.
func writeSecret(p, content string) (string, error) {
	if content == "" {
		return "", nil
	}
	if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", p, err)
	}
	return p, nil
}

// LockWorkDir takes an exclusive flock on <dir>/.lock so only one instance
// uses a work_dir. If another holds it, it logs once and waits up to wait
// before failing. dir is created (mode 0700) if missing. The returned
// function releases the lock; the process exiting releases it too.
func LockWorkDir(ctx context.Context, dir string, wait time.Duration, log *slog.Logger) (func(), error) {
	if err := EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, ".lock")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for logged := false; ; {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", p, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("%s is locked by another instance (waited %s)", p, wait)
		}
		if !logged {
			log.Warn("work_dir is locked by another instance; waiting", "path", p, "timeout", wait)
			logged = true
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
