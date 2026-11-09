// Package server assembles tspackages' components into one HTTP handler.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/radiergummi/tspackages/internal/archive"
	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem"
	"github.com/radiergummi/tspackages/internal/ecosystem/composer"
	"github.com/radiergummi/tspackages/internal/gitmirror"
	"github.com/radiergummi/tspackages/internal/identity"
	"github.com/radiergummi/tspackages/internal/limits"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
	"github.com/radiergummi/tspackages/internal/web"
	"github.com/radiergummi/tspackages/internal/workdir"
	"tailscale.com/tailcfg"
)

// Hooks are test-only escape hatches. main passes the zero value.
type Hooks struct {
	AllowPrivateUpstreams bool // upstream.Options.AllowPrivateForTesting
	AllowFileRemotes      bool // gitmirror.Options.AllowFileRemotesForTesting
}

// onMirror is called for every mirror Build creates. Replaced in tests.
var onMirror = func(*gitmirror.Mirror) {}

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
	if err := stores.ready(ctx); err != nil {
		return nil, nil, fmt.Errorf("store unreachable: %w", err)
	}
	cache, err := storage.NewCache(ctx, stores.cache, int64(cfg.Storage.Cache.MaxSize), log)
	if err != nil {
		return nil, nil, fmt.Errorf("storage.cache: %w", err)
	}
	pinStore := pins.New(stores.state)
	rec := records.New(stores.state)

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
			src := composer.NewStorageSource(s.Name, s.Claims, stores.hosted[s.Store], rec, archiveLimits, log)
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
			src, err := composer.NewGitSource(s.Name, s.Claims, s.Branches, ms, pinStore, rec, stores.state,
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
	movedPkg := func(m pins.MovedTag) string {
		for _, g := range gitSources {
			if p := g.MovedPackage(m); p != "" {
				return p
			}
		}
		return ""
	}
	metrics.SetRejected(limiter.Rejected)
	web.New(cfg.Tailscale.Hostname, ecos, status, pinStore.Moved, movedPkg, conflicts, stores.ready).Mount(mux)

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

type openedStores struct {
	cache, state storage.Driver
	hosted       map[string]storage.Driver // by name in storage.stores
	all          []openedStore             // in config.Storage.Named order
}

type openedStore struct {
	path string
	d    storage.Driver
}

// openStores opens every configured store.
func openStores(ctx context.Context, s config.Storage) (*openedStores, error) {
	out := &openedStores{hosted: map[string]storage.Driver{}}
	for _, n := range s.Named() {
		d, err := storage.Open(ctx, n.Config)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n.Path, err)
		}
		switch n.Path {
		case "storage.cache":
			out.cache = d
		case "storage.state":
			out.state = d
		default:
			out.hosted[n.Name] = d
		}
		out.all = append(out.all, openedStore{n.Path, d})
	}
	return out, nil
}

// ready probes every store concurrently and returns the first failure in
// store order.
func (s *openedStores) ready(ctx context.Context) error {
	errs := make([]error, len(s.all))
	var wg sync.WaitGroup
	for i, o := range s.all {
		wg.Go(func() {
			if err := storage.Reachable(ctx, o.d); err != nil {
				errs[i] = fmt.Errorf("%s: %w", o.path, err)
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
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
		if err := workdir.EnsurePrivateDir(d); err != nil {
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
