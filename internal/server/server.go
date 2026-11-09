// Package server assembles tspackages' components into one HTTP handler.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

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

// cacheRoot is the local directory for git mirrors and SSH key files.
// Replaced in tests.
var cacheRoot = func() string {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "tspackages")
}

// sshPathRe mirrors gitmirror's allowlist for SSH key and known_hosts paths.
var sshPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@+=,-]+$`)

type namedStore struct {
	name string
	d    storage.Driver
}

// Build validates cfg, opens and probes every store, builds the sources in
// config order and returns the handler (identity → rate limits → routes) and a
// function that starts the background loops. SSH key material is written to
// a 0700 directory that is removed when ctx ends.
func Build(ctx context.Context, cfg *config.Config, who identity.Whoiser, log *slog.Logger, h Hooks) (http.Handler, func(context.Context), error) {
	if err := config.Validate(cfg); err != nil {
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
	cache, err := storage.NewCache(ctx, cacheDriver, int64(cfg.Storage.Cache.MaxSize))
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
		keys       *keyDir
	)
	fail := func(err error) (http.Handler, func(context.Context), error) {
		if keys != nil {
			keys.remove()
		}
		return nil, nil, err
	}
	eco, hasComposer := cfg.Ecosystems["composer"]
	for i, s := range eco.Sources {
		switch s.Type {
		case "storage":
			src := composer.NewStorageSource(s.Name, s.Claims, named[s.Store], rec, archiveLimits)
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
				s.MetadataTTL, int64(l.MaxDecompressedBytes), 0, limits.UpstreamWait)
			sources, status = append(sources, src), append(status, src)
		case "git":
			opts := gitmirror.Options{
				BaseDir:                    filepath.Join(cacheRoot(), "git"),
				Token:                      s.Token,
				AllowFileRemotesForTesting: h.AllowFileRemotes,
			}
			if s.SSHKey != "" || s.KnownHosts != "" {
				if keys == nil {
					if keys, err = newKeyDir(ctx, cacheRoot()); err != nil {
						return fail(err)
					}
				}
				if opts.SSHKeyPath, err = keys.write(strconv.Itoa(i)+".key", s.SSHKey); err != nil {
					return fail(err)
				}
				if opts.KnownHostsPath, err = keys.write(strconv.Itoa(i)+".known-hosts", s.KnownHosts); err != nil {
					return fail(err)
				}
			}
			var mirrors []*gitmirror.Mirror
			for _, remote := range s.Remotes {
				opts.Remote = remote
				m, err := gitmirror.New(opts)
				if err != nil {
					return fail(fmt.Errorf("composer source %q: %w", s.Name, err))
				}
				mirrors = append(mirrors, m)
			}
			src, err := composer.NewGitSource(s.Name, s.Claims, s.Branches, mirrors, pinStore, rec, stateDriver,
				s.PollInterval, log, int64(l.MaxDecompressedBytes))
			if err != nil {
				return fail(err)
			}
			sources, status = append(sources, src), append(status, src)
			gitSources = append(gitSources, src)
		}
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
		for _, g := range gitSources {
			go g.Run(ctx)
		}
		go func() {
			<-ctx.Done()
			limiter.Close()
		}()
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

// keyDir holds SSH key material expanded from the configuration.
type keyDir struct{ path string }

func newKeyDir(ctx context.Context, parent string) (*keyDir, error) {
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	p, err := os.MkdirTemp(parent, "keys-")
	if err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	k := &keyDir{path: p}
	if !sshPathRe.MatchString(p) {
		k.remove()
		return nil, fmt.Errorf("key directory %q must use only [A-Za-z0-9._/@+=,-]", p)
	}
	context.AfterFunc(ctx, k.remove)
	return k, nil
}

// write stores content in a 0600 file and returns its path, or "" for empty content.
func (k *keyDir) write(name, content string) (string, error) {
	if content == "" {
		return "", nil
	}
	p := filepath.Join(k.path, name)
	// ssh rejects a private key without a trailing newline.
	if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write key file: %w", err)
	}
	return p, nil
}

func (k *keyDir) remove() { _ = os.RemoveAll(k.path) }
