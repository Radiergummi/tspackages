package server

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/pypi"
	"github.com/radiergummi/tspackages/internal/githubapp"
	"github.com/radiergummi/tspackages/internal/limits"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/upstream"
	"github.com/radiergummi/tspackages/internal/web"
	"github.com/radiergummi/tspackages/internal/workdir"
)

// buildPyPI builds the PyPI endpoint from e's sources in order.
func buildPyPI(sh *shared, e config.Ecosystem) (built, error) {
	var (
		sources []pypi.Source
		status  []web.StatusSource
		gitSrcs []*pypi.GitSource
		ghSrcs  []*pypi.GitHubSource
	)
	for _, s := range e.Sources {
		switch s.Type {
		case "storage":
			src := pypi.NewStorageSource(s.Name, s.Claims, sh.stores.hosted[s.Store], sh.records, sh.archive, sh.log)
			sources, status = append(sources, src), append(status, src)
		case "registry":
			client, err := sh.upstream(s)
			if err != nil {
				return built{}, fmt.Errorf("pypi source %q: %w", s.Name, err)
			}
			src := pypi.NewRegistrySource(s.Name, s.Claims, s.URL, client, sh.cache, sh.relay, sh.records,
				s.MetadataTTL, int64(sh.cfg.Limits.MaxArtifactBytes), limits.UpstreamWait, sh.log)
			sources, status = append(sources, src), append(status, src)
		case "git":
			// Key files live in keys/pypi/, where no composer source's can.
			pyKeyDir := filepath.Join(sh.keyDir, "pypi")
			if err := workdir.EnsurePrivateDir(pyKeyDir); err != nil {
				return built{}, err
			}
			ms, err := sh.mirrors(s, filepath.Join(pyKeyDir, s.Name), s.Remotes)
			if err != nil {
				return built{}, fmt.Errorf("pypi source %q: %w", s.Name, err)
			}
			src, err := pypi.NewGitSource(s.Name, s.Claims, ms, s.Tags, sh.stores.state, sh.records, s.PollInterval, sh.log,
				min(int64(sh.cfg.Limits.MaxArtifactBytes), pypi.MaxGitSdistBytes))
			if err != nil {
				return built{}, err
			}
			sources, status = append(sources, src), append(status, src)
			gitSrcs = append(gitSrcs, src)
		case "github":
			src, err := githubSource(sh, s)
			if err != nil {
				return built{}, fmt.Errorf("pypi source %q: %w", s.Name, err)
			}
			sources, status = append(sources, src), append(status, src)
			ghSrcs = append(ghSrcs, src)
		}
	}

	b := built{eco: pypi.New(sources, int64(sh.cfg.Limits.MaxUploadBytes), sh.uploadDir, sh.log), status: status}
	for _, g := range gitSrcs {
		b.loops = append(b.loops, g.Run)
	}
	for _, g := range ghSrcs {
		b.loops = append(b.loops, g.Run)
	}
	b.section = pypi.StatusSection(
		func() []pypi.Conflict {
			var out []pypi.Conflict
			for _, g := range gitSrcs {
				out = append(out, g.Conflicts()...)
			}
			return out
		},
		func() []pypi.Skipped {
			var out []pypi.Skipped
			for _, g := range gitSrcs {
				out = append(out, g.Skipped()...)
			}
			return out
		},
		ghSrcs)
	return b, nil
}

// githubSource builds a github source whose API client reaches GitHub
// Enterprise Server's hosts through the tailnet dialer.
func githubSource(sh *shared, s config.Source) (*pypi.GitHubSource, error) {
	key, err := githubapp.ParseKey(s.PrivateKey)
	if err != nil {
		return nil, err
	}
	fetch, tailnet := config.GitHubFetchHosts(s)
	if len(tailnet) > 0 && sh.dial == nil {
		return nil, errors.New("GitHub Enterprise Server needs the tailnet dialer")
	}
	client := upstream.New(upstream.Options{
		FetchHosts:             fetch,
		TailnetHosts:           tailnet,
		TailnetDial:            sh.dial,
		AllowPrivateForTesting: sh.hooks.AllowPrivateUpstreams,
	})
	app := githubapp.New(client, s.URL, s.AppID, s.InstallationID, key, time.Now)
	app.OnResponse(func(status int) { metrics.ObserveGitHubRequest(s.Name, status) })
	return pypi.NewGitHubSource(s.Name, s.Claims, app, s.URL, sh.stores.state, sh.relay, sh.records,
		s.PollInterval, int64(sh.cfg.Limits.MaxArtifactBytes), sh.log), nil
}
