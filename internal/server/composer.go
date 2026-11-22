package server

import (
	"fmt"
	"path/filepath"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/composer"
	"github.com/radiergummi/tspackages/internal/limits"
	"github.com/radiergummi/tspackages/internal/pins"
	"github.com/radiergummi/tspackages/internal/web"
)

// buildComposer builds the Composer endpoint from e's sources in order.
func buildComposer(sh *shared, e config.Ecosystem) (built, error) {
	var (
		sources    []composer.Source
		status     []web.StatusSource
		gitSources []*composer.GitSource
		regSources []*composer.RegistrySource
	)
	for _, s := range e.Sources {
		switch s.Type {
		case "storage":
			src := composer.NewStorageSource(s.Name, s.Claims, sh.stores.hosted[s.Store], sh.records, sh.archive, sh.log)
			sources, status = append(sources, src), append(status, src)
		case "registry":
			client, err := sh.upstream(s)
			if err != nil {
				return built{}, fmt.Errorf("composer source %q: %w", s.Name, err)
			}
			src := composer.NewRegistrySource(s.Name, s.Claims, s.URL, client, sh.cache, sh.relay, sh.records,
				s.MetadataTTL, int64(sh.cfg.Limits.MaxArtifactBytes), 0, limits.UpstreamWait, sh.log)
			sources, status = append(sources, src), append(status, src)
			regSources = append(regSources, src)
		case "git":
			ms, err := sh.mirrors(s, filepath.Join(sh.keyDir, s.Name), s.Remotes)
			if err != nil {
				return built{}, fmt.Errorf("composer source %q: %w", s.Name, err)
			}
			src, err := composer.NewGitSource(s.Name, s.Claims, s.Branches, ms, sh.pins, sh.records, sh.stores.state,
				s.PollInterval, sh.log, min(int64(sh.cfg.Limits.MaxArtifactBytes), composer.MaxGitArchiveBytes))
			if err != nil {
				return built{}, err
			}
			sources, status = append(sources, src), append(status, src)
			gitSources = append(gitSources, src)
		}
	}

	b := built{eco: composer.New(sources, sh.archive, sh.log), status: status}
	for _, g := range gitSources {
		b.loops = append(b.loops, g.Run)
	}
	b.section = composer.StatusSection(
		func() []composer.Conflict {
			var out []composer.Conflict
			for _, g := range gitSources {
				out = append(out, g.Conflicts()...)
			}
			return out
		},
		func() []composer.ChangedDist {
			var out []composer.ChangedDist
			for _, r := range regSources {
				out = append(out, r.ChangedDists()...)
			}
			return out
		},
		func(m pins.MovedTag) string {
			for _, g := range gitSources {
				if p := g.MovedPackage(m); p != "" {
					return p
				}
			}
			return ""
		})
	return b, nil
}
