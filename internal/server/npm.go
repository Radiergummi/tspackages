package server

import (
	"fmt"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/npm"
	"github.com/radiergummi/tspackages/internal/limits"
	"github.com/radiergummi/tspackages/internal/web"
)

// buildNPM builds the npm endpoint from e's sources in order.
func buildNPM(sh *shared, e config.Ecosystem) (built, error) {
	var (
		sources []npm.Source
		status  []web.StatusSource
		regs    []*npm.RegistrySource
	)
	maxUpload := int64(sh.cfg.Limits.MaxUploadBytes)
	for _, s := range e.Sources {
		switch s.Type {
		case "storage":
			src := npm.NewStorageSource(s.Name, s.Claims, sh.stores.hosted[s.Store], sh.records, sh.archive,
				maxUpload, sh.uploadDir, sh.log)
			sources, status = append(sources, src), append(status, src)
		case "registry":
			client, err := sh.upstream(s)
			if err != nil {
				return built{}, fmt.Errorf("npm source %q: %w", s.Name, err)
			}
			src := npm.NewRegistrySource(s.Name, s.Claims, s.URL, client, sh.cache, sh.relay, sh.records,
				s.MetadataTTL, int64(sh.cfg.Limits.MaxArtifactBytes), limits.UpstreamWait, sh.uploadDir, sh.log)
			sources, status = append(sources, src), append(status, src)
			regs = append(regs, src)
		}
	}
	return built{
		eco:    npm.New(sources, maxUpload, sh.uploadDir, sh.log),
		status: status,
		section: npm.StatusSection(func() []npm.ChangedTarball {
			var out []npm.ChangedTarball
			for _, r := range regs {
				out = append(out, r.Changed()...)
			}
			return out
		}),
	}, nil
}
