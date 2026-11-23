package server

import (
	"fmt"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/maven"
	"github.com/radiergummi/tspackages/internal/limits"
	"github.com/radiergummi/tspackages/internal/web"
)

// buildMaven builds the Maven endpoint from e's sources in order.
func buildMaven(sh *shared, e config.Ecosystem) (built, error) {
	var (
		sources []maven.Source
		status  []web.StatusSource
		regs    []*maven.RegistrySource
	)
	maxUpload := int64(sh.cfg.Limits.MaxUploadBytes)
	for _, s := range e.Sources {
		switch s.Type {
		case "storage":
			src := maven.NewStorageSource(s.Name, s.Claims, sh.stores.hosted[s.Store], sh.records, maxUpload, sh.log)
			sources, status = append(sources, src), append(status, src)
		case "registry":
			client, err := sh.upstream(s)
			if err != nil {
				return built{}, fmt.Errorf("maven source %q: %w", s.Name, err)
			}
			src := maven.NewRegistrySource(s.Name, s.Claims, s.URL, client, sh.cache, sh.relay, sh.records,
				s.MetadataTTL, int64(sh.cfg.Limits.MaxArtifactBytes), limits.UpstreamWait, sh.uploadDir, sh.log)
			sources, status = append(sources, src), append(status, src)
			regs = append(regs, src)
		}
	}
	return built{
		eco:    maven.New(sources, maxUpload, sh.uploadDir, sh.log),
		status: status,
		section: maven.StatusSection(func() []maven.ChangedFile {
			var out []maven.ChangedFile
			for _, r := range regs {
				out = append(out, r.Changed()...)
			}
			return out
		}),
	}, nil
}
