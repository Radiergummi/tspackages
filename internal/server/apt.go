package server

import (
	"fmt"
	"slices"

	"github.com/radiergummi/tspackages/internal/config"
	"github.com/radiergummi/tspackages/internal/ecosystem/apt"
	"github.com/radiergummi/tspackages/internal/limits"
	"github.com/radiergummi/tspackages/internal/web"
)

// buildAPT builds the apt endpoint from e's sources in order.
func buildAPT(sh *shared, e config.Ecosystem) (built, error) {
	var signer *apt.Signer
	if slices.ContainsFunc(e.Sources, func(s config.Source) bool { return s.Type == "storage" }) {
		var err error
		if signer, err = apt.LoadSigner(e.SigningKey, e.SigningKeyPassphrase); err != nil {
			return built{}, fmt.Errorf("ecosystems.apt.signing_key: %w", err)
		}
	}
	// A registry source never serves a name any storage source claims.
	claimed := func(name string) bool {
		for _, s := range e.Sources {
			if s.Type == "storage" && slices.ContainsFunc(s.Claims, func(c string) bool { return apt.Match(c, name) }) {
				return true
			}
		}
		return false
	}
	var (
		sources         []apt.Source
		status          []web.StatusSource
		storageNames    []string
		registryStanzas []apt.RegistryStanza
		regs            []*apt.RegistrySource
	)
	maxUpload := int64(sh.cfg.Limits.MaxUploadBytes)
	for _, s := range e.Sources {
		switch s.Type {
		case "storage":
			src := apt.NewStorageSource(s.Name, s.Claims, sh.stores.hosted[s.Store], sh.cache, sh.records, signer, sh.log)
			sources, status = append(sources, src), append(status, src)
			storageNames = append(storageNames, s.Name)
		case "registry":
			client, err := sh.upstream(s)
			if err != nil {
				return built{}, fmt.Errorf("apt source %q: %w", s.Name, err)
			}
			keyring, err := apt.LoadKeyring([]byte(s.Keyring))
			if err != nil {
				return built{}, fmt.Errorf("apt source %q: keyring: %w", s.Name, err)
			}
			src := apt.NewRegistrySource(apt.RegistryConfig{
				Name: s.Name, URL: s.URL, Keyring: keyring,
				Suites: s.Suites, Components: s.Components, Architectures: s.Architectures,
				TTL: s.MetadataTTL, MaxArtifact: int64(sh.cfg.Limits.MaxArtifactBytes), Claimed: claimed,
			}, client, sh.cache, sh.stores.state, sh.relay, sh.records, limits.UpstreamWait, sh.log)
			sources, status = append(sources, src), append(status, src)
			registryStanzas = append(registryStanzas, apt.RegistryStanza{Name: s.Name, Suites: s.Suites, Components: s.Components})
			regs = append(regs, src)
		}
	}
	return built{
		eco:    apt.New(sources, signer, maxUpload, sh.uploadDir, sh.log),
		status: status,
		section: apt.StatusSection(storageNames, registryStanzas, signer, func() []apt.ChangedFile {
			var out []apt.ChangedFile
			for _, r := range regs {
				out = append(out, r.Changed()...)
			}
			return out
		}),
	}, nil
}
