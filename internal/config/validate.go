package config

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Validate returns every problem found in c, joined with errors.Join.
func Validate(c *Config) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	errs = append(errs, validateStores(&c.Storage)...)

	for eco, e := range c.Ecosystems {
		if eco != "composer" {
			add("ecosystem %q is not supported yet", eco)
			continue
		}
		errs = append(errs, validateSources(eco, e.Sources, c.Storage.Stores)...)
	}
	return errors.Join(errs...)
}

func validateStores(s *Storage) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	check := func(name string, sc StoreConfig) {
		switch sc.Driver {
		case "fs":
			if sc.Path == "" {
				add("%s: path is required for the fs driver", name)
			}
		case "s3":
			if sc.Bucket == "" {
				add("%s: bucket is required for the s3 driver", name)
			}
		default:
			add("%s: driver must be fs or s3, got %q", name, sc.Driver)
		}
	}
	check("storage.cache", s.Cache)
	check("storage.state", s.State)
	for name, sc := range s.Stores {
		check("storage.stores."+name, sc)
	}

	if s.Cache.Driver == s.State.Driver && location(s.Cache) == location(s.State) {
		add("storage.cache and storage.state must not share a location")
	}
	for name, sc := range s.Stores {
		for other, o := range map[string]StoreConfig{"cache": s.Cache, "state": s.State} {
			if sc.Driver == o.Driver && location(sc) == location(o) {
				add("storage.stores.%s and storage.%s must not share a location", name, other)
			}
		}
	}
	return errs
}

// location identifies where a store keeps its data, within its driver.
func location(sc StoreConfig) string {
	if sc.Driver == "s3" {
		return sc.Bucket + "/" + strings.Trim(sc.Prefix, "/")
	}
	return path.Clean(sc.Path)
}

func validateSources(eco string, sources []Source, stores map[string]StoreConfig) []error {
	var errs []error
	seen := map[string]bool{}
	unclaimed := 0
	for _, s := range sources {
		add := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("%s source %q: %s", eco, s.Name, fmt.Sprintf(format, a...)))
		}
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("%s: source name is required", eco))
		} else if seen[s.Name] {
			add("duplicate source name")
		}
		seen[s.Name] = true

		if len(s.Claims) == 0 && s.Type != "storage" {
			unclaimed++
		}
		switch s.Type {
		case "storage":
			if len(s.Claims) == 0 {
				errs = append(errs, fmt.Errorf("%s: storage source %q must have claims", eco, s.Name))
			}
			if _, ok := stores[s.Store]; !ok {
				add("unknown store %q", s.Store)
			}
		case "git":
			if len(s.Remotes) == 0 {
				add("remotes is required")
			}
			ssh := false
			for _, r := range s.Remotes {
				switch kind := remoteKind(r); kind {
				case "ssh":
					ssh = true
				case "https":
				default:
					add("unsupported remote scheme in %q (use https:// or ssh)", r)
				}
			}
			if ssh && s.KnownHosts == "" {
				add("known_hosts is required for SSH remotes")
			}
		case "registry":
			if s.URL == "" {
				add("url is required")
			}
			if len(s.FetchHosts) == 0 {
				add("fetch_hosts is required")
			}
			allowed := map[string]bool{}
			for _, h := range s.FetchHosts {
				allowed[h] = true
			}
			for host := range s.DownloadCredentials {
				if !allowed[host] {
					add("download_credentials host %q is not in fetch_hosts", host)
				}
			}
		default:
			add("type must be git, storage or registry, got %q", s.Type)
		}
	}
	if unclaimed > 1 {
		errs = append(errs, fmt.Errorf("%s: at most one unclaimed source is allowed, found %d", eco, unclaimed))
	}
	return errs
}

// remoteKind classifies a git remote as "https", "ssh" (ssh:// or scp-style
// user@host:path) or "" for anything else.
func remoteKind(r string) string {
	switch {
	case strings.HasPrefix(r, "https://"):
		return "https"
	case strings.HasPrefix(r, "ssh://"):
		return "ssh"
	case strings.Contains(r, "://"):
		return ""
	}
	// scp-style: a colon before any slash.
	if i := strings.IndexAny(r, ":/"); i > 0 && r[i] == ':' {
		return "ssh"
	}
	return ""
}
