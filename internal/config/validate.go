package config

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Validate returns every problem found in c, joined with errors.Join.
func Validate(c *Config) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	errs = append(errs, validateStores(&c.Storage)...)
	errs = append(errs, validateLimits(&c.Limits)...)

	for _, eco := range slices.Sorted(maps.Keys(c.Ecosystems)) {
		e := c.Ecosystems[eco]
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
	names := slices.Sorted(maps.Keys(s.Stores))
	for _, name := range names {
		check("storage.stores."+name, s.Stores[name])
	}

	type named struct {
		name string
		sc   StoreConfig
	}
	all := []named{{"storage.cache", s.Cache}, {"storage.state", s.State}}
	for _, name := range names {
		all = append(all, named{"storage.stores." + name, s.Stores[name]})
	}
	for _, n := range all {
		if n.sc.MaxSize < 0 {
			add("%s: max_size must not be negative", n.name)
		}
	}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if overlaps(all[i].sc, all[j].sc) {
				add("%s and %s must not share a location", all[i].name, all[j].name)
			}
		}
	}
	return errs
}

func validateLimits(l *Limits) []error {
	var errs []error
	neg := func(name string, negative bool) {
		if negative {
			errs = append(errs, fmt.Errorf("limits.%s must not be negative", name))
		}
	}
	neg("max_upload_bytes", l.MaxUploadBytes < 0)
	neg("max_decompressed_bytes", l.MaxDecompressedBytes < 0)
	neg("max_archive_entries", l.MaxArchiveEntries < 0)
	neg("requests_per_second", l.RequestsPerSecond < 0)
	neg("burst", l.Burst < 0)
	neg("upstream_fetches_per_second", l.UpstreamFetchesPerSecond < 0)
	return errs
}

// overlaps reports whether two stores could read or write each other's data.
// Stores with an invalid or incomplete location are skipped; check reports those.
func overlaps(a, b StoreConfig) bool {
	if a.Driver != b.Driver {
		return false
	}
	switch a.Driver {
	case "fs":
		if a.Path == "" || b.Path == "" {
			return false
		}
		pa, errA := filepath.Abs(a.Path)
		pb, errB := filepath.Abs(b.Path)
		if errA != nil || errB != nil {
			return false
		}
		return pathContains(pa, pb) || pathContains(pb, pa)
	case "s3":
		if a.Bucket == "" || a.Bucket != b.Bucket || normEndpoint(a.Endpoint) != normEndpoint(b.Endpoint) {
			return false
		}
		pa, pb := normPrefix(a.Prefix), normPrefix(b.Prefix)
		return strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)
	}
	return false
}

// pathContains reports whether clean absolute path child is parent or below it.
func pathContains(child, parent string) bool {
	if child == parent {
		return true
	}
	if !strings.HasSuffix(parent, string(filepath.Separator)) {
		parent += string(filepath.Separator)
	}
	return strings.HasPrefix(child, parent)
}

func normEndpoint(e string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(e)), "/")
}

// normPrefix returns "" for the bucket root, else a prefix ending in "/".
func normPrefix(p string) string {
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	return p + "/"
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
		if s.MetadataTTL < 0 {
			add("metadata_ttl must not be negative")
		}
		if s.PollInterval < 0 {
			add("poll_interval must not be negative")
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
					if u, err := url.Parse(r); err == nil && u.User != nil {
						add("remote must not contain credentials; use token")
					}
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
	if scpRe.MatchString(r) {
		return "ssh"
	}
	return ""
}

// scpRe matches scp-style [user@]host:path; the host is plain hostname
// characters, never starting with "-", and "::" (transport helpers) is out.
var scpRe = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:[^:]`)
