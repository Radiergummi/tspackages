package pypi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/radiergummi/tspackages/internal/digest"
	"github.com/radiergummi/tspackages/internal/flight"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
	"golang.org/x/sync/singleflight"
)

const (
	// metaFetchTimeout bounds a project page request including its body.
	metaFetchTimeout = 2 * time.Minute
	// maxPageSize caps a project page; the largest PyPI pages are a few MB.
	maxPageSize = 64 << 20
	// maxProvenanceSize caps a provenance object.
	maxProvenanceSize = 4 << 20
)

// notFoundMarker is cached for a project the upstream does not have.
var notFoundMarker = []byte("\x00tspackages:not-found")

// RegistrySource passes through an index that speaks the JSON simple API
// (PEP 691). Project pages are cached for ttl and served stale when the
// upstream fails; files stream through the relay and are cached only once
// their sha256 matched.
type RegistrySource struct {
	name        string
	claims      []string
	base        string // ends in "/"
	c           *upstream.Client
	cache       *storage.Cache
	relay       *relay.Relay
	rec         *records.Store
	ttl         time.Duration
	maxArtifact int64
	wait        func(context.Context) error
	log         *slog.Logger
	now         func() time.Time // replaced in tests

	pageFlight singleflight.Group

	hmu      sync.Mutex
	fetchErr error
	stale    bool
}

var _ Source = (*RegistrySource)(nil)

// NewRegistrySource builds a pass-through source for the simple index at
// baseURL (".../simple/"). wait, if non-nil, is called before every
// upstream request; log nil means slog.Default().
func NewRegistrySource(name string, claims []string, baseURL string, c *upstream.Client, cache *storage.Cache, rl *relay.Relay, rec *records.Store, ttl time.Duration, maxArtifact int64, wait func(context.Context) error, log *slog.Logger) *RegistrySource {
	if log == nil {
		log = slog.Default()
	}
	if wait == nil {
		wait = func(context.Context) error { return nil }
	}
	return &RegistrySource{
		name: name, claims: claims, base: strings.TrimRight(baseURL, "/") + "/", c: c, cache: cache, relay: rl, rec: rec,
		ttl: ttl, maxArtifact: maxArtifact, wait: wait, log: log, now: time.Now,
	}
}

func (s *RegistrySource) Name() string     { return s.name }
func (s *RegistrySource) Claims() []string { return s.claims }

// upstreamFile is a served file with the upstream locations behind it.
type upstreamFile struct {
	File
	url, provenance string
}

// upstreamPage is the allowlisted part of a PEP 691 project page.
type upstreamPage struct {
	Project
	files map[string]upstreamFile
}

func (s *RegistrySource) pageKey(name string) string {
	return "pypi/" + s.name + "/simple/" + name + ".json"
}

// Project returns the allowlisted project page.
func (s *RegistrySource) Project(ctx context.Context, name string) (Project, error) {
	p, err := s.page(ctx, name)
	if err != nil {
		return Project{}, err
	}
	return p.Project, nil
}

func (s *RegistrySource) page(ctx context.Context, name string) (upstreamPage, error) {
	key := s.pageKey(name)
	cached, written, haveCache := s.readCached(ctx, key)
	if haveCache && s.now().Sub(written) < s.ttl {
		metrics.ObserveCacheHit(ecoName, s.name)
		return s.parseCached(cached, name)
	}
	body, err := flight.Do(ctx, &s.pageFlight, key, func() ([]byte, error) {
		return s.refresh(ctx, key, name, haveCache)
	})
	if err != nil {
		if haveCache {
			s.log.Warn("serving stale pypi project page", "source", s.name, "project", name, "error", err)
			return s.parseCached(cached, name)
		}
		return upstreamPage{}, err
	}
	return s.parseCached(body, name)
}

func (s *RegistrySource) readCached(ctx context.Context, key string) ([]byte, time.Time, bool) {
	rc, written, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, time.Time{}, false
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, time.Time{}, false
	}
	return b, written, true
}

// refresh fetches, validates and caches the page (or the not-found marker).
func (s *RegistrySource) refresh(ctx context.Context, key, name string, haveCache bool) ([]byte, error) {
	body, err := s.fetchPage(ctx, name)
	if err == nil && body != nil {
		// Validate before caching, so garbage never replaces a good copy.
		_, err = s.parsePage(body, name)
	}
	s.noteFetch(ctx, err, haveCache)
	if err != nil {
		return nil, err
	}
	if body == nil {
		body = notFoundMarker
	}
	if perr := s.cache.Put(ctx, key, bytes.NewReader(body)); perr != nil {
		s.log.Warn("caching pypi project page failed", "source", s.name, "project", name, "error", perr)
	}
	return body, nil
}

// fetchPage returns nil for a definite upstream 404.
func (s *RegistrySource) fetchPage(ctx context.Context, name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, metaFetchTimeout)
	defer cancel()
	if err := s.wait(ctx); err != nil {
		return nil, err
	}
	start := time.Now()
	resp, err := s.c.GetAccept(ctx, s.base+name+"/", jsonType)
	metrics.ObserveUpstream(s.name, time.Since(start))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, &upstream.StatusError{Code: resp.StatusCode, URL: resp.Request.URL.Redacted()}
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != jsonType {
		return nil, fmt.Errorf("upstream answered %q, not the JSON simple API", mt)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxPageSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPageSize {
		return nil, upstream.ErrTooLarge
	}
	return b, nil
}

func (s *RegistrySource) parseCached(b []byte, name string) (upstreamPage, error) {
	if bytes.Equal(b, notFoundMarker) {
		return upstreamPage{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, name)
	}
	return s.parsePage(b, name)
}

type pageJSON struct {
	Meta struct {
		APIVersion string `json:"api-version"`
	} `json:"meta"`
	Name          string            `json:"name"`
	Versions      []string          `json:"versions"`
	ProjectStatus map[string]string `json:"project-status"`
	Files         []struct {
		Filename       string            `json:"filename"`
		URL            string            `json:"url"`
		Hashes         map[string]string `json:"hashes"`
		RequiresPython string            `json:"requires-python"`
		Yanked         any               `json:"yanked"`
		Size           int64             `json:"size"`
		UploadTime     string            `json:"upload-time"`
		CoreMetadata   any               `json:"core-metadata"`
		DistInfo       any               `json:"dist-info-metadata"`
		Provenance     *string           `json:"provenance"`
	} `json:"files"`
}

// parsePage keeps only the allowlisted fields of files that have a sha256,
// are hosted on an allowed host and belong to name.
func (s *RegistrySource) parsePage(b []byte, name string) (upstreamPage, error) {
	var doc pageJSON
	if err := json.Unmarshal(b, &doc); err != nil {
		return upstreamPage{}, fmt.Errorf("decode upstream project page: %w", err)
	}
	if !strings.HasPrefix(doc.Meta.APIVersion, "1.") {
		return upstreamPage{}, fmt.Errorf("upstream project page has api-version %q", doc.Meta.APIVersion)
	}
	if n, err := Normalize(doc.Name); err != nil || n != name {
		return upstreamPage{}, fmt.Errorf("upstream project page names %q, not %q", doc.Name, name)
	}
	pageURL, _ := url.Parse(s.base + name + "/")
	out := upstreamPage{
		Name: name, Versions: doc.Versions, Status: doc.ProjectStatus["status"],
		files: map[string]upstreamFile{},
	}
	for _, f := range doc.Files {
		sha := strings.ToLower(f.Hashes["sha256"])
		if !digest.IsHex(sha, 64) || fileProject(f.Filename) != name {
			continue
		}
		u, err := pageURL.Parse(f.URL)
		if err != nil {
			continue
		}
		u.Fragment = ""
		if !s.c.Allowed(u.String()) {
			continue
		}
		uf := upstreamFile{
			Filename: f.Filename, SHA256: sha, RequiresPython: f.RequiresPython,
			Yanked: yanked(f.Yanked), Size: f.Size, url: u.String()}
		if t, err := time.Parse(time.RFC3339Nano, f.UploadTime); err == nil {
			uf.UploadTime = t
		}
		cm := f.CoreMetadata
		if cm == nil {
			cm = f.DistInfo
		}
		if m, ok := cm.(map[string]any); ok {
			if h, _ := m["sha256"].(string); digest.IsHex(strings.ToLower(h), 64) {
				uf.CoreMetadata = strings.ToLower(h)
			}
		}
		if f.Provenance != nil {
			if pu, err := pageURL.Parse(*f.Provenance); err == nil && s.c.Allowed(pu.String()) {
				uf.HasProvenance, uf.provenance = true, pu.String()
			}
		}
		if _, dup := out.files[f.Filename]; dup {
			continue
		}
		out.files[f.Filename] = uf
		out.Files = append(out.Files, uf.File)
	}
	return out, nil
}

// fileProject returns the normalised project a distribution filename
// belongs to, or "" for a filename that is not a wheel or sdist.
func fileProject(filename string) string {
	var name string
	if w, err := ParseWheelFilename(filename); err == nil {
		name = w.Name
	} else if n, _, err := ParseSdistFilename(filename); err == nil {
		name = n
	} else if stem, ok := strings.CutSuffix(filename, ".zip"); ok {
		// Legacy sdists; pip still installs them.
		if n, _, err := ParseSdistFilename(stem + ".tar.gz"); err == nil {
			name = n
		}
	}
	n, err := Normalize(name)
	if err != nil {
		return ""
	}
	return n
}

func (s *RegistrySource) lookupFile(ctx context.Context, name, filename string) (upstreamFile, error) {
	p, err := s.page(ctx, name)
	if err != nil {
		return upstreamFile{}, err
	}
	f, ok := p.files[filename]
	if !ok {
		return upstreamFile{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, filename)
	}
	return f, nil
}

func (s *RegistrySource) open(ctx context.Context, key, rawURL string, want relay.Digest, maxBytes int64, onCommit func(context.Context, relay.Result) error) (Artifact, error) {
	fetch := func(ctx context.Context) (io.ReadCloser, int64, error) {
		if err := s.wait(ctx); err != nil {
			return nil, 0, err
		}
		start := time.Now()
		body, size, err := s.c.Open(ctx, rawURL, maxBytes)
		metrics.ObserveUpstream(s.name, time.Since(start))
		if errors.Is(err, resolve.ErrNotFound) {
			// Listed upstream but gone: a source fault, not a miss.
			return nil, 0, fmt.Errorf("upstream file missing for a listed entry: %v", err) //nolint:errorlint // a listed file's 404 is a fault, not a miss
		}
		return body, size, err
	}
	body, size, hit, err := s.relay.Open(ctx, key, want, fetch, onCommit)
	if err != nil {
		return Artifact{}, err
	}
	if hit {
		metrics.ObserveCacheHit(ecoName, s.name)
	}
	return Artifact{Body: body, Size: max(size, 0)}, nil
}

// File streams a listed file, verified against its declared sha256.
func (s *RegistrySource) File(ctx context.Context, name, filename string) (Artifact, error) {
	f, err := s.lookupFile(ctx, name, filename)
	if err != nil {
		return Artifact{}, err
	}
	version := ""
	if w, err := ParseWheelFilename(filename); err == nil {
		version = w.Version
	} else if _, v, err := ParseSdistFilename(strings.Replace(filename, ".zip", ".tar.gz", 1)); err == nil {
		version = v
	}
	if v, err := ParseVersion(version); err == nil {
		version = v.String() // as the storage and git sources record it
	}
	onCommit := func(ctx context.Context, res relay.Result) error {
		if err := s.rec.PutProvenance(ctx, records.Provenance{
			Ecosystem: ecoName, Package: name, Version: version, Source: s.name, SourceType: "registry",
			UpstreamURL: f.url, DeclaredDigest: "sha256:" + f.SHA256, SHA1: res.SHA1, SHA256: res.SHA256,
		}); err != nil {
			return fmt.Errorf("record provenance: %w", err)
		}
		return nil
	}
	return s.open(ctx, "pypi/"+s.name+"/files/"+f.SHA256, f.url, relay.Digest{SHA256: f.SHA256}, s.maxArtifact, onCommit)
}

// Metadata streams a file's core metadata, verified against its declared
// sha256. Files without a declared hash have none.
func (s *RegistrySource) Metadata(ctx context.Context, name, filename string) (Artifact, error) {
	f, err := s.lookupFile(ctx, name, filename)
	if err != nil {
		return Artifact{}, err
	}
	if f.CoreMetadata == "" {
		return Artifact{}, fmt.Errorf("%w: no metadata for %s", resolve.ErrNotFound, filename)
	}
	return s.open(ctx, "pypi/"+s.name+"/metadata/"+f.CoreMetadata, f.url+".metadata", relay.Digest{SHA256: f.CoreMetadata}, maxPageSize, nil)
}

// Provenance streams a file's PEP 740 provenance object from upstream. It
// declares no hash; it is cached per file digest.
func (s *RegistrySource) Provenance(ctx context.Context, name, filename string) (Artifact, error) {
	f, err := s.lookupFile(ctx, name, filename)
	if err != nil {
		return Artifact{}, err
	}
	if !f.HasProvenance {
		return Artifact{}, fmt.Errorf("%w: no provenance for %s", resolve.ErrNotFound, filename)
	}
	return s.open(ctx, "pypi/"+s.name+"/provenance/"+f.SHA256, f.provenance, relay.Digest{}, maxProvenanceSize, nil)
}

// noteFetch records the outcome of a project page fetch for Health; a
// cancelled request says nothing about upstream.
func (s *RegistrySource) noteFetch(ctx context.Context, err error, haveCache bool) {
	if ctx.Err() != nil {
		return
	}
	s.hmu.Lock()
	defer s.hmu.Unlock()
	switch {
	case err == nil && s.fetchErr != nil:
		s.log.Info("pypi upstream recovered", "source", s.name)
	case err != nil && s.fetchErr == nil:
		s.log.Warn("pypi upstream unhealthy", "source", s.name, "stale", haveCache, "error", err)
	case err != nil:
		s.log.Debug("pypi upstream still unhealthy", "source", s.name, "stale", haveCache, "error", err)
	}
	s.fetchErr, s.stale = err, err != nil && haveCache
}

// Health reports the last project page fetch.
func (s *RegistrySource) Health(context.Context) []metrics.Health {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	h := metrics.Health{Name: s.name, OK: s.fetchErr == nil, Detail: "no upstream fetch has failed"}
	if s.fetchErr != nil {
		h.Detail = "upstream error"
		if s.stale {
			h.Detail = "serving stale"
		}
	}
	return []metrics.Health{h}
}
