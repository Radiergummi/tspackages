package composer

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

const (
	defaultFetchTimeout = 5 * time.Minute
	// maxMetadataSize caps one p2 response; the largest real packages are well under 16 MiB.
	maxMetadataSize = 16 << 20
)

// notFoundMarker is cached in place of metadata when upstream answered 404,
// so repeated lookups of an unknown name do not hammer upstream. Real p2
// documents always carry a "packages" key, so they never equal it.
var notFoundMarker = []byte(`{"tspackages":"not-found"}`)

// RegistrySource passes through an upstream Composer v2 repository. Metadata
// is cached for ttl and served stale when upstream fails; dist archives are
// verified against the upstream-declared shasum before they are cached.
type RegistrySource struct {
	name         string
	claims       []string
	base         string
	c            *upstream.Client
	cache        *storage.Cache
	rec          *records.Store
	ttl          time.Duration
	maxArtifact  int64
	fetchTimeout time.Duration
	wait         func(context.Context) error
	log          *slog.Logger
	now          func() time.Time // replaced in tests

	hmu      sync.Mutex // guards the health fields
	fetchErr error      // last metadata fetch failure; nil once one succeeds
	fetchAt  time.Time  // when fetchErr happened
	stale    bool       // fetchErr was answered from stale cache
}

var _ Source = (*RegistrySource)(nil)

// NewRegistrySource builds a pass-through source for the repository at
// baseURL (the directory holding p2/). fetchTimeout bounds every upstream
// request including the body read (default 5 minutes). wait, if non-nil, is
// called before every upstream request (rate limiting).
func NewRegistrySource(name string, claims []string, baseURL string, c *upstream.Client, cache *storage.Cache, rec *records.Store, ttl time.Duration, maxArtifact int64, fetchTimeout time.Duration, wait func(context.Context) error) *RegistrySource {
	if fetchTimeout <= 0 {
		fetchTimeout = defaultFetchTimeout
	}
	if wait == nil {
		wait = func(context.Context) error { return nil }
	}
	return &RegistrySource{
		name: name, claims: claims, base: strings.TrimRight(baseURL, "/"), c: c, cache: cache, rec: rec,
		ttl: ttl, maxArtifact: maxArtifact, fetchTimeout: fetchTimeout, wait: wait,
		log: slog.Default(), now: time.Now,
	}
}

func (s *RegistrySource) Name() string     { return s.name }
func (s *RegistrySource) Claims() []string { return s.claims }
func (s *RegistrySource) Type() string     { return "registry" }

// Packages is not enumerable for a pass-through source.
func (s *RegistrySource) Packages(context.Context) ([]string, bool, error) { return nil, false, nil }

func (s *RegistrySource) metaKey(pkg string, dev bool) string {
	suffix := ".json"
	if dev {
		suffix = "~dev.json"
	}
	return "composer/" + s.name + "/p2/" + pkg + suffix
}

func (s *RegistrySource) metaURL(pkg string, dev bool) string {
	suffix := ".json"
	if dev {
		suffix = "~dev.json"
	}
	return s.base + "/p2/" + pkg + suffix
}

// readCached returns the cached bytes and whether they are still fresh.
func (s *RegistrySource) readCached(ctx context.Context, key string) (body []byte, fresh, ok bool) {
	rc, age, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, false, false
	}
	defer rc.Close()
	body, err = io.ReadAll(rc)
	if err != nil {
		return nil, false, false
	}
	// Cache ages come from the real clock; shift them by the injected one.
	age += s.now().Sub(time.Now())
	return body, age < s.ttl, true
}

// fetchMeta returns (nil, false, nil) for a definite upstream 404.
func (s *RegistrySource) fetchMeta(ctx context.Context, url string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
	defer cancel()
	if err := s.wait(ctx); err != nil {
		return nil, false, err
	}
	start := time.Now()
	resp, err := s.c.Get(ctx, url)
	metrics.ObserveUpstream(s.name, time.Since(start))
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, false, &upstream.StatusError{Code: resp.StatusCode, URL: resp.Request.URL.Redacted()}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxMetadataSize {
		return nil, false, upstream.ErrTooLarge
	}
	return b, true, nil
}

// metadata returns the raw p2 document, or found=false for a definite miss.
func (s *RegistrySource) metadata(ctx context.Context, pkg string, dev bool) (body []byte, found bool, err error) {
	key := s.metaKey(pkg, dev)
	cached, fresh, have := s.readCached(ctx, key)
	if have && fresh {
		metrics.ObserveCacheHit(ecoName, s.name)
		return cached, !bytes.Equal(cached, notFoundMarker), nil
	}
	body, found, err = s.fetchMeta(ctx, s.metaURL(pkg, dev))
	if err == nil && found {
		// Validate before caching, so garbage never replaces good bytes.
		_, err = parseMetadata(body, pkg, dev)
	}
	s.noteFetch(err, have)
	if err != nil {
		if have {
			// A stale not-found marker is served too, deliberately: during an
			// outage an unknown name stays unknown rather than turning into a 502.
			s.log.Warn("serving stale composer metadata", "source", s.name, "package", pkg, "dev", dev, "error", err)
			return cached, !bytes.Equal(cached, notFoundMarker), nil
		}
		return nil, false, err
	}
	toStore := body
	if !found {
		toStore = notFoundMarker
	}
	if perr := s.cache.Put(ctx, key, bytes.NewReader(toStore)); perr != nil {
		s.log.Warn("caching composer metadata failed", "source", s.name, "package", pkg, "error", perr)
	}
	return body, found, nil
}

// parseMetadata decodes a p2 document for pkg. Foreign package names are an
// error; other top-level keys are ignored; fields stay exactly as sent.
func parseMetadata(body []byte, pkg string, dev bool) ([]Version, error) {
	var doc struct {
		Minified string                     `json:"minified"`
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode upstream metadata: %w", err)
	}
	if doc.Packages == nil {
		return nil, errors.New("upstream metadata has no packages key")
	}
	var raw json.RawMessage
	for k, v := range doc.Packages {
		if n, err := Normalize(k); err != nil || n != pkg {
			return nil, fmt.Errorf("upstream metadata for %s contains package %q", pkg, k)
		}
		if raw != nil {
			return nil, fmt.Errorf("upstream metadata for %s lists the package twice", pkg)
		}
		raw = v
	}
	if raw == nil {
		return nil, nil
	}
	var entries []map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode upstream versions: %w", err)
	}
	switch doc.Minified {
	case "":
	case "composer/2.0":
		entries = Expand(entries)
	default:
		return nil, fmt.Errorf("unsupported metadata format %q", doc.Minified)
	}
	out := make([]Version, 0, len(entries))
	for _, e := range entries {
		ver, _ := e["version"].(string)
		if ver == "" {
			continue
		}
		dist, _ := e["dist"].(map[string]any)
		ref, _ := dist["reference"].(string)
		out = append(out, Version{Package: e, Version: ver, Reference: ref, Dev: dev})
	}
	return out, nil
}

// Versions returns the stable and dev versions of name as upstream lists them.
// Only a 404 on the stable file together with a 404 on ~dev is a definite miss.
func (s *RegistrySource) Versions(ctx context.Context, name string) ([]Version, error) {
	pkg, err := Normalize(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", resolve.ErrNotFound, err)
	}
	stable, okStable, err := s.metadata(ctx, pkg, false)
	if err != nil {
		return nil, err
	}
	devBody, okDev, err := s.metadata(ctx, pkg, true)
	if err != nil {
		return nil, err
	}
	var out []Version
	if okStable {
		vs, err := parseMetadata(stable, pkg, false)
		if err != nil {
			return nil, err
		}
		out = vs
	}
	if okDev {
		vs, err := parseMetadata(devBody, pkg, true)
		if err != nil {
			return nil, err
		}
		out = append(out, vs...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, pkg)
	}
	return out, nil
}

func (s *RegistrySource) distKey(sha256 string) string {
	return "composer/" + s.name + "/dist/" + sha256 + ".zip"
}

func (s *RegistrySource) distRefKey(pkg, version, reference string) string {
	return "composer/" + s.name + "/distref/" + pkg + "/" + storage.EscapeSegment(version) + "/" + storage.EscapeSegment(reference)
}

// cachedDist serves a previously verified archive if the cache still has it
// and its bytes still satisfy the currently declared shasum. Artifact.SHA1 is
// always the sha1 of the bytes returned.
func (s *RegistrySource) cachedDist(ctx context.Context, refKey, declared string) (Artifact, bool) {
	rc, _, err := s.cache.Get(ctx, refKey)
	if err != nil {
		return Artifact{}, false
	}
	sum, err := io.ReadAll(io.LimitReader(rc, 256))
	rc.Close()
	if err != nil {
		return Artifact{}, false
	}
	sha256Hex, _, _ := strings.Cut(strings.TrimSpace(string(sum)), " ")
	zrc, _, err := s.cache.Get(ctx, s.distKey(sha256Hex))
	if err != nil {
		return Artifact{}, false
	}
	defer zrc.Close()
	b, err := io.ReadAll(zrc)
	if err != nil {
		return Artifact{}, false
	}
	s1 := sha1.Sum(b)
	sha1Hex := hex.EncodeToString(s1[:])
	if declared != "" && !strings.EqualFold(declared, sha1Hex) {
		return Artifact{}, false
	}
	return Artifact{Body: io.NopCloser(bytes.NewReader(b)), Size: int64(len(b)), SHA1: sha1Hex}, true
}

// Dist serves the archive of the version whose number and dist.reference
// match. The only URL fetched is the dist.url from upstream's own metadata.
func (s *RegistrySource) Dist(ctx context.Context, name, version, reference string) (Artifact, error) {
	pkg, err := Normalize(name)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", resolve.ErrNotFound, err)
	}
	vs, err := s.Versions(ctx, pkg)
	if err != nil {
		return Artifact{}, err
	}
	var dist map[string]any
	for _, v := range vs {
		if v.Version != version || v.Reference != reference {
			continue
		}
		if d, ok := v.Package["dist"].(map[string]any); ok {
			dist = d
			break
		}
	}
	distURL, _ := dist["url"].(string)
	if distURL == "" || reference == "" {
		return Artifact{}, fmt.Errorf("%w: %s %s", resolve.ErrNotFound, pkg, version)
	}
	shasum, _ := dist["shasum"].(string)

	refKey := s.distRefKey(pkg, version, reference)
	if a, ok := s.cachedDist(ctx, refKey, shasum); ok {
		metrics.ObserveCacheHit(ecoName, s.name)
		return a, nil
	}

	var want *upstream.Digest
	declared := ""
	if shasum != "" {
		want = &upstream.Digest{Algo: "sha1", Hex: shasum}
		declared = "sha1:" + shasum
	}
	body, sha1Hex, sha256Hex, err := s.fetchDist(ctx, distURL, want)
	if errors.Is(err, resolve.ErrNotFound) {
		// Listed in metadata but gone upstream: a source fault, not a miss.
		return Artifact{}, fmt.Errorf("upstream dist missing for listed version: %v", err)
	}
	if err != nil {
		return Artifact{}, err
	}
	if err := s.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: "composer", Package: pkg, Version: version, Source: s.name, SourceType: "registry",
		UpstreamURL: distURL, DeclaredDigest: declared, SHA1: sha1Hex, SHA256: sha256Hex,
	}); err != nil {
		return Artifact{}, fmt.Errorf("record provenance: %w", err)
	}
	if err := s.cache.Put(ctx, s.distKey(sha256Hex), bytes.NewReader(body)); err != nil {
		s.log.Warn("caching composer dist failed", "source", s.name, "package", pkg, "version", version, "error", err)
	} else if err := s.cache.Put(ctx, refKey, strings.NewReader(sha256Hex+" "+sha1Hex)); err != nil {
		s.log.Warn("caching composer distref failed", "source", s.name, "package", pkg, "version", version, "error", err)
	}
	return Artifact{Body: io.NopCloser(bytes.NewReader(body)), Size: int64(len(body)), SHA1: sha1Hex}, nil
}

func (s *RegistrySource) fetchDist(ctx context.Context, url string, want *upstream.Digest) (body []byte, sha1Hex, sha256Hex string, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
	defer cancel()
	if err := s.wait(ctx); err != nil {
		return nil, "", "", err
	}
	start := time.Now()
	defer func() { metrics.ObserveUpstream(s.name, time.Since(start)) }()
	return s.c.FetchVerified(ctx, url, want, s.maxArtifact)
}

// noteFetch records the outcome of an upstream metadata fetch for Health.
func (s *RegistrySource) noteFetch(err error, haveCache bool) {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	if err == nil {
		s.fetchErr, s.stale = nil, false
		return
	}
	s.fetchErr, s.fetchAt, s.stale = err, s.now(), haveCache
}

// Health is OK unless the last upstream metadata fetch failed.
func (s *RegistrySource) Health(context.Context) []metrics.Health {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	h := metrics.Health{Name: s.name, OK: s.fetchErr == nil, Detail: "no upstream fetch has failed"}
	if s.fetchErr != nil {
		h.Detail = fmt.Sprintf("last upstream fetch failed at %s: %v", s.fetchAt.UTC().Format(time.RFC3339), s.fetchErr)
		if s.stale {
			h.Detail += "; serving stale"
		}
	}
	return []metrics.Health{h}
}
