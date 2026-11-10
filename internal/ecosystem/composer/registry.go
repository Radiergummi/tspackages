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
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

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

	metaFlight singleflight.Group // by metadata cache key: one upstream fetch at a time
	distFlight singleflight.Group // by distref key: one fetch, verify and store at a time

	hmu      sync.Mutex // guards the health fields
	fetchErr error      // last metadata fetch failure; nil once one succeeds
	stale    bool       // fetchErr was answered from stale cache
}

var _ Source = (*RegistrySource)(nil)

// NewRegistrySource builds a pass-through source for the repository at
// baseURL (the directory holding p2/). fetchTimeout bounds every upstream
// request including the body read (default 5 minutes). wait, if non-nil, is
// called before every upstream request (rate limiting). log nil means
// slog.Default().
func NewRegistrySource(name string, claims []string, baseURL string, c *upstream.Client, cache *storage.Cache, rec *records.Store, ttl time.Duration, maxArtifact int64, fetchTimeout time.Duration, wait func(context.Context) error, log *slog.Logger) *RegistrySource {
	if fetchTimeout <= 0 {
		fetchTimeout = defaultFetchTimeout
	}
	if log == nil {
		log = slog.Default()
	}
	if wait == nil {
		wait = func(context.Context) error { return nil }
	}
	return &RegistrySource{
		name: name, claims: claims, base: strings.TrimRight(baseURL, "/"), c: c, cache: cache, rec: rec,
		ttl: ttl, maxArtifact: maxArtifact, fetchTimeout: fetchTimeout, wait: wait,
		log: log, now: time.Now,
	}
}

func (s *RegistrySource) Name() string     { return s.name }
func (s *RegistrySource) Claims() []string { return s.claims }

// metaSuffix ends the name of a p2 file holding stable or dev versions.
func metaSuffix(dev bool) string {
	if dev {
		return "~dev.json"
	}
	return ".json"
}

func (s *RegistrySource) metaKey(pkg string, dev bool) string {
	return "composer/" + s.name + "/p2/" + pkg + metaSuffix(dev)
}

func (s *RegistrySource) metaURL(pkg string, dev bool) string {
	return s.base + "/p2/" + pkg + metaSuffix(dev)
}

// readCached returns the cached bytes and whether they are still fresh.
func (s *RegistrySource) readCached(ctx context.Context, key string) (body []byte, fresh, ok bool) {
	rc, written, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, false, false
	}
	defer rc.Close()
	body, err = io.ReadAll(rc)
	if err != nil {
		return nil, false, false
	}
	age := max(s.now().Sub(written), 0)
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

// metadata returns the parsed p2 document (nil when it does not list pkg), or
// found=false for a definite miss.
func (s *RegistrySource) metadata(ctx context.Context, pkg string, dev bool) (vs []Version, found bool, err error) {
	key := s.metaKey(pkg, dev)
	cached, fresh, have := s.readCached(ctx, key)
	if have && fresh {
		metrics.ObserveCacheHit(ecoName, s.name)
		return parseCached(cached, pkg, dev)
	}
	res, err := flight(ctx, &s.metaFlight, key, func() (fetchedMeta, error) {
		return s.refreshMetadata(ctx, key, pkg, dev, have)
	})
	if err != nil {
		if have {
			// A stale not-found marker is served too, deliberately: during an
			// outage an unknown name stays unknown rather than turning into a 502.
			s.log.Warn("serving stale composer metadata", "source", s.name, "package", pkg, "dev", dev, "error", err)
			return parseCached(cached, pkg, dev)
		}
		return nil, false, err
	}
	return res.vs, res.found, nil
}

type fetchedMeta struct {
	vs    []Version
	found bool
}

// refreshMetadata fetches, validates and caches the p2 document of pkg.
// haveCache says whether a stale copy is cached (for Health).
func (s *RegistrySource) refreshMetadata(ctx context.Context, key, pkg string, dev, haveCache bool) (fetchedMeta, error) {
	body, found, err := s.fetchMeta(ctx, s.metaURL(pkg, dev))
	var vs []Version
	if err == nil && found {
		// Validate before caching, so garbage never replaces good bytes.
		vs, err = parseMetadata(body, pkg, dev)
	}
	s.noteFetch(ctx, err, haveCache)
	if err != nil {
		return fetchedMeta{}, err
	}
	toStore := body
	if !found {
		toStore = notFoundMarker
	}
	if perr := s.cache.Put(ctx, key, bytes.NewReader(toStore)); perr != nil {
		s.log.Warn("caching composer metadata failed", "source", s.name, "package", pkg, "error", perr)
	}
	return fetchedMeta{vs: vs, found: found}, nil
}

// flight runs fn once for all concurrent callers with the same key, with the
// context of the caller that started it. Every caller stops waiting when its
// own context ends; one whose result was cut short by another caller's
// cancellation tries again.
func flight[T any](ctx context.Context, g *singleflight.Group, key string, fn func() (T, error)) (T, error) {
	for {
		select {
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		case r := <-g.DoChan(key, func() (any, error) { return fn() }):
			if r.Shared && errors.Is(r.Err, context.Canceled) && ctx.Err() == nil {
				continue
			}
			t, _ := r.Val.(T)
			return t, r.Err
		}
	}
}

// parseCached parses cached metadata; the not-found marker is a definite miss.
func parseCached(cached []byte, pkg string, dev bool) ([]Version, bool, error) {
	if bytes.Equal(cached, notFoundMarker) {
		return nil, false, nil
	}
	vs, err := parseMetadata(cached, pkg, dev)
	return vs, true, err
}

// parseMetadata decodes a p2 document for pkg; versions is nil when the
// document does not list pkg. Foreign package names, as keys or as a version's
// "name", are an error; other top-level keys are ignored; fields stay exactly
// as sent.
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
		if n, ok := e["name"]; ok {
			ns, _ := n.(string)
			if nn, err := Normalize(ns); err != nil || nn != pkg {
				return nil, fmt.Errorf("upstream metadata for %s has a version named %v", pkg, n)
			}
		}
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

// Versions returns the stable or dev versions of name as upstream lists them.
// A miss on the stable file is definite. A miss on the dev file is definite
// only if the stable file misses too; otherwise the package has no dev
// versions here, and resolution must not take them from another source.
func (s *RegistrySource) Versions(ctx context.Context, name string, dev bool) ([]Version, error) {
	pkg, err := lookupName(name)
	if err != nil {
		return nil, err
	}
	vs, found, err := s.metadata(ctx, pkg, dev)
	if err != nil {
		return nil, err
	}
	if found && vs != nil { // nil: the document does not list the package
		return vs, nil
	}
	if dev {
		stable, found, err := s.metadata(ctx, pkg, false)
		if err != nil {
			return nil, err
		}
		if found && stable != nil {
			return []Version{}, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, pkg)
}

func (s *RegistrySource) distKey(sha256 string) string {
	return "composer/" + s.name + "/dist/" + sha256 + ".zip"
}

func (s *RegistrySource) distRefKey(pkg, version, reference string) string {
	return "composer/" + s.name + "/distref/" + pkg + "/" + storage.EscapeSegment(version) + "/" + storage.EscapeSegment(reference)
}

// cachedDist serves a previously verified archive if the cache still has it
// and its bytes still satisfy the currently declared shasum.
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
	return Artifact{Body: io.NopCloser(bytes.NewReader(b)), Size: int64(len(b))}, true
}

// Dist serves the archive of the version whose number and dist.reference
// match. The only URL fetched is the dist.url from upstream's own metadata.
func (s *RegistrySource) Dist(ctx context.Context, name, version, reference string) (Artifact, error) {
	pkg, err := lookupName(name)
	if err != nil {
		return Artifact{}, err
	}
	// The route does not say whether version is a dev version: look in the
	// file its form suggests first, then in the other one.
	normalized, _ := NormalizeVersion(version)
	dev := isDevVersion(normalized)
	var vs []Version
	for _, dev := range []bool{dev, !dev} {
		dvs, err := s.Versions(ctx, pkg, dev)
		if err != nil && !errors.Is(err, resolve.ErrNotFound) {
			return Artifact{}, err
		}
		vs = append(vs, dvs...)
		if slices.ContainsFunc(dvs, func(v Version) bool { return v.Version == version && v.Reference == reference }) {
			break
		}
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

	body, err := flight(ctx, &s.distFlight, refKey, func() ([]byte, error) {
		return s.fetchAndStoreDist(ctx, pkg, version, distURL, shasum, refKey)
	})
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Body: io.NopCloser(bytes.NewReader(body)), Size: int64(len(body))}, nil
}

// fetchAndStoreDist downloads and verifies the archive, records its
// provenance and caches it under refKey.
func (s *RegistrySource) fetchAndStoreDist(ctx context.Context, pkg, version, distURL, shasum, refKey string) ([]byte, error) {
	declared := ""
	if shasum != "" {
		declared = "sha1:" + shasum
	}
	body, sha1Hex, sha256Hex, err := s.fetchDist(ctx, distURL, shasum)
	if errors.Is(err, resolve.ErrNotFound) {
		// Listed in metadata but gone upstream: a source fault, not a miss.
		return nil, fmt.Errorf("upstream dist missing for listed version: %v", err) //nolint:errorlint // a listed version's missing dist is a fault, not a miss
	}
	if err != nil {
		return nil, err
	}
	if err := s.rec.PutProvenance(ctx, records.Provenance{
		Ecosystem: "composer", Package: pkg, Version: version, Source: s.name, SourceType: "registry",
		UpstreamURL: distURL, DeclaredDigest: declared, SHA1: sha1Hex, SHA256: sha256Hex,
	}); err != nil {
		return nil, fmt.Errorf("record provenance: %w", err)
	}
	if err := s.cache.Put(ctx, s.distKey(sha256Hex), bytes.NewReader(body)); err != nil {
		s.log.Warn("caching composer dist failed", "source", s.name, "package", pkg, "version", version, "error", err)
	} else if err := s.cache.Put(ctx, refKey, strings.NewReader(sha256Hex+" "+sha1Hex)); err != nil {
		s.log.Warn("caching composer distref failed", "source", s.name, "package", pkg, "version", version, "error", err)
	}
	return body, nil
}

func (s *RegistrySource) fetchDist(ctx context.Context, url, wantSHA1 string) (body []byte, sha1Hex, sha256Hex string, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
	defer cancel()
	if err := s.wait(ctx); err != nil {
		return nil, "", "", err
	}
	start := time.Now()
	defer func() { metrics.ObserveUpstream(s.name, time.Since(start)) }()
	return s.c.FetchVerified(ctx, url, wantSHA1, s.maxArtifact)
}

// noteFetch records the outcome of an upstream metadata fetch for Health.
// A cancelled request context says nothing about upstream and is ignored.
func (s *RegistrySource) noteFetch(ctx context.Context, err error, haveCache bool) {
	if ctx.Err() != nil {
		return
	}
	s.hmu.Lock()
	defer s.hmu.Unlock()
	if err == nil {
		s.fetchErr, s.stale = nil, false
		return
	}
	if s.fetchErr == nil || s.fetchErr.Error() != err.Error() { // log changes, not repeats
		s.log.Warn("composer upstream unhealthy", "source", s.name, "stale", haveCache, "error", err)
	}
	s.fetchErr, s.stale = err, haveCache
}

// Health is OK unless the last upstream metadata fetch failed.
func (s *RegistrySource) Health(context.Context) []metrics.Health {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	h := metrics.Health{Name: s.name, OK: s.fetchErr == nil, Detail: "no upstream fetch has failed"}
	if s.fetchErr != nil {
		// Category only; the error itself was logged when it occurred or changed.
		h.Detail = "upstream error"
		if s.stale {
			h.Detail = "serving stale"
		}
	}
	return []metrics.Health{h}
}
