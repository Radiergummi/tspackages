package goproxy

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
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/mod/module"
	"golang.org/x/sync/singleflight"

	"github.com/radiergummi/tspackages/internal/flight"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

const (
	// metaFetchTimeout bounds a metadata request including its body.
	metaFetchTimeout = 2 * time.Minute
	// maxList caps a version list.
	maxList = 16 << 20
	// maxInfo caps a .info or @latest body.
	maxInfo = 64 << 10
)

// notFoundMarker is cached for a miss the upstream answered with 404 or 410.
var notFoundMarker = []byte("\x00tspackages:not-found")

// RegistryOptions configures a RegistrySource.
type RegistryOptions struct {
	Name        string
	Claims      []string
	BaseURL     string // https://proxy.golang.org
	Client      *upstream.Client
	Cache       *storage.Cache
	Relay       *relay.Relay
	Records     *records.Store
	TTL         time.Duration
	MaxArtifact int64
	Wait        func(context.Context) error // called before every upstream request; nil = none
	Log         *slog.Logger                // nil = slog.Default()
}

// RegistrySource passes through a GOPROXY. Version lists, @latest and
// non-canonical .info answers are cached for the TTL and served stale when
// the upstream fails; a canonical .info never changes and is cached for good.
// Everything is validated before it is cached, and URLs are built from the
// module path and version, never taken from a response.
type RegistrySource struct {
	name   string
	claims []string
	base   string // no trailing "/"
	c      *upstream.Client
	cache  *storage.Cache
	ttl    time.Duration
	wait   func(context.Context) error
	log    *slog.Logger
	now    func() time.Time // replaced in tests

	flight singleflight.Group

	hmu      sync.Mutex
	fetchErr error
	stale    bool
}

var _ Source = (*RegistrySource)(nil)

// NewRegistrySource builds a pass-through source for the GOPROXY at BaseURL.
func NewRegistrySource(o RegistryOptions) *RegistrySource {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Wait == nil {
		o.Wait = func(context.Context) error { return nil }
	}
	return &RegistrySource{
		name: o.Name, claims: o.Claims, base: strings.TrimRight(o.BaseURL, "/"), c: o.Client, cache: o.Cache,
		ttl: o.TTL, wait: o.Wait, log: o.Log, now: time.Now,
	}
}

func (s *RegistrySource) Name() string     { return s.name }
func (s *RegistrySource) Claims() []string { return s.claims }

// metaKey returns the cache key of a metadata file; name is "list", "latest"
// or "<version seg>.info".
func (s *RegistrySource) metaKey(path, name string) (string, error) {
	p, ok := pathSeg(path)
	if !ok {
		return "", fmt.Errorf("%w: module path too long", resolve.ErrNotFound)
	}
	return "go/" + s.name + "/" + p + "/" + name, nil
}

// List returns the canonical, non-pseudo versions the upstream lists.
func (s *RegistrySource) List(ctx context.Context, path string) ([]string, error) {
	key, err := s.metaKey(path, "list")
	if err != nil {
		return nil, err
	}
	esc, err := module.EscapePath(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", resolve.ErrNotFound, err) //nolint:errorlint // an unescapable path is a miss
	}
	b, err := s.meta(ctx, key, false, func(ctx context.Context) ([]byte, error) {
		return s.fetch(ctx, s.base+"/"+esc+"/@v/list", maxList, true, func(b []byte) ([]byte, error) { return s.cleanList(path, b) })
	})
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(b)), nil
}

// Info resolves version, a canonical version or a query, upstream.
func (s *RegistrySource) Info(ctx context.Context, path, version string) (Info, error) {
	canonical := module.CanonicalVersion(version) == version
	vs, ok := versionSeg(version)
	if !ok {
		return Info{}, fmt.Errorf("%w: version too long", resolve.ErrNotFound)
	}
	key, err := s.metaKey(path, vs+".info")
	if err != nil {
		return Info{}, err
	}
	esc, err := module.EscapePath(path)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %v", resolve.ErrNotFound, err) //nolint:errorlint // an unescapable path is a miss
	}
	escV, err := module.EscapeVersion(version)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %v", resolve.ErrNotFound, err) //nolint:errorlint // an unescapable version is a miss
	}
	want := ""
	if canonical {
		want = version
	}
	return s.info(ctx, key, canonical, s.base+"/"+esc+"/@v/"+escV+".info", path, want)
}

// Latest returns the upstream's latest version.
func (s *RegistrySource) Latest(ctx context.Context, path string) (Info, error) {
	key, err := s.metaKey(path, "latest")
	if err != nil {
		return Info{}, err
	}
	esc, err := module.EscapePath(path)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %v", resolve.ErrNotFound, err) //nolint:errorlint // an unescapable path is a miss
	}
	return s.info(ctx, key, false, s.base+"/"+esc+"/@latest", path, "")
}

// Mod is not served yet.
func (s *RegistrySource) Mod(context.Context, string, string) (Artifact, error) {
	return Artifact{}, ErrUnavailable
}

// Zip is not served yet.
func (s *RegistrySource) Zip(context.Context, string, string) (Artifact, error) {
	return Artifact{}, ErrUnavailable
}

func (s *RegistrySource) info(ctx context.Context, key string, immutable bool, rawURL, path, want string) (Info, error) {
	b, err := s.meta(ctx, key, immutable, func(ctx context.Context) ([]byte, error) {
		return s.fetch(ctx, rawURL, maxInfo, false, func(b []byte) ([]byte, error) { return cleanInfo(path, want, b) })
	})
	if err != nil {
		return Info{}, err
	}
	var in Info
	if err := json.Unmarshal(b, &in); err != nil {
		return Info{}, fmt.Errorf("decode cached info: %w", err)
	}
	return in, nil
}

// meta returns the validated metadata at key from the cache or, when it is
// missing or older than the TTL (never, for an immutable hit), from fetch. A
// failed fetch is answered from the stale copy if there is one. A miss is
// cached as notFoundMarker and returned as resolve.ErrNotFound.
func (s *RegistrySource) meta(ctx context.Context, key string, immutable bool, fetch func(context.Context) ([]byte, error)) ([]byte, error) {
	cached, written, haveCache := s.readCached(ctx, key)
	if haveCache && (immutable && !bytes.Equal(cached, notFoundMarker) || s.now().Sub(written) < s.ttl) {
		metrics.ObserveCacheHit(ecoName, s.name)
		return unmarker(cached, key)
	}
	body, err := flight.Do(ctx, &s.flight, key, func() ([]byte, error) {
		b, err := fetch(ctx)
		s.noteFetch(ctx, err, haveCache)
		if err != nil {
			return nil, err
		}
		if b == nil {
			b = notFoundMarker
		}
		if perr := s.cache.Put(ctx, key, bytes.NewReader(b)); perr != nil {
			s.log.Warn("caching go metadata failed", "source", s.name, "key", key, "error", perr)
		}
		return b, nil
	})
	if err != nil {
		if haveCache {
			s.log.Warn("serving stale go metadata", "source", s.name, "key", key, "error", err)
			return unmarker(cached, key)
		}
		return nil, err
	}
	return unmarker(body, key)
}

func unmarker(b []byte, key string) ([]byte, error) {
	if bytes.Equal(b, notFoundMarker) {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, key)
	}
	return b, nil
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

// fetch GETs rawURL and returns clean(body); nil for a 404 or 410. text
// demands a text/plain answer.
func (s *RegistrySource) fetch(ctx context.Context, rawURL string, limit int64, text bool, clean func([]byte) ([]byte, error)) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, metaFetchTimeout)
	defer cancel()
	if err := s.wait(ctx); err != nil {
		return nil, err
	}
	start := time.Now()
	resp, err := s.c.Get(ctx, rawURL)
	metrics.ObserveUpstream(s.name, time.Since(start))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, &upstream.StatusError{Code: resp.StatusCode, URL: resp.Request.URL.Redacted()}
	}
	if text {
		if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/plain" {
			return nil, fmt.Errorf("upstream answered %q, not a version list", mt)
		}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, upstream.ErrTooLarge
	}
	out, err := clean(b)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []byte{} // an empty answer is not a miss
	}
	return out, nil
}

// cleanList keeps the first field of each line that is a canonical version of
// path and no pseudo-version; the go command ignores pseudo-versions in a list.
func (s *RegistrySource) cleanList(path string, b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("upstream version list is not UTF-8")
	}
	if bytes.HasPrefix(bytes.TrimLeft(b, " \t\r\n"), []byte("<")) {
		return nil, errors.New("upstream version list is markup")
	}
	var out strings.Builder
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		v := f[0]
		if module.Check(path, v) != nil || module.CanonicalVersion(v) != v || module.IsPseudoVersion(v) {
			s.log.Warn("dropping invalid line of upstream version list", "source", s.name, "module", path, "line", truncate(line))
			continue
		}
		out.WriteString(v + "\n")
	}
	return []byte(out.String()), nil
}

func truncate(s string) string {
	if len(s) > 100 {
		return s[:100]
	}
	return s
}

// cleanInfo validates a .info body and re-marshals it as {"Version","Time"}.
// want is the canonical version that was requested, or "".
func cleanInfo(path, want string, b []byte) ([]byte, error) {
	var in struct {
		Version string `json:"Version"`
		Time    string `json:"Time"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("decode upstream info: %w", err)
	}
	if err := module.Check(path, in.Version); err != nil {
		return nil, fmt.Errorf("upstream info has invalid version: %w", err)
	}
	if want != "" && in.Version != want {
		return nil, fmt.Errorf("upstream info names version %q, not %q", in.Version, want)
	}
	t, err := time.Parse(time.RFC3339, in.Time)
	if err != nil {
		return nil, fmt.Errorf("upstream info has invalid time: %w", err)
	}
	return json.Marshal(Info{Version: in.Version, Time: t.UTC()})
}

// noteFetch records the outcome of a metadata fetch for Health; a cancelled
// request says nothing about the upstream.
func (s *RegistrySource) noteFetch(ctx context.Context, err error, haveCache bool) {
	if ctx.Err() != nil {
		return
	}
	s.hmu.Lock()
	defer s.hmu.Unlock()
	switch {
	case err == nil && s.fetchErr != nil:
		s.log.Info("go upstream recovered", "source", s.name)
	case err != nil && s.fetchErr == nil:
		s.log.Warn("go upstream unhealthy", "source", s.name, "stale", haveCache, "error", err)
	case err != nil:
		s.log.Debug("go upstream still unhealthy", "source", s.name, "stale", haveCache, "error", err)
	}
	s.fetchErr, s.stale = err, err != nil && haveCache
}

// Health reports the last metadata fetch.
func (s *RegistrySource) Health(context.Context) []metrics.Health {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	h := metrics.Health{Name: s.name, Ecosystem: ecoName, OK: s.fetchErr == nil, Detail: "no upstream fetch has failed"}
	if s.fetchErr != nil {
		h.Detail = "upstream error"
		if s.stale {
			h.Detail = "serving stale"
		}
	}
	return []metrics.Health{h}
}
