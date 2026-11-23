package maven

import (
	"bytes"
	"cmp"
	"context"
	"crypto/md5" //nolint:gosec // MD5 is one of the checksums Maven clients request, not a security digest
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/radiergummi/tspackages/internal/flight"
	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
	"golang.org/x/sync/singleflight"
)

// metaFetchTimeout bounds a checksum or metadata request including its body.
const metaFetchTimeout = 5 * time.Minute

// missMarker is cached as the metadata of a path the upstream does not have.
var missMarker = []byte("\x00tspackages:not-found")

// signatureSuffixes are the files served uncached when the upstream
// declares no checksum for them.
var signatureSuffixes = []string{".asc", ".sigstore", ".sigstore.json"}

// ChangedFile is a file whose upstream bytes differ from the ones this
// source first recorded for it. It is served anyway and shown on the status
// page.
type ChangedFile struct {
	Package, Version, File, Source string
	FirstSHA256, NowSHA256         string
	Seen                           time.Time
}

// RegistrySource passes through a Maven repository. A file is verified
// against the upstream's <file>.sha1 by the relay before it is cached;
// maven-metadata.xml is checked and passed through byte-for-byte, refreshed
// after ttl and served stale when the upstream fails.
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
	tmpDir      string
	log         *slog.Logger
	now         func() time.Time // replaced in tests

	mapFlight, metaFlight singleflight.Group

	hmu      sync.Mutex
	fetchErr error
	stale    bool

	cmu     sync.Mutex
	changed map[[3]string]ChangedFile // by package, version and file
}

var _ Source = (*RegistrySource)(nil)

// NewRegistrySource builds a pass-through source for the repository at
// baseURL (ending in "/"). wait, if non-nil, is called before every upstream
// request; log nil means slog.Default().
func NewRegistrySource(name string, claims []string, baseURL string, c *upstream.Client, cache *storage.Cache, rl *relay.Relay, rec *records.Store, ttl time.Duration, maxArtifact int64, wait func(context.Context) error, tmpDir string, log *slog.Logger) *RegistrySource {
	if log == nil {
		log = slog.Default()
	}
	if wait == nil {
		wait = func(context.Context) error { return nil }
	}
	return &RegistrySource{
		name: name, claims: claims, base: strings.TrimRight(baseURL, "/") + "/", c: c, cache: cache, relay: rl, rec: rec,
		ttl: ttl, maxArtifact: maxArtifact, wait: wait, tmpDir: tmpDir, log: log, now: time.Now,
	}
}

func (s *RegistrySource) Name() string     { return s.name }
func (s *RegistrySource) Claims() []string { return s.claims }

// pathKey is the cache key of one of p's objects under dir.
func (s *RegistrySource) pathKey(dir string, p Path) string {
	sum := sha256.Sum256([]byte(p.String()))
	return "maven/" + s.name + "/" + dir + "/" + hex.EncodeToString(sum[:])
}

func (s *RegistrySource) digestsKey(sha1Hex string) string {
	return "maven/" + s.name + "/digests/sha1-" + sha1Hex + ".json"
}

// mapping is a file path's cached lookup: the SHA-1 its upstream declares and
// the relay key of its bytes, or Miss when neither it nor its .sha1 exist.
type mapping struct {
	SHA1 string `json:"sha1,omitempty"`
	Key  string `json:"key,omitempty"`
	Miss bool   `json:"miss,omitempty"`
}

// digestsObject is what the cache holds about a file's verified bytes.
type digestsObject struct {
	SHA1     string    `json:"sha1"`
	SHA256   string    `json:"sha256"`
	SHA512   string    `json:"sha512"`
	MD5      string    `json:"md5"`
	Modified time.Time `json:"modified,omitzero"`
}

func (d digestsObject) digests() Digests {
	return Digests{SHA1: d.SHA1, SHA256: d.SHA256, SHA512: d.SHA512, MD5: d.MD5}
}

// File serves p: verified through the relay when the upstream declares a
// SHA-1, streamed uncached (with no digests) when it is a signature without
// one.
func (s *RegistrySource) File(ctx context.Context, p Path) (File, error) {
	p.Checksum = ""
	m, err := s.lookup(ctx, p)
	if err != nil {
		return File{}, err
	}
	return s.open(ctx, p, m)
}

// Digests returns p's digests from the digests object, or by reading the
// file to its end when there is none.
func (s *RegistrySource) Digests(ctx context.Context, p Path) (Digests, error) {
	p.Checksum = ""
	m, err := s.lookup(ctx, p)
	if err != nil {
		return Digests{}, err
	}
	if m.Key != "" {
		if d, ok := s.readDigests(ctx, m.SHA1); ok {
			return d.digests(), nil
		}
	}
	f, err := s.open(ctx, p, m)
	if err != nil {
		return Digests{}, err
	}
	defer f.Body.Close()
	h := NewHasher()
	if _, err := io.Copy(h, f.Body); err != nil {
		return Digests{}, err
	}
	d := h.Digests()
	// Only bytes the relay verified are recorded; an unchecked signature's
	// digests are answered and forgotten.
	if f.Digests.SHA1 != "" {
		if err := s.writeDigests(ctx, digestsObject{SHA1: d.SHA1, SHA256: d.SHA256, SHA512: d.SHA512, MD5: d.MD5, Modified: f.Modified}); err != nil {
			s.log.Warn("cache maven digests", "source", s.name, "file", p.File, "error", err)
		}
	}
	return d, nil
}

// open serves p as m describes it. A mapping without a SHA-1 asks the
// upstream for the file itself.
func (s *RegistrySource) open(ctx context.Context, p Path, m mapping) (File, error) {
	if m.SHA1 == "" {
		return s.openUnchecked(ctx, p)
	}
	rawURL := s.base + p.String()
	immutable := !p.Snapshot || !strings.HasPrefix(p.File, p.Coords.Artifact+"-"+p.Coords.Version)
	md := md5.New() //nolint:gosec // see the md5 import
	var modified time.Time
	fetch := func(ctx context.Context) (io.ReadCloser, int64, error) {
		body, size, mod, err := s.get(ctx, rawURL, s.maxArtifact)
		if errors.Is(err, resolve.ErrNotFound) {
			// Its .sha1 exists: a source fault, not a miss.
			return nil, 0, fmt.Errorf("upstream file missing although its checksum exists: %v", err) //nolint:errorlint // a 404 here is a fault, not a miss
		}
		if err != nil {
			return nil, 0, err
		}
		modified = mod
		return teeBody{io.TeeReader(body, md), body}, size, nil
	}
	onCommit := func(ctx context.Context, res relay.Result) error {
		pkg := p.Coords.Group + ":" + p.Coords.Artifact
		if err := s.checkChanged(ctx, pkg, p.Coords.Version, p.File, res.SHA256); err != nil {
			return err
		}
		if err := s.rec.PutProvenance(ctx, records.Provenance{
			Ecosystem: ecoName, Package: pkg, Version: p.Coords.Version, File: p.File, Source: s.name, SourceType: "registry",
			UpstreamURL: rawURL, DeclaredDigest: "sha1:" + m.SHA1, SHA1: res.SHA1, SHA256: res.SHA256,
		}); err != nil {
			return fmt.Errorf("record provenance: %w", err)
		}
		return s.writeDigests(ctx, digestsObject{
			SHA1: res.SHA1, SHA256: res.SHA256, SHA512: res.SHA512, MD5: hex.EncodeToString(md.Sum(nil)), Modified: modified,
		})
	}
	body, size, hit, err := s.relay.Open(ctx, m.Key, relay.Digest{SHA1: m.SHA1}, fetch, onCommit)
	if err != nil {
		return File{}, err
	}
	f := File{Body: body, Size: size, Digests: Digests{SHA1: m.SHA1}, Modified: modified, Immutable: immutable}
	if hit {
		metrics.ObserveCacheHit(ecoName, s.name)
		if d, ok := s.readDigests(ctx, m.SHA1); ok {
			f.Digests, f.Modified = d.digests(), d.Modified
		}
	}
	return f, nil
}

// teeBody reads through a TeeReader and closes the upstream body.
type teeBody struct {
	io.Reader
	io.Closer
}

// openUnchecked asks the upstream for a file that has no .sha1: a 404 is a
// miss (cached), a signature is streamed uncached, anything else is a fault.
func (s *RegistrySource) openUnchecked(ctx context.Context, p Path) (File, error) {
	body, size, mod, err := s.get(ctx, s.base+p.String(), maxSignature)
	isSig := slices.ContainsFunc(signatureSuffixes, func(sfx string) bool { return strings.HasSuffix(p.File, sfx) })
	switch {
	case errors.Is(err, resolve.ErrNotFound):
		if err := s.writeMapping(ctx, p, mapping{Miss: true}); err != nil {
			return File{}, err
		}
		return File{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, p.File)
	case !isSig && (err == nil || errors.Is(err, upstream.ErrTooLarge)):
		if body != nil {
			body.Close()
		}
		return File{}, fmt.Errorf("upstream declares no checksum for %s", p.File)
	case err != nil:
		return File{}, err
	}
	s.log.Debug("serving maven signature without upstream checksum, uncached", "source", s.name, "file", p.String())
	return File{Body: body, Size: size, Modified: mod}, nil
}

// lookup returns p's mapping, fetching its .sha1 when the cached one is
// absent or older than the ttl, and keeping the cached one when that fails.
// A mapping without a SHA-1 (no .sha1 upstream) is never cached.
func (s *RegistrySource) lookup(ctx context.Context, p Path) (mapping, error) {
	key := s.pathKey("paths", p) + ".json"
	cached, written, have := s.readMapping(ctx, key)
	if !have || s.now().Sub(written) >= s.ttl {
		m, err := flight.Do(ctx, &s.mapFlight, key, func() (mapping, error) {
			return s.refreshMapping(ctx, p, have)
		})
		switch {
		case err != nil && have:
			s.log.Warn("serving stale maven checksum", "source", s.name, "file", p.String(), "error", err)
		case err != nil:
			return mapping{}, err
		default:
			cached = m
		}
	} else {
		metrics.ObserveCacheHit(ecoName, s.name)
	}
	if cached.Miss {
		return mapping{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, p.File)
	}
	return cached, nil
}

func (s *RegistrySource) readMapping(ctx context.Context, key string) (mapping, time.Time, bool) {
	rc, written, err := s.cache.Get(ctx, key)
	if err != nil {
		return mapping{}, time.Time{}, false
	}
	defer rc.Close()
	var m mapping
	if json.NewDecoder(io.LimitReader(rc, maxChecksumFile)).Decode(&m) != nil || (!m.Miss && m.Key != s.filesKey(m.SHA1)) {
		return mapping{}, time.Time{}, false
	}
	return m, written, true
}

func (s *RegistrySource) filesKey(sha1Hex string) string {
	return "maven/" + s.name + "/files/sha1-" + sha1Hex
}

func (s *RegistrySource) writeMapping(ctx context.Context, p Path, m mapping) error {
	b, _ := json.Marshal(m)
	if err := s.cache.Put(ctx, s.pathKey("paths", p)+".json", bytes.NewReader(b)); err != nil {
		return fmt.Errorf("cache maven checksum: %w", err)
	}
	return nil
}

// refreshMapping fetches p's .sha1 and caches the mapping it gives. It runs
// on its own context: a client leaving does not cancel it while another
// waits.
func (s *RegistrySource) refreshMapping(ctx context.Context, p Path, haveCache bool) (mapping, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), metaFetchTimeout)
	defer cancel()
	m, err := s.fetchMapping(ctx, p)
	s.noteFetch(err, haveCache)
	return m, err
}

func (s *RegistrySource) fetchMapping(ctx context.Context, p Path) (mapping, error) {
	body, _, _, err := s.get(ctx, s.base+p.String()+".sha1", maxChecksumFile)
	if errors.Is(err, resolve.ErrNotFound) {
		return mapping{}, nil
	}
	if err != nil {
		return mapping{}, err
	}
	defer body.Close()
	sum, err := ParseChecksumFile(body, "sha1")
	if err != nil {
		return mapping{}, fmt.Errorf("upstream checksum of %s: %w", p.File, err)
	}
	m := mapping{SHA1: sum, Key: s.filesKey(sum)}
	return m, s.writeMapping(ctx, p, m)
}

func (s *RegistrySource) readDigests(ctx context.Context, sha1Hex string) (digestsObject, bool) {
	rc, _, err := s.cache.Get(ctx, s.digestsKey(sha1Hex))
	if err != nil {
		return digestsObject{}, false
	}
	defer rc.Close()
	var d digestsObject
	if json.NewDecoder(io.LimitReader(rc, maxChecksumFile)).Decode(&d) != nil || d.SHA1 != sha1Hex {
		return digestsObject{}, false
	}
	return d, true
}

func (s *RegistrySource) writeDigests(ctx context.Context, d digestsObject) error {
	b, _ := json.Marshal(d)
	if err := s.cache.Put(ctx, s.digestsKey(d.SHA1), bytes.NewReader(b)); err != nil {
		return fmt.Errorf("cache maven digests: %w", err)
	}
	return nil
}

// Metadata returns p's maven-metadata.xml exactly as the upstream sent it,
// once it passed CheckXML.
func (s *RegistrySource) Metadata(ctx context.Context, p Path) ([]byte, error) {
	p.Checksum = ""
	key := s.pathKey("metadata", p) + ".xml"
	cached, written, have := s.readMetadata(ctx, key)
	if !have || s.now().Sub(written) >= s.ttl {
		b, err := flight.Do(ctx, &s.metaFlight, key, func() ([]byte, error) {
			return s.refreshMetadata(ctx, p, key, have)
		})
		switch {
		case err != nil && have:
			s.log.Warn("serving stale maven metadata", "source", s.name, "path", p.String(), "error", err)
		case err != nil:
			return nil, err
		default:
			cached = b
		}
	} else {
		metrics.ObserveCacheHit(ecoName, s.name)
	}
	if bytes.Equal(cached, missMarker) {
		return nil, fmt.Errorf("%w: %s", resolve.ErrNotFound, p.String())
	}
	return cached, nil
}

func (s *RegistrySource) readMetadata(ctx context.Context, key string) ([]byte, time.Time, bool) {
	rc, written, err := s.cache.Get(ctx, key)
	if err != nil {
		return nil, time.Time{}, false
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, UpstreamXML.MaxBytes+1))
	if err != nil || int64(len(b)) > UpstreamXML.MaxBytes {
		return nil, time.Time{}, false
	}
	return b, written, true
}

// refreshMetadata fetches, checks and caches p's metadata, or the miss
// marker. It runs on its own context, as refreshMapping does.
func (s *RegistrySource) refreshMetadata(ctx context.Context, p Path, key string, haveCache bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), metaFetchTimeout)
	defer cancel()
	b, err := s.fetchMetadata(ctx, p)
	s.noteFetch(err, haveCache)
	if err != nil {
		return nil, err
	}
	if err := s.cache.Put(ctx, key, bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("cache maven metadata: %w", err)
	}
	return b, nil
}

func (s *RegistrySource) fetchMetadata(ctx context.Context, p Path) ([]byte, error) {
	body, _, _, err := s.get(ctx, s.base+p.String(), UpstreamXML.MaxBytes)
	if errors.Is(err, resolve.ErrNotFound) {
		return missMarker, nil
	}
	if err != nil {
		return nil, err
	}
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if err := CheckXML(bytes.NewReader(b), UpstreamXML, "metadata"); err != nil {
		return nil, fmt.Errorf("upstream %s: %w", p.String(), err)
	}
	return b, nil
}

// get opens rawURL as upstream.Client.Open does (a non-2xx answer is a
// *upstream.StatusError, more than maxBytes is upstream.ErrTooLarge) and
// also returns its Last-Modified time (zero when absent or unparseable).
func (s *RegistrySource) get(ctx context.Context, rawURL string, maxBytes int64) (io.ReadCloser, int64, time.Time, error) {
	if err := s.wait(ctx); err != nil {
		return nil, 0, time.Time{}, err
	}
	start := time.Now()
	resp, err := s.c.Get(ctx, rawURL)
	metrics.ObserveUpstream(s.name, time.Since(start))
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		return nil, 0, time.Time{}, &upstream.StatusError{Code: resp.StatusCode, URL: resp.Request.URL.Redacted()}
	}
	if resp.ContentLength > maxBytes {
		resp.Body.Close()
		return nil, 0, time.Time{}, upstream.ErrTooLarge
	}
	mod, _ := http.ParseTime(resp.Header.Get("Last-Modified")) // zero when absent or unparseable
	return &cappedBody{rc: resp.Body, left: maxBytes}, resp.ContentLength, mod, nil
}

// cappedBody fails with upstream.ErrTooLarge once more than its limit has
// been read.
type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, upstream.ErrTooLarge
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1] // one byte more than allowed detects overflow
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n + int(b.left), upstream.ErrTooLarge
	}
	return n, err
}

func (b *cappedBody) Close() error { return b.rc.Close() }

// checkChanged compares sha256Hex with the first digest this source
// recorded for the same file; a difference is served, logged and listed by
// Changed.
func (s *RegistrySource) checkChanged(ctx context.Context, pkg, version, file, sha256Hex string) error {
	digests, err := s.rec.ProvenanceDigests(ctx, ecoName, pkg, version)
	if err != nil {
		return fmt.Errorf("read provenance: %w", err)
	}
	var first *records.Provenance
	for _, d := range digests {
		if d == sha256Hex {
			continue
		}
		p, err := s.rec.GetProvenance(ctx, ecoName, pkg, version, d)
		if err != nil {
			return fmt.Errorf("read provenance: %w", err)
		}
		if p.Source == s.name && p.File == file && (first == nil || p.Created.Before(first.Created)) {
			first = &p
		}
	}
	if first == nil {
		return nil
	}
	s.log.Warn("maven file changed upstream; serving the new bytes", "source", s.name, "package", pkg,
		"version", version, "file", file, "first_sha256", first.SHA256, "seen_sha256", sha256Hex)
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if s.changed == nil {
		s.changed = map[[3]string]ChangedFile{}
	}
	s.changed[[3]string{pkg, version, file}] = ChangedFile{
		Package: pkg, Version: version, File: file, Source: s.name, FirstSHA256: first.SHA256, NowSHA256: sha256Hex, Seen: s.now(),
	}
	return nil
}

// Changed returns the files seen changing since start, sorted.
func (s *RegistrySource) Changed() []ChangedFile {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	out := slices.Collect(maps.Values(s.changed))
	slices.SortFunc(out, func(a, b ChangedFile) int {
		return cmp.Or(strings.Compare(a.Package, b.Package), strings.Compare(a.Version, b.Version), strings.Compare(a.File, b.File))
	})
	return out
}

// noteFetch records the outcome of a checksum or metadata fetch for Health.
// Fetches run detached from the request, so a client leaving never shows up
// here.
func (s *RegistrySource) noteFetch(err error, haveCache bool) {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	switch {
	case err == nil && s.fetchErr != nil:
		s.log.Info("maven upstream recovered", "source", s.name)
	case err != nil && s.fetchErr == nil:
		s.log.Warn("maven upstream unhealthy", "source", s.name, "stale", haveCache, "error", err)
	case err != nil:
		s.log.Debug("maven upstream still unhealthy", "source", s.name, "stale", haveCache, "error", err)
	}
	s.fetchErr, s.stale = err, err != nil && haveCache
}

// Health reports the last checksum or metadata fetch.
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
