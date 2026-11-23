package npm

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
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
	// metaFetchTimeout bounds a packument request including its body.
	metaFetchTimeout = 5 * time.Minute
	// maxPackumentBytes caps an upstream packument.
	maxPackumentBytes = 256 << 20
	// maxVersions caps the entries of an upstream "versions" object.
	maxVersions = 200_000
	// maxDepth caps the nesting of an upstream packument, the document
	// itself included.
	maxDepth = 64
	// maxKeyBytes caps every object key of an upstream packument.
	maxKeyBytes = 1 << 10
	// maxVersionKey caps a version; longer ones are dropped.
	maxVersionKey = 156
	// maxDistTags caps the upstream dist-tags; maxDistTagsBytes their size.
	maxDistTags      = 1000
	maxDistTagsBytes = 2 << 20
	// maxTimeBytes caps the upstream time object.
	maxTimeBytes = 32 << 20
)

// missMarker is cached as the file index of a package the upstream does not
// have (404, or no versions: unpublished).
var missMarker = []byte("\x00tspackages:not-found")

// errCacheGone reports a cached document that disappeared or is unreadable;
// the package is fetched again.
var errCacheGone = errors.New("npm: cached document gone")

// ChangedTarball is a tarball whose upstream bytes differ from the ones first
// recorded for its version by this source. It is served anyway and shown on
// the status page.
type ChangedTarball struct {
	Package, Version, Source string
	FirstSHA256, NowSHA256   string
	Seen                     time.Time
}

// RegistrySource passes through an npm registry. Packuments are streamed,
// filtered and rewritten into cached full and abbreviated documents plus a
// file index, refreshed after ttl and served stale when the upstream fails.
// Tarballs stream through the relay and are cached only once their declared
// digest matched.
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

	docFlight, keysFlight singleflight.Group

	hmu      sync.Mutex
	fetchErr error
	stale    bool

	cmu     sync.Mutex
	changed map[[2]string]ChangedTarball // by package and version
}

var (
	_ Source   = (*RegistrySource)(nil)
	_ Attester = (*RegistrySource)(nil)
)

// NewRegistrySource builds a pass-through source for the registry at baseURL
// (ending in "/"). wait, if non-nil, is called before every upstream request;
// log nil means slog.Default().
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

// key is the cache key of one of n's cached files.
func (s *RegistrySource) key(n Name, file string) string {
	return "npm/" + s.name + "/" + storage.EscapeSegment(n.Exact) + "/" + file
}

// docHeader is the first line of a cached full.json or corgi.json; the
// document follows it. It sits in the same object so it always describes
// the bytes after it.
type docHeader struct {
	SHA256 string `json:"sha256"`
	Tokens int    `json:"tokens"`
}

// fileEntry is one file of the index: a tarball file name's upstream
// location, declared digest and version. Attestations is the upstream URL of
// the version's attestation bundle.
type fileEntry struct {
	URL          string `json:"url"`
	Algo         string `json:"algo"` // "sha512" or "sha1"
	Digest       string `json:"digest"`
	Version      string `json:"version"`
	Attestations string `json:"attestations,omitempty"`
}

// Packument returns the cached full or abbreviated document.
func (s *RegistrySource) Packument(ctx context.Context, n Name, corgi bool) (Doc, error) {
	file := "full.json"
	if corgi {
		file = "corgi.json"
	}
	var doc Doc
	err := s.withIndex(ctx, n, func() error {
		var err error
		doc, err = s.openDoc(ctx, n, file)
		return err
	})
	return doc, err
}

// openDoc opens a cached document past its header.
func (s *RegistrySource) openDoc(ctx context.Context, n Name, file string) (Doc, error) {
	rc, size, err := s.cache.Open(ctx, s.key(n, file))
	if errors.Is(err, storage.ErrNotFound) {
		return Doc{}, errCacheGone
	}
	if err != nil {
		return Doc{}, err
	}
	br := bufio.NewReader(rc)
	line, err := br.ReadSlice('\n')
	var h docHeader
	if err != nil || json.Unmarshal(line, &h) != nil || !digest.IsHex(h.SHA256, 64) {
		rc.Close()
		return Doc{}, errCacheGone
	}
	body := struct {
		io.Reader
		io.Closer
	}{br, rc}
	return Doc{Body: body, Size: size - int64(len(line)), SHA256: h.SHA256, Tokens: h.Tokens}, nil
}

// DistTags returns the dist-tags of the cached packument.
func (s *RegistrySource) DistTags(ctx context.Context, n Name) (map[string]string, error) {
	var tags map[string]string
	err := s.withIndex(ctx, n, func() error {
		var err error
		tags, _, err = s.readIndex(ctx, n, "")
		return err
	})
	return tags, err
}

// Version returns one version object of the cached full document; a tag is
// resolved through the cached dist-tags. The document is scanned, not
// loaded.
func (s *RegistrySource) Version(ctx context.Context, n Name, versionOrTag string) ([]byte, error) {
	var obj []byte
	err := s.withIndex(ctx, n, func() error {
		tags, _, err := s.readIndex(ctx, n, "")
		if err != nil {
			return err
		}
		v := versionOrTag
		if t, ok := tags[versionOrTag]; ok {
			v = t
		}
		doc, err := s.openDoc(ctx, n, "full.json")
		if err != nil {
			return err
		}
		defer doc.Body.Close()
		obj, err = findVersion(doc.Body, v)
		return err
	})
	return obj, err
}

// Tarball streams a file listed in the index, verified against its declared
// digest.
func (s *RegistrySource) Tarball(ctx context.Context, n Name, file string) (Artifact, error) {
	e, err := s.lookup(ctx, n, file)
	if err != nil {
		return Artifact{}, err
	}
	want := relay.Digest{SHA1: e.Digest}
	if e.Algo == "sha512" {
		want = relay.Digest{SHA512: e.Digest}
	}
	onCommit := func(ctx context.Context, res relay.Result) error {
		if err := s.checkChanged(ctx, n.Exact, e.Version, res.SHA256); err != nil {
			return err
		}
		if err := s.rec.PutProvenance(ctx, records.Provenance{
			Ecosystem: ecoName, Package: n.Exact, Version: e.Version, Source: s.name, SourceType: "registry",
			UpstreamURL: e.URL, DeclaredDigest: e.Algo + ":" + e.Digest, SHA1: res.SHA1, SHA256: res.SHA256,
		}); err != nil {
			return fmt.Errorf("record provenance: %w", err)
		}
		return nil
	}
	return s.open(ctx, "npm/"+s.name+"/tarballs/"+e.Algo+"-"+e.Digest, e.URL, want, s.maxArtifact, onCommit)
}

// lookup returns the index entry of file.
func (s *RegistrySource) lookup(ctx context.Context, n Name, file string) (fileEntry, error) {
	var e *fileEntry
	err := s.withIndex(ctx, n, func() error {
		var err error
		_, e, err = s.readIndex(ctx, n, file)
		return err
	})
	if err != nil {
		return fileEntry{}, err
	}
	if e == nil {
		return fileEntry{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, file)
	}
	return *e, nil
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

// checkChanged compares sha256Hex with the first digest this source
// recorded for the version; a difference is served, logged and listed by
// Changed.
func (s *RegistrySource) checkChanged(ctx context.Context, pkg, version, sha256Hex string) error {
	digests, err := s.rec.ProvenanceDigests(ctx, ecoName, pkg, version)
	if err != nil {
		return fmt.Errorf("read provenance: %w", err)
	}
	// Records are read only when another digest is recorded, which is rare.
	if !slices.ContainsFunc(digests, func(d string) bool { return d != sha256Hex }) {
		return nil
	}
	var first *records.Provenance
	for _, d := range digests {
		p, err := s.rec.GetProvenance(ctx, ecoName, pkg, version, d)
		if err != nil {
			return fmt.Errorf("read provenance: %w", err)
		}
		if p.Source == s.name && (first == nil || p.Created.Before(first.Created)) {
			first = &p
		}
	}
	if first == nil || first.SHA256 == sha256Hex {
		return nil
	}
	s.log.Warn("npm tarball changed upstream; serving the new bytes", "source", s.name, "package", pkg,
		"version", version, "first_sha256", first.SHA256, "seen_sha256", sha256Hex)
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if s.changed == nil {
		s.changed = map[[2]string]ChangedTarball{}
	}
	s.changed[[2]string{pkg, version}] = ChangedTarball{
		Package: pkg, Version: version, Source: s.name, FirstSHA256: first.SHA256, NowSHA256: sha256Hex, Seen: s.now(),
	}
	return nil
}

// Changed returns the tarballs seen changing since start, sorted.
func (s *RegistrySource) Changed() []ChangedTarball {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	out := slices.Collect(maps.Values(s.changed))
	slices.SortFunc(out, func(a, b ChangedTarball) int {
		return cmp.Or(strings.Compare(a.Package, b.Package), strings.Compare(a.Version, b.Version))
	})
	return out
}

// withIndex runs fn once n's cached index is fresh (or stale, when the
// upstream fails). If fn finds a cached document gone, the package is
// fetched again and fn retried once. A definite miss is resolve.ErrNotFound.
func (s *RegistrySource) withIndex(ctx context.Context, n Name, fn func() error) error {
	if err := s.fresh(ctx, n, false); err != nil {
		return err
	}
	err := fn()
	if errors.Is(err, errCacheGone) {
		if err := s.fresh(ctx, n, true); err != nil {
			return err
		}
		err = fn()
	}
	return err
}

// fresh refreshes n's cache when it is absent, expired or (force) broken.
func (s *RegistrySource) fresh(ctx context.Context, n Name, force bool) error {
	key := s.key(n, "files.json")
	written, miss, have := s.indexState(ctx, key)
	missErr := fmt.Errorf("%w: %s", resolve.ErrNotFound, n.Exact)
	if have && !force && s.now().Sub(written) < s.ttl {
		metrics.ObserveCacheHit(ecoName, s.name)
		if miss {
			return missErr
		}
		return nil
	}
	missNow, err := flight.Do(ctx, &s.docFlight, key, func() (bool, error) {
		return s.refresh(ctx, n, have)
	})
	switch {
	case err != nil && have && !force:
		s.log.Warn("serving stale npm packument", "source", s.name, "package", n.Exact, "error", err)
		missNow = miss
	case err != nil:
		return err
	}
	if missNow {
		return missErr
	}
	return nil
}

// indexState reports when n's index was written and whether it is the miss
// marker.
func (s *RegistrySource) indexState(ctx context.Context, key string) (written time.Time, miss, ok bool) {
	rc, written, err := s.cache.Get(ctx, key)
	if err != nil {
		return time.Time{}, false, false
	}
	defer rc.Close()
	head := make([]byte, len(missMarker))
	k, _ := io.ReadFull(rc, head)
	return written, bytes.Equal(head[:k], missMarker), true
}

// readIndex reads the dist-tags of n's index and, when file is not empty,
// its entry (nil when not listed). The index is decoded as a stream.
func (s *RegistrySource) readIndex(ctx context.Context, n Name, file string) (map[string]string, *fileEntry, error) {
	rc, _, err := s.cache.Get(ctx, s.key(n, "files.json"))
	if err != nil {
		return nil, nil, errCacheGone
	}
	defer rc.Close()
	dec := json.NewDecoder(rc)
	var tags map[string]string
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil, errCacheGone
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, errCacheGone
		}
		switch t {
		case "dist-tags":
			err = dec.Decode(&tags)
		case "files":
			if file == "" {
				return tags, nil, nil
			}
			e, ferr := findEntry(dec, file)
			if ferr != nil {
				return nil, nil, errCacheGone
			}
			return tags, e, nil
		default:
			err = dec.Decode(new(json.RawMessage))
		}
		if err != nil {
			return nil, nil, errCacheGone
		}
	}
	return nil, nil, errCacheGone
}

func findEntry(dec *json.Decoder, file string) (*fileEntry, error) {
	if t, err := dec.Token(); err != nil {
		return nil, err
	} else if t != json.Delim('{') {
		return nil, errors.New("file index: files is not an object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if t != file {
			if err := dec.Decode(new(json.RawMessage)); err != nil {
				return nil, err
			}
			continue
		}
		var e fileEntry
		if err := dec.Decode(&e); err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, nil
}

// refresh fetches and caches n's documents, or the miss marker. It runs on
// its own context: a client leaving does not cancel it while another waits.
func (s *RegistrySource) refresh(ctx context.Context, n Name, haveCache bool) (miss bool, err error) {
	ctx = context.WithoutCancel(ctx)
	fctx, cancel := context.WithTimeout(ctx, metaFetchTimeout)
	defer cancel()
	miss, err = s.fetchAndStore(fctx, n)
	s.noteFetch(ctx, err, haveCache)
	return miss, err
}

// tempFile is an unlinked-on-close temporary file.
type tempFile struct{ *os.File }

func newTemp() (tempFile, error) {
	f, err := os.CreateTemp("", "npm-packument-*")
	return tempFile{f}, err
}

func (f tempFile) remove() {
	f.Close()
	os.Remove(f.Name()) //nolint:gosec // our own os.CreateTemp file
}

// hashWriter hashes and counts what it writes to a buffered file.
type hashWriter struct {
	w *bufio.Writer
	h hash.Hash
}

func newHashWriter(f tempFile) *hashWriter {
	return &hashWriter{w: bufio.NewWriterSize(f, 64<<10), h: sha256.New()}
}

func (w *hashWriter) Write(p []byte) (int, error) {
	w.h.Write(p)
	return w.w.Write(p)
}

func (s *RegistrySource) fetchAndStore(ctx context.Context, n Name) (bool, error) {
	if err := s.wait(ctx); err != nil {
		return false, err
	}
	start := time.Now()
	resp, err := s.c.GetAccept(ctx, s.base+n.Escaped(), "application/json")
	metrics.ObserveUpstream(s.name, time.Since(start))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	indexKey := s.key(n, "files.json")
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return true, s.cache.Put(ctx, indexKey, bytes.NewReader(missMarker))
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return false, &upstream.StatusError{Code: resp.StatusCode, URL: resp.Request.URL.Redacted()}
	}
	var files [4]tempFile // spool, full, corgi, entries
	for i := range files {
		if files[i], err = newTemp(); err != nil {
			return false, err
		}
		defer files[i].remove()
	}
	spool, fullF, corgiF, entriesF := files[0], files[1], files[2], files[3]
	size, err := io.Copy(spool, io.LimitReader(resp.Body, maxPackumentBytes+1))
	if err != nil {
		return false, fmt.Errorf("read upstream packument: %w", err)
	}
	if size > maxPackumentBytes {
		return false, upstream.ErrTooLarge
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	full, corgi, entries := newHashWriter(fullF), newHashWriter(corgiF), bufio.NewWriter(entriesF)
	res, err := s.build(n, spool.File, full, corgi, entries)
	if err != nil {
		return false, err
	}
	if res.miss {
		return true, s.cache.Put(ctx, indexKey, bytes.NewReader(missMarker))
	}
	for _, w := range []*bufio.Writer{full.w, corgi.w, entries} {
		if err := w.Flush(); err != nil {
			return false, err
		}
	}
	for _, d := range []struct {
		f      tempFile
		w      *hashWriter
		tokens int
		name   string
	}{{fullF, full, res.tokFull, "full.json"}, {corgiF, corgi, res.tokCorgi, "corgi.json"}} {
		header, _ := json.Marshal(docHeader{SHA256: hex.EncodeToString(d.w.h.Sum(nil)), Tokens: d.tokens})
		if _, err := d.f.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		if err := s.cache.Put(ctx, s.key(n, d.name), io.MultiReader(bytes.NewReader(append(header, '\n')), d.f)); err != nil {
			return false, fmt.Errorf("cache npm %s: %w", d.name, err)
		}
	}
	// The index goes last: its write time is the packument's.
	if _, err := entriesF.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	head := append(append([]byte(`{"dist-tags":`), RenderDistTags(res.tags)...), `,"files":{`...)
	if err := s.cache.Put(ctx, indexKey, io.MultiReader(bytes.NewReader(head), entriesF, strings.NewReader("}}"))); err != nil {
		return false, fmt.Errorf("cache npm file index: %w", err)
	}
	return false, nil
}

// buildResult is what build produced besides the documents.
type buildResult struct {
	miss              bool
	tags              map[string]string
	tokFull, tokCorgi int
}

// prepared is a version that passed validation, rendered.
type prepared struct {
	full, corgi []byte
	files       []string // canonical name, then the upstream alias if it differs
	entry       fileEntry
}

// build renders an upstream packument into the full and abbreviated
// documents and the file index entries ("<file>":{...},...). It walks the
// body twice: first to find the versions to keep (valid, and no file name
// shared with another version), then to render them. A body without
// versions is a miss.
func (s *RegistrySource) build(n Name, body io.ReadSeeker, full, corgi, entries io.Writer) (buildResult, error) {
	valid := map[string]bool{}    // well-formed version keys seen, and whether the version is usable
	owner := map[string]string{}  // file name → version
	collided := map[string]bool{} // versions dropped for a shared file name or a repeated key
	w, err := walkPackument(body, func(key string, raw []byte) error {
		if !validVersionKey(key) {
			return nil
		}
		if _, dup := valid[key]; dup {
			collided[key] = true
			return nil
		}
		p, ok := s.prepare(n, key, raw)
		valid[key] = ok
		if !ok {
			return nil
		}
		for _, f := range p.files {
			if o, taken := owner[f]; taken {
				collided[o], collided[key] = true, true
			} else {
				owner[f] = key
			}
		}
		return nil
	})
	if err != nil {
		return buildResult{}, fmt.Errorf("upstream packument: %w", err)
	}
	if w.versions == 0 {
		return buildResult{miss: true}, nil
	}
	if w.name != n.Exact {
		return buildResult{}, fmt.Errorf("upstream packument names %q, not %q", w.name, n.Exact)
	}
	kept := func(v string) bool { return valid[v] && !collided[v] }

	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return buildResult{}, err
	}
	dw := NewDocWriter(full, corgi)
	sep := ""
	if _, err := walkPackument(body, func(key string, raw []byte) error {
		if !kept(key) {
			return nil
		}
		p, _ := s.prepare(n, key, raw)
		if err := dw.Version(key, p.full, p.corgi); err != nil {
			return err
		}
		e, _ := json.Marshal(p.entry)
		for _, f := range p.files {
			if _, err := io.WriteString(entries, sep+string(encString(f))+":"+string(e)); err != nil {
				return err
			}
			sep = ","
		}
		return nil
	}); err != nil {
		return buildResult{}, fmt.Errorf("upstream packument: %w", err)
	}
	for k, raw := range w.top {
		dw.Top(k, raw)
	}
	tags := map[string]string{}
	for t, v := range w.tags {
		if kept(v) {
			tags[t] = v
		}
	}
	times := map[string]string{}
	for k, v := range w.times {
		// Entries of versions the upstream no longer lists are kept, as
		// npmjs serves them; entries of dropped versions are not.
		_, listed := valid[k]
		if k == "created" || k == "modified" || kept(k) || !listed && validVersionKey(k) {
			times[k] = v
		}
	}
	if err := dw.Close(tags, times); err != nil {
		return buildResult{}, err
	}
	tf, tc := dw.Tokens()
	return buildResult{tags: tags, tokFull: tf, tokCorgi: tc}, nil
}

// validVersionKey reports whether a version can be served: at most 156
// bytes, without "/", "%", whitespace or control bytes.
func validVersionKey(v string) bool {
	if v == "" || len(v) > maxVersionKey {
		return false
	}
	for _, c := range []byte(v) {
		if c <= ' ' || c == 0x7f || c == '/' || c == '%' {
			return false
		}
	}
	return true
}

// prepare validates and renders one upstream version object (raw is nil
// when it exceeded MaxVersionBytes). It is deterministic: build calls it
// once per walk.
func (s *RegistrySource) prepare(n Name, key string, raw []byte) (prepared, bool) {
	var obj map[string]json.RawMessage
	if raw == nil || json.Unmarshal(raw, &obj) != nil {
		return prepared{}, false
	}
	var name, version string
	if json.Unmarshal(obj["name"], &name) != nil || name != n.Exact || json.Unmarshal(obj["version"], &version) != nil || version != key {
		return prepared{}, false
	}
	var dist struct {
		Tarball      string          `json:"tarball"`
		Integrity    string          `json:"integrity"`
		Shasum       string          `json:"shasum"`
		FileCount    json.RawMessage `json:"fileCount"`
		UnpackedSize json.RawMessage `json:"unpackedSize"`
		Signatures   json.RawMessage `json:"signatures"`
		NPMSignature json.RawMessage `json:"npm-signature"`
		Attestations *struct {
			URL        string          `json:"url"`
			Provenance json.RawMessage `json:"provenance"`
		} `json:"attestations"`
	}
	if json.Unmarshal(obj["dist"], &dist) != nil {
		return prepared{}, false
	}
	e := fileEntry{URL: dist.Tarball, Version: key}
	if algo, sum, ok := digest.ParseIntegrity(dist.Integrity); ok {
		e.Algo, e.Digest = algo, sum
	} else if sum := strings.ToLower(dist.Shasum); digest.IsHex(sum, 40) {
		e.Algo, e.Digest = "sha1", sum
	} else {
		return prepared{}, false
	}
	if !s.c.Allowed(dist.Tarball) {
		return prepared{}, false
	}
	canonical := n.TarballFile(key)
	d := Dist{
		Tarball: BaseToken + n.Exact + "/-/" + canonical, Integrity: dist.Integrity, Shasum: dist.Shasum,
		Signatures: dist.Signatures, NPMSignature: dist.NPMSignature,
	}
	_ = json.Unmarshal(dist.FileCount, &d.FileCount) // optional: unusable counts are left out
	_ = json.Unmarshal(dist.UnpackedSize, &d.UnpackedSize)
	if a := dist.Attestations; a != nil && s.c.Allowed(a.URL) {
		d.AttestationsURL = BaseToken + "-/npm/v1/attestations/" + n.Exact + "@" + key
		d.AttestationsProvenance = a.Provenance
		e.Attestations = a.URL
	}
	full, corgi, err := RenderVersion(obj, d)
	if err != nil || len(full) > MaxVersionBytes || len(corgi) > MaxVersionBytes {
		return prepared{}, false
	}
	files := []string{canonical}
	if u, err := url.Parse(dist.Tarball); err == nil {
		if alias := path.Base(u.Path); alias != canonical && strings.HasSuffix(alias, ".tgz") {
			files = append(files, alias)
		}
	}
	return prepared{full: full, corgi: corgi, files: files, entry: e}, true
}

// noteFetch records the outcome of a packument fetch for Health; a
// cancelled request says nothing about upstream.
func (s *RegistrySource) noteFetch(ctx context.Context, err error, haveCache bool) {
	if ctx.Err() != nil {
		return
	}
	s.hmu.Lock()
	defer s.hmu.Unlock()
	switch {
	case err == nil && s.fetchErr != nil:
		s.log.Info("npm upstream recovered", "source", s.name)
	case err != nil && s.fetchErr == nil:
		s.log.Warn("npm upstream unhealthy", "source", s.name, "stale", haveCache, "error", err)
	case err != nil:
		s.log.Debug("npm upstream still unhealthy", "source", s.name, "stale", haveCache, "error", err)
	}
	s.fetchErr, s.stale = err, err != nil && haveCache
}

// Health reports the last packument fetch.
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

// walked is what walkPackument collected besides the versions.
type walked struct {
	name     string
	top      map[string]json.RawMessage // kept top-level fields
	tags     map[string]string
	times    map[string]string
	versions int // entries of "versions"
}

var (
	errMalformed = errors.New("malformed JSON")
	errTooDeep   = fmt.Errorf("nesting exceeds %d", maxDepth)
)

// walkPackument scans an upstream packument without decoding it whole. It
// calls onVersion for every entry of "versions" with its raw object, or nil
// when that exceeds MaxVersionBytes, and buffers the kept top-level fields,
// "dist-tags" and "time".
func walkPackument(r io.Reader, onVersion func(key string, raw []byte) error) (walked, error) {
	sc := &scanner{r: bufio.NewReaderSize(r, 64<<10)}
	w := walked{top: map[string]json.RawMessage{}}
	err := sc.object(nil, 0, func(key string) error {
		switch {
		case key == "versions":
			c := &capture{limit: MaxVersionBytes}
			return sc.object(nil, 1, func(v string) error {
				if w.versions++; w.versions > maxVersions {
					return fmt.Errorf("more than %d versions", maxVersions)
				}
				c.buf, c.over = c.buf[:0], false
				if err := sc.value(c, 2); err != nil {
					return err
				}
				var raw []byte
				if !c.over {
					raw = c.buf
				}
				return onVersion(v, raw)
			})
		case key == "dist-tags":
			m, err := sc.stringMap(maxDistTagsBytes, maxDistTags)
			w.tags = m
			return err
		case key == "time":
			m, err := sc.stringMap(maxTimeBytes, maxVersions+2)
			w.times = m
			return err
		case slices.Contains(fullTopFields, key):
			c := &capture{limit: maxTopBytes}
			if err := sc.value(c, 1); err != nil {
				return err
			}
			if c.over {
				return fmt.Errorf("top-level field %s exceeds %d bytes", key, maxTopBytes)
			}
			w.top[key] = c.buf
			if key == "name" {
				_ = json.Unmarshal(c.buf, &w.name) // a non-string name matches no package
			}
			return nil
		default:
			return sc.value(nil, 1)
		}
	})
	if err != nil {
		return w, err
	}
	if _, err := sc.next(); !errors.Is(err, io.EOF) {
		return w, fmt.Errorf("%w: data after the document", errMalformed)
	}
	return w, nil
}

// stringMap reads an object value of at most limit bytes and n entries and
// keeps its string members.
func (sc *scanner) stringMap(limit, n int) (map[string]string, error) {
	c := &capture{limit: limit}
	if err := sc.value(c, 1); err != nil {
		return nil, err
	}
	if c.over {
		return nil, fmt.Errorf("object exceeds %d bytes", limit)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(c.buf, &raw); err != nil {
		return nil, err
	}
	if len(raw) > n {
		return nil, fmt.Errorf("object has more than %d entries", n)
	}
	m := make(map[string]string, len(raw))
	for k, v := range raw {
		var str string
		if json.Unmarshal(v, &str) == nil {
			m[k] = str
		}
	}
	return m, nil
}

// findVersion scans a cached full document (as DocWriter writes it,
// "versions" first) for version v.
func findVersion(r io.Reader, v string) ([]byte, error) {
	sc := &scanner{r: bufio.NewReaderSize(r, 64<<10)}
	var obj []byte
	found := false
	errStop := errors.New("stop")
	err := sc.object(nil, 0, func(key string) error {
		if key != "versions" {
			return fmt.Errorf("%w: cached document does not start with versions", errMalformed)
		}
		err := sc.object(nil, 1, func(k string) error {
			if k != v {
				return sc.value(nil, 2)
			}
			c := &capture{limit: MaxVersionBytes}
			if err := sc.value(c, 2); err != nil {
				return err
			}
			obj, found = c.buf, true
			return errStop
		})
		if err == nil {
			err = errStop
		}
		return err
	})
	switch {
	case errors.Is(err, errStop) && found:
		return obj, nil
	case errors.Is(err, errStop):
		return nil, fmt.Errorf("%w: version %s", resolve.ErrNotFound, v)
	}
	return nil, fmt.Errorf("%w: %v", errCacheGone, err) //nolint:errorlint // an unreadable cached document is rebuilt, whatever the cause
}

// capture collects the raw bytes of a value up to limit; past it, it drops
// them and sets over.
type capture struct {
	buf   []byte
	limit int
	over  bool
}

func (c *capture) add(b []byte) {
	if c == nil || c.over {
		return
	}
	if len(c.buf)+len(b) > c.limit {
		c.over, c.buf = true, c.buf[:0]
		return
	}
	c.buf = append(c.buf, b...)
}

func (c *capture) addByte(b byte) {
	if c == nil || c.over {
		return
	}
	if len(c.buf) >= c.limit {
		c.over, c.buf = true, c.buf[:0]
		return
	}
	c.buf = append(c.buf, b)
}

// scanner is a JSON tokenizer that skips or copies values without
// buffering them. It checks structure, nesting and key length; captured
// values are validated again by whoever decodes them.
type scanner struct{ r *bufio.Reader }

// next consumes and returns the next byte after whitespace.
func (sc *scanner) next() (byte, error) {
	for {
		b, err := sc.r.ReadByte()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return b, nil
	}
}

func (sc *scanner) peek() (byte, error) {
	b, err := sc.next()
	if err == nil {
		_ = sc.r.UnreadByte() // undoes the ReadByte above
	}
	return b, err
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// object reads an object at the given depth (containers already open),
// calling member for each key with the scanner positioned at its value,
// which member must consume.
func (sc *scanner) object(c *capture, depth int, member func(key string) error) error {
	b, err := sc.next()
	if err != nil {
		return unexpected(err)
	}
	if b != '{' {
		return fmt.Errorf("%w: want an object", errMalformed)
	}
	if depth >= maxDepth {
		return errTooDeep
	}
	c.addByte('{')
	if p, err := sc.peek(); err != nil {
		return unexpected(err)
	} else if p == '}' {
		_, _ = sc.r.ReadByte()
		c.addByte('}')
		return nil
	}
	for {
		key, err := sc.key(c)
		if err != nil {
			return err
		}
		if b, err := sc.next(); err != nil {
			return unexpected(err)
		} else if b != ':' {
			return fmt.Errorf("%w: want ':'", errMalformed)
		}
		c.addByte(':')
		if err := member(key); err != nil {
			return err
		}
		b, err := sc.next()
		if err != nil {
			return unexpected(err)
		}
		c.addByte(b)
		switch b {
		case '}':
			return nil
		case ',':
		default:
			return fmt.Errorf("%w: want ',' or '}'", errMalformed)
		}
	}
}

// key reads an object key of at most maxKeyBytes.
func (sc *scanner) key(c *capture) (string, error) {
	b, err := sc.next()
	if err != nil {
		return "", unexpected(err)
	}
	if b != '"' {
		return "", fmt.Errorf("%w: want a key", errMalformed)
	}
	c.addByte('"')
	raw := []byte{'"'}
	if err := sc.stringRest(c, &raw); err != nil {
		return "", err
	}
	var k string
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", fmt.Errorf("%w: key: %w", errMalformed, err)
	}
	return k, nil
}

// stringRest reads a string after its opening quote. keep, when not nil,
// collects it and caps it at maxKeyBytes.
func (sc *scanner) stringRest(c *capture, keep *[]byte) error {
	for {
		if _, err := sc.r.Peek(1); err != nil {
			return unexpected(err)
		}
		buf, _ := sc.r.Peek(sc.r.Buffered())
		i := bytes.IndexByte(buf, '"')
		chunk := buf
		if i >= 0 {
			chunk = buf[:i]
		}
		if j := bytes.IndexByte(chunk, '\\'); j >= 0 {
			chunk, i = chunk[:j], j
		}
		if keep != nil {
			if len(*keep)+len(chunk) > maxKeyBytes {
				return fmt.Errorf("key exceeds %d bytes", maxKeyBytes)
			}
			*keep = append(*keep, chunk...)
		}
		c.add(chunk)
		_, _ = sc.r.Discard(len(chunk)) // buffered
		if i < 0 {
			continue
		}
		b, _ := sc.r.ReadByte() // buffered
		c.addByte(b)
		if keep != nil {
			*keep = append(*keep, b)
		}
		if b == '"' {
			return nil
		}
		esc, err := sc.r.ReadByte()
		if err != nil {
			return unexpected(err)
		}
		c.addByte(esc)
		if keep != nil {
			*keep = append(*keep, esc)
		}
	}
}

// value reads one value at the given depth.
func (sc *scanner) value(c *capture, depth int) error {
	b, err := sc.peek()
	if err != nil {
		return unexpected(err)
	}
	switch {
	case b == '{':
		return sc.object(c, depth, func(string) error { return sc.value(c, depth+1) })
	case b == '[':
		_, _ = sc.r.ReadByte()
		if depth >= maxDepth {
			return errTooDeep
		}
		c.addByte('[')
		if p, err := sc.peek(); err != nil {
			return unexpected(err)
		} else if p == ']' {
			_, _ = sc.r.ReadByte()
			c.addByte(']')
			return nil
		}
		for {
			if err := sc.value(c, depth+1); err != nil {
				return err
			}
			b, err := sc.next()
			if err != nil {
				return unexpected(err)
			}
			c.addByte(b)
			switch b {
			case ']':
				return nil
			case ',':
			default:
				return fmt.Errorf("%w: want ',' or ']'", errMalformed)
			}
		}
	case b == '"':
		_, _ = sc.r.ReadByte()
		c.addByte('"')
		return sc.stringRest(c, nil)
	case b == 't' || b == 'f' || b == 'n':
		lit := map[byte]string{'t': "true", 'f': "false", 'n': "null"}[b]
		got := make([]byte, len(lit))
		if _, err := io.ReadFull(sc.r, got); err != nil {
			return unexpected(err)
		}
		if string(got) != lit {
			return fmt.Errorf("%w: bad literal", errMalformed)
		}
		c.add(got)
		return nil
	case b == '-' || b >= '0' && b <= '9':
		for {
			b, err := sc.r.ReadByte()
			if err != nil {
				return unexpected(err) // a number never ends the document
			}
			if b != '+' && b != '-' && b != '.' && b != 'e' && b != 'E' && (b < '0' || b > '9') {
				_ = sc.r.UnreadByte()
				return nil
			}
			c.addByte(b)
		}
	}
	return fmt.Errorf("%w: unexpected %q", errMalformed, b)
}
