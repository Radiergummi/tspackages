package apt

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/url"
	"path"
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

const (
	// releaseFetchTimeout bounds a Release refresh, signature included.
	releaseFetchTimeout = 5 * time.Minute
	// maxReleaseObject caps the cached Release object: the upstream
	// files, base64-encoded, and the previous Release's hash list.
	maxReleaseObject = 24 << 20
	// maxFutureDate is how far ahead of the clock an upstream Release's
	// Date may be; a later one would raise the high-water mark past every
	// honest Release until then.
	maxFutureDate = 24 * time.Hour
)

// RegistryConfig configures a RegistrySource.
type RegistryConfig struct {
	Name, URL                         string
	Keyring                           *Keyring
	Suites, Components, Architectures []string
	TTL                               time.Duration
	MaxArtifact                       int64
	Claimed                           func(name string) bool // any storage source's claim matches
}

// ChangedFile is a pool file whose upstream bytes differ from the ones this
// source first recorded for it. It is served anyway and shown on the status
// page.
type ChangedFile struct{ Source, Package, Path, First, Now string }

// RegistrySource passes one upstream apt repository through. The upstream
// Release (InRelease, else Release and Release.gpg) is verified against the
// keyring and served byte for byte; it is refreshed after the TTL and served
// stale when the refresh fails or is rejected. A dists file is served only
// when the verified Release lists it, a pool file only when the lookup built
// from the verified Packages indexes of the current or the previous Release
// lists it; both are verified by SHA256
// through the relay before they are cached, keyed by that hash:
//
//	apt/<src>/dists/<suite>/release                 the verified Release (JSON)
//	apt/<src>/sha256-<hex>                          a verified dists or pool file
//	apt/<src>/lookup/<release sha256>/<xx>.json     the pool lookup, see lookup.go
//
// The state store holds, per suite, the Date of the newest Release accepted
// (apt/<src>/release-mark/<suite>): no older one is accepted, whatever the
// cache has lost.
//
// Suites, components and architectures not configured are misses without an
// upstream request; so is a package any storage source claims.
type RegistrySource struct {
	cfg    RegistryConfig // URL ends in "/"
	suites map[string]bool
	archs  []string // configured, and "all"
	c      *upstream.Client
	cache  *storage.Cache
	state  storage.Driver // the Release high-water marks
	relay  *relay.Relay
	rec    *records.Store
	wait   func(context.Context) error
	log    *slog.Logger
	now    func() time.Time // replaced in tests

	relFlight, lookupFlight singleflight.Group

	mu     sync.Mutex
	states map[string]*relState // by suite

	hmu      sync.Mutex
	fetchErr error
	stale    bool

	cmu     sync.Mutex
	changed map[string]ChangedFile // by pool path
}

var _ Source = (*RegistrySource)(nil)

// NewRegistrySource returns a pass-through source for the repository at
// cfg.URL that keeps its Release high-water marks in state. wait, if non-nil, is called before every upstream request; log
// nil means slog.Default().
func NewRegistrySource(cfg RegistryConfig, c *upstream.Client, cache *storage.Cache, state storage.Driver, rl *relay.Relay, rec *records.Store, wait func(context.Context) error, log *slog.Logger) *RegistrySource {
	if log == nil {
		log = slog.Default()
	}
	if wait == nil {
		wait = func(context.Context) error { return nil }
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/") + "/"
	s := &RegistrySource{cfg: cfg, suites: map[string]bool{}, c: c, cache: cache, state: state, relay: rl, rec: rec, wait: wait, log: log,
		now: time.Now, states: map[string]*relState{}}
	for _, suite := range cfg.Suites {
		s.suites[suite] = true
	}
	s.archs = slices.Clone(cfg.Architectures)
	if !slices.Contains(s.archs, "all") {
		s.archs = append(s.archs, "all")
	}
	return s
}

func (s *RegistrySource) Name() string { return s.cfg.Name }

// releaseObj is what the cache holds of a suite's verified Release: the
// upstream bytes (InRelease, or Release and Release.gpg) and, of the
// Release it replaced, the SHA256 list (whose by-hash files stay served),
// its sha256 and whether it said Acquire-By-Hash (for its pool lookup).
type releaseObj struct {
	InRelease      []byte     `json:"in_release,omitempty"`
	Release        []byte     `json:"release,omitempty"`
	ReleaseGPG     []byte     `json:"release_gpg,omitempty"`
	Previous       []FileHash `json:"previous,omitempty"`
	PreviousSHA256 string     `json:"previous_sha256,omitempty"`
	PreviousByHash bool       `json:"previous_by_hash,omitempty"`
}

// relState is a suite's verified Release, ready to answer requests. It is
// not changed once built.
type relState struct {
	obj     releaseObj
	text    []byte // the Release text the signature covers
	doc     ReleaseDoc
	sum     string                 // sha256 of the verified upstream bytes: InRelease, else Release
	files   map[string]FileHash    // the current Release's list, by path
	hashes  map[[2]string]FileHash // the current and previous lists, by directory and sha256
	fetched time.Time
	// prev is the Release this one replaced, as far as its pool lookup
	// needs it; nil when unknown.
	prev *relState
}

// newState verifies obj and parses its Release.
func (s *RegistrySource) newState(obj releaseObj, fetched time.Time) (*relState, error) {
	var text, signed []byte
	if len(obj.InRelease) > 0 {
		t, err := s.cfg.Keyring.VerifyInRelease(obj.InRelease, s.now())
		if err != nil {
			return nil, err
		}
		text, signed = t, obj.InRelease
	} else {
		if err := s.cfg.Keyring.VerifyDetached(obj.Release, obj.ReleaseGPG, s.now()); err != nil {
			return nil, err
		}
		text, signed = obj.Release, obj.Release
	}
	doc, err := ParseRelease(text)
	if err != nil {
		return nil, err
	}
	st := &relState{obj: obj, text: text, doc: doc, sum: hexSHA256(signed), files: map[string]FileHash{},
		hashes: map[[2]string]FileHash{}, fetched: fetched}
	for _, h := range obj.Previous {
		st.hashes[[2]string{path.Dir(h.Path), h.SHA256}] = h
	}
	if obj.PreviousSHA256 != "" {
		st.prev = &relState{sum: obj.PreviousSHA256, doc: ReleaseDoc{ByHash: obj.PreviousByHash, SHA256: obj.Previous},
			files: map[string]FileHash{}}
		for _, h := range obj.Previous {
			st.prev.files[h.Path] = h
		}
	}
	for _, h := range doc.SHA256 {
		st.files[h.Path] = h
		st.hashes[[2]string{path.Dir(h.Path), h.SHA256}] = h
	}
	return st, nil
}

func (s *RegistrySource) releaseKey(suite string) string {
	return "apt/" + s.cfg.Name + "/dists/" + storage.EscapeSegment(suite) + "/release"
}

// hashKey is the cache key of verified bytes with sha256Hex, dists and pool
// files alike.
func (s *RegistrySource) hashKey(sha256Hex string) string {
	return "apt/" + s.cfg.Name + "/sha256-" + sha256Hex
}

// Release serves the verified upstream Release of suite: InRelease when the
// upstream has one; Release as the upstream's, or else the signed text of
// its InRelease; Release.gpg only when the upstream has no InRelease.
func (s *RegistrySource) Release(ctx context.Context, _ ReadAccess, suite, which string) (Blob, error) {
	st, err := s.current(ctx, suite)
	if err != nil {
		return Blob{}, err
	}
	var b []byte
	switch which {
	case "InRelease":
		b = st.obj.InRelease
	case "Release":
		b = st.text
	case "Release.gpg":
		b = st.obj.ReleaseGPG
	}
	if len(b) == 0 {
		return Blob{}, fmt.Errorf("%w: %s/%s", resolve.ErrNotFound, suite, which)
	}
	return Blob{Body: io.NopCloser(bytes.NewReader(b)), Size: int64(len(b)), ETag: etagOf(b), Modified: st.doc.Date}, nil
}

// Dist serves a file the verified Release lists below dists/<suite>/.
func (s *RegistrySource) Dist(ctx context.Context, _ ReadAccess, suite, rel string) (Blob, error) {
	miss := fmt.Errorf("%w: %s/%s", resolve.ErrNotFound, suite, rel)
	if !s.suites[suite] || !s.allowedDir(path.Dir(rel)) {
		return Blob{}, miss
	}
	st, err := s.current(ctx, suite)
	if err != nil {
		return Blob{}, err
	}
	fh, ok := st.files[rel]
	if !ok {
		return Blob{}, miss
	}
	body, size, _, err := s.openListed(ctx, suite, st, fh)
	if err != nil {
		return Blob{}, err
	}
	return Blob{Body: body, Size: size, ETag: `"` + fh.SHA256 + `"`, Modified: st.doc.Date}, nil
}

// ByHash serves <dir>/by-hash/SHA256/<sum> when the current or the previous
// verified Release lists a file in dir with that hash.
func (s *RegistrySource) ByHash(ctx context.Context, _ ReadAccess, suite, rel, sum string) (Blob, error) {
	miss := fmt.Errorf("%w: %s/%s", resolve.ErrNotFound, suite, rel)
	dir, ok := strings.CutSuffix(rel, "/by-hash/SHA256/"+sum)
	if !ok || !isHex64(sum) || !s.suites[suite] || !s.allowedDir(dir) {
		return Blob{}, miss
	}
	st, err := s.current(ctx, suite)
	if err != nil {
		return Blob{}, err
	}
	fh, ok := st.hashes[[2]string{dir, sum}]
	if !ok {
		return Blob{}, miss
	}
	body, size, _, err := s.openListed(ctx, suite, st, fh)
	if err != nil {
		return Blob{}, err
	}
	return Blob{Body: body, Size: size, ETag: `"` + sum + `"`, Immutable: true}, nil
}

// allowedDir reports whether dir, a directory below dists/<suite>/ ("." for
// the suite itself), is in a configured component and names no
// binary-<arch> directory of an architecture not configured ("all" always
// is).
func (s *RegistrySource) allowedDir(dir string) bool {
	if dir == "." {
		return true
	}
	segs := strings.Split(dir, "/")
	if !slices.Contains(s.cfg.Components, segs[0]) {
		return false
	}
	for _, seg := range segs[1:] {
		if arch, ok := strings.CutPrefix(seg, "binary-"); ok && !slices.Contains(s.archs, arch) {
			return false
		}
	}
	return true
}

// Pool serves a file the pool lookup lists, unless a storage source claims
// its package.
func (s *RegistrySource) Pool(ctx context.Context, _ ReadAccess, p Path) (Blob, error) {
	miss := fmt.Errorf("%w: %s", resolve.ErrNotFound, p.Rel)
	if p.Deb.Name != "" && s.cfg.Claimed(p.Deb.Name) {
		return Blob{}, miss
	}
	e, err := s.findPool(ctx, p.Rel)
	if err != nil {
		return Blob{}, err
	}
	if s.cfg.Claimed(e.Package) {
		return Blob{}, miss
	}
	rawURL := s.cfg.URL + escapePath(e.Path)
	fetch := func(ctx context.Context) (io.ReadCloser, int64, error) {
		body, size, err := s.get(ctx, rawURL, s.cfg.MaxArtifact)
		if errors.Is(err, resolve.ErrNotFound) {
			// The verified index lists it: a source fault, not a miss.
			return nil, 0, fmt.Errorf("upstream pool file missing although its index lists it: %v", err) //nolint:errorlint // a 404 here is a fault, not a miss
		}
		return body, size, err
	}
	onCommit := func(ctx context.Context, res relay.Result) error {
		if err := s.checkChanged(ctx, e, res.SHA256); err != nil {
			return err
		}
		if err := s.rec.PutProvenance(ctx, records.Provenance{
			Ecosystem: ecoName, Package: e.Package, Version: e.Version, File: e.Path, Source: s.cfg.Name, SourceType: "registry",
			UpstreamURL: rawURL, DeclaredDigest: "sha256:" + e.SHA256, SHA1: res.SHA1, SHA256: res.SHA256,
		}); err != nil {
			return fmt.Errorf("record provenance: %w", err)
		}
		return nil
	}
	body, size, hit, err := s.relay.Open(ctx, s.hashKey(e.SHA256), relay.Digest{SHA256: e.SHA256}, fetch, onCommit)
	if err != nil {
		return Blob{}, err
	}
	if hit {
		metrics.ObserveCacheHit(ecoName, s.cfg.Name)
	}
	if size < 0 {
		size = e.Size
	}
	return Blob{Body: body, Size: size, ETag: `"` + e.SHA256 + `"`, Immutable: true}, nil
}

// findPool looks rel up in the lookup of each configured suite's Release,
// in order, then in the lookups of the Releases they replaced: a client
// that listed the previous Release still downloads what it lists. A suite
// whose Release or lookup fails is skipped; its error is returned when no
// other lookup lists rel.
func (s *RegistrySource) findPool(ctx context.Context, rel string) (lookupEntry, error) {
	var firstErr error
	note := func(err error) {
		if err != nil && !errors.Is(err, resolve.ErrNotFound) && firstErr == nil {
			firstErr = err
		}
	}
	var prevs []*relState
	var prevSuites []string
	for _, suite := range s.cfg.Suites {
		st, err := s.current(ctx, suite)
		if err != nil {
			note(err)
			continue
		}
		e, found, err := s.find(ctx, suite, st, rel)
		if err == nil && found {
			return e, nil
		}
		note(err)
		if st.prev != nil {
			prevs, prevSuites = append(prevs, st.prev), append(prevSuites, suite)
		}
	}
	for i, st := range prevs {
		e, found, err := s.find(ctx, prevSuites[i], st, rel)
		if err == nil && found {
			return e, nil
		}
		note(err)
	}
	if firstErr != nil {
		return lookupEntry{}, firstErr
	}
	return lookupEntry{}, fmt.Errorf("%w: %s", resolve.ErrNotFound, rel)
}

// openListed opens the dists file fh of suite through the relay: by hash
// when the Release says Acquire-By-Hash, else by its path. hit reports a
// cache hit.
func (s *RegistrySource) openListed(ctx context.Context, suite string, st *relState, fh FileHash) (io.ReadCloser, int64, bool, error) {
	rel := fh.Path
	if st.doc.ByHash {
		rel = "by-hash/SHA256/" + fh.SHA256
		if dir := path.Dir(fh.Path); dir != "." {
			rel = dir + "/" + rel
		}
	}
	rawURL := s.cfg.URL + "dists/" + url.PathEscape(suite) + "/" + escapePath(rel)
	fetch := func(ctx context.Context) (io.ReadCloser, int64, error) {
		body, size, err := s.get(ctx, rawURL, max(fh.Size, 1))
		if errors.Is(err, resolve.ErrNotFound) {
			// The verified Release lists it: a source fault, not a miss.
			return nil, 0, fmt.Errorf("upstream dists file missing although its Release lists it: %v", err) //nolint:errorlint // a 404 here is a fault, not a miss
		}
		return body, size, err
	}
	body, size, hit, err := s.relay.Open(ctx, s.hashKey(fh.SHA256), relay.Digest{SHA256: fh.SHA256}, fetch, nil)
	if err != nil {
		return nil, 0, false, err
	}
	if hit {
		metrics.ObserveCacheHit(ecoName, s.cfg.Name)
	}
	if size < 0 {
		size = fh.Size
	}
	return body, size, hit, nil
}

// escapePath escapes every segment of p, so no byte of it leaves the path.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/")
}

// current returns suite's verified Release, refreshing it when it is older
// than the TTL and keeping the one it has when that fails.
func (s *RegistrySource) current(ctx context.Context, suite string) (*relState, error) {
	if !s.suites[suite] {
		return nil, fmt.Errorf("%w: suite %s", resolve.ErrNotFound, suite)
	}
	st := s.loaded(ctx, suite)
	if st != nil && s.now().Sub(st.fetched) < s.cfg.TTL {
		return st, nil
	}
	fresh, err := flight.Do(ctx, &s.relFlight, suite, func() (*relState, error) { return s.refresh(ctx, suite) })
	switch {
	case err != nil && st != nil:
		s.log.Warn("serving stale apt Release", "source", s.cfg.Name, "suite", suite, "error", err)
		return st, nil
	case err != nil:
		return nil, err
	}
	return fresh, nil
}

// loaded returns suite's Release from memory, or else from the cache,
// verified again; nil when there is none.
func (s *RegistrySource) loaded(ctx context.Context, suite string) *relState {
	s.mu.Lock()
	st := s.states[suite]
	s.mu.Unlock()
	if st != nil {
		return st
	}
	rc, written, err := s.cache.Get(ctx, s.releaseKey(suite))
	if err != nil {
		return nil
	}
	defer rc.Close()
	var obj releaseObj
	if err := json.NewDecoder(io.LimitReader(rc, maxReleaseObject)).Decode(&obj); err != nil {
		s.log.Warn("unreadable cached apt Release; fetching it again", "source", s.cfg.Name, "suite", suite, "error", err)
		return nil
	}
	if st, err = s.newState(obj, written); err != nil {
		s.log.Warn("cached apt Release no longer verifies; fetching it again", "source", s.cfg.Name, "suite", suite, "error", err)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.states[suite]; cur != nil {
		return cur
	}
	s.states[suite] = st
	return st
}

// refresh fetches, verifies and checks suite's Release, then makes it the
// current one. It runs on its own context: a client leaving does not cancel
// it while another waits.
func (s *RegistrySource) refresh(ctx context.Context, suite string) (*relState, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseFetchTimeout)
	defer cancel()
	s.mu.Lock()
	old := s.states[suite]
	s.mu.Unlock()
	st, err := s.fetchRelease(ctx, suite, old)
	s.noteFetch(err, old != nil)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.states[suite] = st
	s.mu.Unlock()
	return st, nil
}

// fetchRelease fetches suite's InRelease, or Release and Release.gpg when
// there is none, and accepts it when it verifies, its Valid-Until has not
// passed, its Date is at most maxFutureDate ahead, its Suite or Codename is
// suite, and its Date is older neither than the high-water mark nor than
// old's.
func (s *RegistrySource) fetchRelease(ctx context.Context, suite string, old *relState) (*relState, error) {
	base := s.cfg.URL + "dists/" + url.PathEscape(suite) + "/"
	var obj releaseObj
	in, err := s.fetchAll(ctx, base+"InRelease", MaxRelease)
	switch {
	case err == nil:
		obj.InRelease = in
	case !errors.Is(err, resolve.ErrNotFound):
		return nil, err
	default:
		if obj.Release, err = s.fetchAll(ctx, base+"Release", MaxRelease); err != nil {
			return nil, err
		}
		if obj.ReleaseGPG, err = s.fetchAll(ctx, base+"Release.gpg", maxDetachedSig); err != nil {
			return nil, fmt.Errorf("upstream Release.gpg of %s: %v", suite, err) //nolint:errorlint // a missing signature is a fault, not a miss
		}
	}
	st, err := s.newState(obj, s.now())
	if err != nil {
		return nil, fmt.Errorf("upstream Release of %s rejected: %w", suite, err)
	}
	if vu := st.doc.ValidUntil; !vu.IsZero() && s.now().After(vu) {
		return nil, fmt.Errorf("upstream Release of %s rejected: Valid-Until %s has passed", suite, vu.Format(time.RFC3339))
	}
	if st.doc.Date.After(s.now().Add(maxFutureDate)) {
		return nil, fmt.Errorf("upstream Release of %s rejected: Date %s is more than %s ahead", suite,
			st.doc.Date.Format(time.RFC3339), maxFutureDate)
	}
	rs, _ := st.doc.Fields.Get("Suite")
	rc, _ := st.doc.Fields.Get("Codename")
	if rs != suite && rc != suite {
		return nil, fmt.Errorf("upstream Release of %s rejected: it is for Suite %q, Codename %q", suite, truncate(rs, 80), truncate(rc, 80))
	}
	if err := s.raiseMark(ctx, suite, st); err != nil {
		return nil, err
	}
	if old == nil {
		s.writeRelease(ctx, suite, st)
		return st, nil
	}
	if st.doc.Date.Before(old.doc.Date) {
		return nil, fmt.Errorf("upstream Release of %s rejected: Date %s is older than the cached copy's %s", suite,
			st.doc.Date.Format(time.RFC3339), old.doc.Date.Format(time.RFC3339))
	}
	if st.sum == old.sum {
		same := *old
		same.fetched = st.fetched
		return &same, nil
	}
	obj.Previous, obj.PreviousSHA256, obj.PreviousByHash = old.doc.SHA256, old.sum, old.doc.ByHash
	if st, err = s.newState(obj, st.fetched); err != nil {
		return nil, err
	}
	s.writeRelease(ctx, suite, st)
	return st, nil
}

// releaseMark is the newest Release Date a source accepted for a suite,
// kept in the state store so that losing the cache never lets an older
// Release back in.
type releaseMark struct {
	Date   time.Time `json:"date"`
	SHA256 string    `json:"sha256"` // of the verified upstream bytes
}

func (s *RegistrySource) markKey(suite string) string {
	return "apt/" + s.cfg.Name + "/release-mark/" + storage.EscapeSegment(suite)
}

// raiseMark rejects st when its Date is older than suite's high-water mark,
// and raises the mark to st's Date when it is newer, with a compare-and-swap
// so that concurrent writers never lower it. Failing to read or write the
// mark rejects st.
func (s *RegistrySource) raiseMark(ctx context.Context, suite string, st *relState) error {
	key := s.markKey(suite)
	for range updateRetries {
		var m releaseMark
		etag := ""
		rc, info, err := s.state.Get(ctx, key)
		switch {
		case err == nil:
			err = json.NewDecoder(io.LimitReader(rc, maxSidecarBytes)).Decode(&m)
			rc.Close()
			if err != nil {
				return fmt.Errorf("apt Release mark %s: %w", key, err)
			}
			etag = info.ETag
		case !errors.Is(err, storage.ErrNotFound):
			return fmt.Errorf("read apt Release mark: %w", err)
		}
		if st.doc.Date.Before(m.Date) {
			return fmt.Errorf("upstream Release of %s rejected: Date %s is older than the newest accepted, %s", suite,
				st.doc.Date.Format(time.RFC3339), m.Date.Format(time.RFC3339))
		}
		if etag != "" && !st.doc.Date.After(m.Date) {
			return nil
		}
		b, err := json.Marshal(releaseMark{Date: st.doc.Date, SHA256: st.sum})
		if err != nil {
			return err
		}
		_, err = s.state.PutIfMatch(ctx, key, bytes.NewReader(b), etag)
		if !errors.Is(err, storage.ErrPrecondition) {
			if err != nil {
				return fmt.Errorf("write apt Release mark: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("write apt Release mark: %d conflicting writes in a row", updateRetries)
}

// writeRelease caches st. A failure is logged: st is verified and serves
// from memory.
func (s *RegistrySource) writeRelease(ctx context.Context, suite string, st *relState) {
	b, err := json.Marshal(st.obj)
	if err == nil {
		err = s.cache.Put(ctx, s.releaseKey(suite), bytes.NewReader(b))
	}
	if err != nil {
		s.log.Warn("cache apt Release", "source", s.cfg.Name, "suite", suite, "error", err)
	}
}

// fetchAll reads rawURL whole, at most maxBytes of it.
func (s *RegistrySource) fetchAll(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	body, _, err := s.get(ctx, rawURL, maxBytes)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}

// get waits for the upstream limit, then opens rawURL.
func (s *RegistrySource) get(ctx context.Context, rawURL string, maxBytes int64) (io.ReadCloser, int64, error) {
	if err := s.wait(ctx); err != nil {
		return nil, 0, err
	}
	start := time.Now()
	body, size, err := s.c.Open(ctx, rawURL, maxBytes)
	metrics.ObserveUpstream(s.cfg.Name, time.Since(start))
	return body, size, err
}

// checkChanged compares sha256Hex with the first digest this source
// recorded for e's pool path; a difference is served, logged and listed by
// Changed.
func (s *RegistrySource) checkChanged(ctx context.Context, e lookupEntry, sha256Hex string) error {
	recs, err := s.rec.FileProvenance(ctx, ecoName, e.Package, e.Version, e.Path)
	if err != nil {
		return fmt.Errorf("read provenance: %w", err)
	}
	var first *records.Provenance
	for i, p := range recs {
		if p.Source == s.cfg.Name && (first == nil || p.Created.Before(first.Created)) {
			first = &recs[i]
		}
	}
	if first == nil || first.SHA256 == sha256Hex {
		return nil
	}
	s.log.Warn("apt pool file changed upstream; serving the new bytes", "source", s.cfg.Name, "path", e.Path,
		"first_sha256", first.SHA256, "seen_sha256", sha256Hex)
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if s.changed == nil {
		s.changed = map[string]ChangedFile{}
	}
	s.changed[e.Path] = ChangedFile{Source: s.cfg.Name, Package: e.Package, Path: e.Path, First: first.SHA256, Now: sha256Hex}
	return nil
}

// Changed returns the pool files seen changing since start, by path.
func (s *RegistrySource) Changed() []ChangedFile {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	out := slices.Collect(maps.Values(s.changed))
	slices.SortFunc(out, func(a, b ChangedFile) int { return cmp.Compare(a.Path, b.Path) })
	return out
}

// noteFetch records the outcome of a Release refresh for Health. Refreshes
// run detached from the request, so a client leaving never shows up here.
func (s *RegistrySource) noteFetch(err error, haveCache bool) {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	switch {
	case err == nil && s.fetchErr != nil:
		s.log.Info("apt upstream recovered", "source", s.cfg.Name)
	case err != nil && s.fetchErr == nil:
		s.log.Warn("apt upstream unhealthy", "source", s.cfg.Name, "stale", haveCache, "error", err)
	case err != nil:
		s.log.Debug("apt upstream still unhealthy", "source", s.cfg.Name, "stale", haveCache, "error", err)
	}
	s.fetchErr, s.stale = err, err != nil && haveCache
}

// Health reports the last Release refresh.
func (s *RegistrySource) Health(context.Context) []metrics.Health {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	h := metrics.Health{Name: s.cfg.Name, Ecosystem: ecoName, OK: s.fetchErr == nil, Detail: "no upstream fetch has failed"}
	if s.fetchErr != nil {
		h.Detail = "upstream error"
		if s.stale {
			h.Detail = "serving stale"
		}
	}
	return []metrics.Health{h}
}
