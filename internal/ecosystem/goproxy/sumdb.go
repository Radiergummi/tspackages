package goproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/radiergummi/tspackages/internal/metrics"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

const (
	// SumDBName is the checksum database the verifier and the sumdb proxy
	// speak for.
	SumDBName = "sum.golang.org"
	// sumDBKey is sum.golang.org's verifier key as the go command knows it
	// (modfetch/key.go:knownGOSUMDB).
	sumDBKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ks+jGaZp7QhgiKfm"
	sumDBURL = "https://sum.golang.org"
	// maxLookup and maxTile cap a /lookup/ and a /tile/ body.
	maxLookup = 64 << 10
	maxTile   = 4 << 20
	// swapEvery bounds the life, and so the memory, of one sumdb.Client.
	swapEvery = time.Hour
	// remoteTimeout bounds one database request or state access; ClientOps
	// carries no context.
	remoteTimeout = 30 * time.Second

	// latestKey holds the latest verified signed tree head, in the state store.
	latestKey = "go-sumdb/" + SumDBName + "/latest"
)

// missingMarker is cached under go-sumdb-missing/ for a lookup the database
// answered with 404 or 410.
var missingMarker = []byte("\x00tspackages:sumdb-missing")

// VerifierOptions configures a Verifier.
type VerifierOptions struct {
	Key, URL string           // "" = sumDBKey, sumDBURL; only test hooks set them
	Client   *upstream.Client // must allow the URL's host
	State    storage.Driver
	Cache    *storage.Cache
	TTL      time.Duration // how long a missing version stays a miss
	Log      *slog.Logger  // nil = slog.Default()
}

// Lookup is the checksum database's answer for one module version.
type Lookup struct {
	ZipHash, ModHash string // "h1:…" from the "path v" and "path v/go.mod" lines
	Record           []byte // raw signed record bytes, as ReadRemote or ReadCache returned them
}

// Verifier checks module versions against sum.golang.org with an x/mod
// sumdb.Client. The client memoises every result, errors included, for its
// whole life, so it sits behind a swap: after an error (unless a security
// error was recorded) and once it is older than swapEvery, the next caller
// replaces it; lookups in flight finish on the old one. A security error is
// sticky until restart and fails every later lookup.
type Verifier struct {
	key, url string
	c        *upstream.Client
	state    storage.Driver
	cache    *storage.Cache
	ttl      time.Duration
	log      *slog.Logger
	vkeys    note.Verifiers // nil if key does not parse; the client then fails to init

	// Replaced in tests.
	now           func() time.Time
	swapEvery     time.Duration
	remoteTimeout time.Duration

	cur    atomic.Pointer[instance]
	swapMu sync.Mutex

	mu       sync.Mutex
	security string    // the first SecurityError message
	treeSize int64     // largest tree a successful lookup was verified in
	verified time.Time // when that lookup finished
	lastErr  error     // the last lookup's failure, nil after a success or miss
}

// instance is one sumdb.Client with the ops it alone uses.
type instance struct {
	client *sumdb.Client
	ops    *verifierOps
	born   time.Time
}

// NewVerifier returns a verifier for sum.golang.org, or the database the
// options name.
func NewVerifier(o VerifierOptions) *Verifier {
	if o.Key == "" {
		o.Key = sumDBKey
	}
	if o.URL == "" {
		o.URL = sumDBURL
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	v := &Verifier{
		key: o.Key, url: strings.TrimRight(o.URL, "/"), c: o.Client, state: o.State, cache: o.Cache, ttl: o.TTL, log: o.Log,
		now: time.Now, swapEvery: swapEvery, remoteTimeout: remoteTimeout,
	}
	if vk, err := note.NewVerifier(o.Key); err == nil {
		v.vkeys = note.VerifierList(vk)
	}
	return v
}

func (v *Verifier) newInstance() *instance {
	ops := &verifierOps{v: v, records: map[string][]byte{}, missing: map[string]bool{}}
	return &instance{client: sumdb.NewClient(ops), ops: ops, born: v.now()}
}

// instance returns the current client, replacing it when it is too old.
func (v *Verifier) instance() *instance {
	in := v.cur.Load()
	if in != nil && v.now().Sub(in.born) < v.swapEvery {
		return in
	}
	return v.retire(in)
}

// retire replaces old with a fresh client unless another caller already did,
// and returns the current one.
func (v *Verifier) retire(old *instance) *instance {
	v.swapMu.Lock()
	defer v.swapMu.Unlock()
	if in := v.cur.Load(); in != old {
		return in
	}
	in := v.newInstance()
	v.cur.Store(in)
	return in
}

// SecurityError returns the recorded security error, "" when none.
func (v *Verifier) SecurityError() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.security
}

func (v *Verifier) securityErr() error {
	if msg := v.SecurityError(); msg != "" {
		first, _, _ := strings.Cut(strings.TrimSpace(msg), "\n")
		return fmt.Errorf("go checksum database: %s (recorded until restart; see the error log)", first)
	}
	return nil
}

// Lookup returns the go.sum hashes of path at version and the signed record
// they came from. A version the database does not know is
// resolve.ErrNotFound, remembered for the TTL.
func (v *Verifier) Lookup(ctx context.Context, path, version string) (Lookup, error) {
	if err := v.securityErr(); err != nil {
		return Lookup{}, err
	}
	epath, err := module.EscapePath(path)
	if err != nil {
		return Lookup{}, fmt.Errorf("%w: %v", resolve.ErrNotFound, err) //nolint:errorlint // an unescapable path is a miss
	}
	evers, err := module.EscapeVersion(version)
	if err != nil {
		return Lookup{}, fmt.Errorf("%w: %v", resolve.ErrNotFound, err) //nolint:errorlint // an unescapable version is a miss
	}
	file := "/lookup/" + epath + "@" + evers
	missKey, cacheable := v.missingKey(file)
	if cacheable && v.knownMissing(ctx, missKey) {
		return Lookup{}, fmt.Errorf("%w: %s %s is not in the checksum database", resolve.ErrNotFound, path, version)
	}

	type result struct {
		l   Lookup
		err error
	}
	done := make(chan result, 1)
	// The client takes no context: the lookup runs on and its bookkeeping
	// completes even when the caller gives up.
	go func() {
		l, err := v.lookup(context.WithoutCancel(ctx), path, version, file, missKey, cacheable)
		done <- result{l, err}
	}()
	select {
	case r := <-done:
		return r.l, r.err
	case <-ctx.Done():
		return Lookup{}, ctx.Err()
	}
}

func (v *Verifier) lookup(ctx context.Context, path, version, file, missKey string, cacheable bool) (Lookup, error) {
	in := v.instance()
	zip, err := v.line(in, path, version)
	var mod string
	if err == nil {
		mod, err = v.line(in, path, version+"/go.mod")
	}
	if err != nil {
		if serr := v.securityErr(); serr != nil {
			return Lookup{}, serr
		}
		v.retire(in)
		if in.ops.isMissing(file) {
			if cacheable {
				ctx, cancel := context.WithTimeout(ctx, v.remoteTimeout)
				defer cancel()
				if perr := v.cache.Put(ctx, missKey, bytes.NewReader(missingMarker)); perr != nil {
					v.log.Warn("caching a checksum database miss failed", "module", path, "version", version, "error", perr)
				}
			}
			v.noteResult(nil, nil)
			return Lookup{}, fmt.Errorf("%w: %s %s is not in the checksum database", resolve.ErrNotFound, path, version)
		}
		if in.ops.timedOut.Load() {
			err = fmt.Errorf("%w: %v", context.DeadlineExceeded, err) //nolint:errorlint // the client flattened the cause; mark it a timeout
		}
		v.noteResult(nil, err)
		return Lookup{}, err
	}
	rec := in.ops.record(file)
	if rec == nil {
		// Unreachable: the client read the record through ReadCache or
		// ReadRemote, which captured it.
		v.retire(in)
		return Lookup{}, fmt.Errorf("checksum database record for %s %s was not captured", path, version)
	}
	v.noteResult(rec, nil)
	return Lookup{ZipHash: zip, ModHash: mod, Record: rec}, nil
}

// line returns the hash of the go.sum line for path and vers.
func (v *Verifier) line(in *instance, path, vers string) (string, error) {
	lines, err := in.client.Lookup(path, vers)
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if f := strings.Fields(l); len(f) == 3 && strings.HasPrefix(f[2], "h1:") {
			return f[2], nil
		}
	}
	return "", fmt.Errorf("checksum database has no h1 line for %s %s", path, vers)
}

func (v *Verifier) missingKey(file string) (string, bool) {
	s, ok := seg(SumDBName + file)
	return "go-sumdb-missing/" + s, ok
}

func (v *Verifier) knownMissing(ctx context.Context, key string) bool {
	rc, written, err := v.cache.Get(ctx, key)
	if err != nil {
		return false
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, int64(len(missingMarker))+1))
	return err == nil && bytes.Equal(b, missingMarker) && v.now().Sub(written) < v.ttl
}

// noteResult records a lookup's outcome for Health: rec is the verified
// record, err a failure; both nil for a miss.
func (v *Verifier) noteResult(rec []byte, err error) {
	var size int64 = -1
	if rec != nil {
		size = v.recordTreeSize(rec)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case err != nil && v.lastErr == nil:
		v.log.Warn("go checksum database lookups failing", "error", err)
	case err == nil && v.lastErr != nil:
		v.log.Info("go checksum database lookups recovered")
	}
	v.lastErr = err
	if rec != nil {
		v.verified = v.now()
		v.treeSize = max(v.treeSize, size)
	}
}

// recordTreeSize returns the size of the signed tree in a verified record.
func (v *Verifier) recordTreeSize(rec []byte) int64 {
	_, _, msg, err := tlog.ParseRecord(rec)
	if err != nil {
		return -1
	}
	n, err := note.Open(msg, v.vkeys)
	if err != nil {
		return -1
	}
	t, err := tlog.ParseTree([]byte(n.Text))
	if err != nil {
		return -1
	}
	return t.N
}

// Health reports the security error, the last failure, or the last verified
// tree.
func (v *Verifier) Health(context.Context) []metrics.Health {
	v.mu.Lock()
	defer v.mu.Unlock()
	h := metrics.Health{Name: SumDBName, Ecosystem: ecoName, OK: true, Detail: "no lookup yet"}
	if !v.verified.IsZero() {
		h.Detail = fmt.Sprintf("verified tree %d at %s", v.treeSize, v.verified.UTC().Format(time.RFC3339))
	}
	switch {
	case v.security != "":
		h.OK, h.Detail = false, v.security
	case v.lastErr != nil:
		h.OK, h.Detail = false, "lookup failed; "+h.Detail
	}
	return []metrics.Health{h}
}

// Tile returns a tile of the database for a client, from the cache under
// go-sumdb-proxy/ (never the verifier's keys, which hold only tiles the
// client verified) or the database. tilePath is "tile/…" as
// tlog.ParseTilePath reads it; a hash tile must hold W hashes.
func (v *Verifier) Tile(ctx context.Context, tilePath string) ([]byte, error) {
	t, err := tlog.ParseTilePath(tilePath)
	if err != nil {
		return nil, err
	}
	s, cacheable := seg(tilePath)
	key := "go-sumdb-proxy/" + s
	if cacheable {
		if rc, _, err := v.cache.Get(ctx, key); err == nil {
			b, err := io.ReadAll(io.LimitReader(rc, maxTile+1))
			rc.Close()
			if err == nil && len(b) <= maxTile {
				return b, nil
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, v.remoteTimeout)
	defer cancel()
	b, err := v.fetch(ctx, "/"+tilePath, maxTile)
	if err != nil {
		return nil, err
	}
	if t.L >= 0 && len(b) != t.W*tlog.HashSize {
		return nil, fmt.Errorf("checksum database tile %s has %d bytes, want %d", tilePath, len(b), t.W*tlog.HashSize)
	}
	if cacheable {
		if perr := v.cache.Put(ctx, key, bytes.NewReader(b)); perr != nil {
			v.log.Warn("caching a checksum database tile failed", "tile", tilePath, "error", perr)
		}
	}
	return b, nil
}

// statusError is a non-2xx answer of the database. Unlike
// upstream.StatusError, a 404 is not resolve.ErrNotFound: only a lookup the
// verifier recorded as missing is a miss.
type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return e.msg }

// fetch GETs the database path.
func (v *Verifier) fetch(ctx context.Context, path string, limit int64) ([]byte, error) {
	rc, _, err := v.c.Open(ctx, v.url+path, limit)
	if err != nil {
		if se, ok := errors.AsType[*upstream.StatusError](err); ok {
			return nil, &statusError{code: se.Code, msg: se.Error()}
		}
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// verifierOps is the sumdb.ClientOps of one instance. It captures the raw
// lookup records the client reads and the lookups the database answered
// with 404 or 410, keyed by "/lookup/<path>@<version>".
type verifierOps struct {
	v *Verifier

	mu       sync.Mutex
	records  map[string][]byte
	missing  map[string]bool
	timedOut atomic.Bool
}

var _ sumdb.ClientOps = (*verifierOps)(nil)

func (o *verifierOps) record(file string) []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.records[file]
}

func (o *verifierOps) isMissing(file string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.missing[file]
}

func (o *verifierOps) capture(file string, b []byte) {
	if strings.HasPrefix(file, "/lookup/") {
		o.mu.Lock()
		o.records[file] = b
		o.mu.Unlock()
	}
}

func (o *verifierOps) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), o.v.remoteTimeout)
}

func (o *verifierOps) ReadRemote(path string) ([]byte, error) {
	limit := int64(maxTile)
	if strings.HasPrefix(path, "/lookup/") {
		limit = maxLookup
	}
	ctx, cancel := o.ctx()
	defer cancel()
	b, err := o.v.fetch(ctx, path, limit)
	if err != nil {
		if ctx.Err() != nil {
			o.timedOut.Store(true)
		}
		se, ok := errors.AsType[*statusError](err)
		if ok && strings.HasPrefix(path, "/lookup/") && (se.code == http.StatusNotFound || se.code == http.StatusGone) {
			o.mu.Lock()
			o.missing[path] = true
			o.mu.Unlock()
		}
		return nil, err
	}
	o.capture(path, b)
	return b, nil
}

func (o *verifierOps) ReadConfig(file string) ([]byte, error) {
	switch file {
	case "key":
		return []byte(o.v.key), nil
	case SumDBName + "/latest":
		b, _, err := o.readLatest()
		return b, err
	}
	return nil, fmt.Errorf("unknown checksum database config file %q", file)
}

// readLatest returns the stored latest tree head and its ETag; nil and ""
// when there is none.
func (o *verifierOps) readLatest() ([]byte, string, error) {
	ctx, cancel := o.ctx()
	defer cancel()
	rc, info, err := o.v.state.Get(ctx, latestKey)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxLookup+1))
	if err != nil {
		return nil, "", err
	}
	if len(b) > maxLookup {
		return nil, "", fmt.Errorf("%s is larger than %d bytes", latestKey, maxLookup)
	}
	return b, info.ETag, nil
}

// WriteConfig replaces the stored latest tree head, a compare-and-swap on
// its bytes and ETag. A conflict is the bare sumdb.ErrWriteConflict, which
// the client compares with !=.
func (o *verifierOps) WriteConfig(file string, old, new []byte) error {
	if file != SumDBName+"/latest" {
		return fmt.Errorf("unknown checksum database config file %q", file)
	}
	cur, etag, err := o.readLatest()
	if err != nil {
		return err
	}
	if !bytes.Equal(cur, old) {
		return sumdb.ErrWriteConflict
	}
	ctx, cancel := o.ctx()
	defer cancel()
	if _, err := o.v.state.PutIfMatch(ctx, latestKey, bytes.NewReader(new), etag); err != nil {
		if errors.Is(err, storage.ErrPrecondition) {
			return sumdb.ErrWriteConflict
		}
		return err
	}
	return nil
}

func (o *verifierOps) cacheKey(file string) (string, bool) {
	s, ok := seg(file)
	return "go-sumdb/" + s, ok
}

func (o *verifierOps) ReadCache(file string) ([]byte, error) {
	key, ok := o.cacheKey(file)
	if !ok {
		return nil, storage.ErrNotFound
	}
	ctx, cancel := o.ctx()
	defer cancel()
	rc, _, err := o.v.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxTile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxTile {
		return nil, fmt.Errorf("cached %s is too large", file)
	}
	o.capture(strings.TrimPrefix(file, SumDBName), b)
	return b, nil
}

func (o *verifierOps) WriteCache(file string, data []byte) {
	key, ok := o.cacheKey(file)
	if !ok {
		return
	}
	ctx, cancel := o.ctx()
	defer cancel()
	if err := o.v.cache.Put(ctx, key, bytes.NewReader(data)); err != nil {
		o.v.log.Debug("caching checksum database data failed", "file", file, "error", err)
	}
}

func (o *verifierOps) Log(msg string) { o.v.log.Debug("go checksum database client", "msg", msg) }

// SecurityError records msg for good: the process keeps running, so a
// recorded fork cannot make every start crash, but no lookup succeeds until
// restart.
func (o *verifierOps) SecurityError(msg string) {
	o.v.log.Error("go checksum database misbehaved", "error", msg)
	o.v.mu.Lock()
	defer o.v.mu.Unlock()
	if o.v.security == "" {
		o.v.security = msg
	}
}
