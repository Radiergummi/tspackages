// Package relay fetches an upstream artifact once, streams it to every
// client asking for it while it downloads, and caches it only after its
// digest matched.
package relay

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/workdir"
)

// Digest is the expected digest of an artifact, as hex; empty fields are not
// checked.
type Digest struct{ SHA1, SHA256 string }

// Result is what a completed download observed.
type Result struct {
	SHA1, SHA256 string
	Size         int64
}

// Fetch opens the upstream artifact, returning its body and declared size
// (-1 if unknown).
type Fetch func(ctx context.Context) (io.ReadCloser, int64, error)

// ErrDigestMismatch is returned by a reader whose artifact did not match
// the expected digest.
var ErrDigestMismatch = errors.New("relay: digest mismatch")

// Relay shares one fetch per key among concurrent readers.
type Relay struct {
	cache  *storage.Cache
	tmpDir string
	log    *slog.Logger

	mu       sync.Mutex
	inflight map[string]*download
}

// New returns a Relay keeping downloads in progress in tmpDir, which it
// creates (mode 0700) and empties. log nil means slog.Default().
func New(cache *storage.Cache, tmpDir string, log *slog.Logger) (*Relay, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := workdir.EnsurePrivateDir(tmpDir); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(tmpDir, e.Name())); err != nil {
			return nil, fmt.Errorf("relay: remove leftover %s: %w", e.Name(), err)
		}
	}
	return &Relay{cache: cache, tmpDir: tmpDir, log: log, inflight: map[string]*download{}}, nil
}

// Open returns the cached object under key, or starts (or joins) the one
// fetch for key and returns a reader that streams it as it arrives. A failure
// to open the upstream is returned here; anything later comes from Read.
//
// The reader's final Read returns io.EOF only after the digest matched,
// onCommit (if any) succeeded and the object was written to the cache. On a
// mismatch it returns ErrDigestMismatch and nothing is cached. A cache hit is
// re-checked against want while it streams: a mismatch fails the read and
// drops the entry. The returned size is -1 when unknown.
func (r *Relay) Open(ctx context.Context, key string, want Digest, fetch Fetch, onCommit func(context.Context, Result) error) (io.ReadCloser, int64, error) {
	if rc, size, err := r.cache.Open(ctx, key); err == nil {
		return r.verifying(rc, key, want), size, nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, 0, err
	}

	r.mu.Lock()
	dl, joined := r.inflight[key]
	if joined {
		dl.readers++
	} else {
		dl = &download{key: key, readers: 1, ready: make(chan struct{})}
		dl.cond = sync.NewCond(&dl.mu)
		r.inflight[key] = dl
	}
	r.mu.Unlock()
	if !joined {
		go r.run(context.WithoutCancel(ctx), dl, want, fetch, onCommit)
	}
	select {
	case <-dl.ready:
	case <-ctx.Done():
		r.leave(dl)
		return nil, 0, ctx.Err()
	}
	if dl.openErr != nil {
		r.leave(dl)
		return nil, 0, dl.openErr
	}
	return &reader{r: r, dl: dl}, dl.size, nil
}

type download struct {
	key   string
	ready chan struct{} // closed once the upstream answered (openErr or file set)

	openErr error
	file    *os.File // temp file; read with ReadAt, closed when the last reader leaves
	size    int64
	cancel  context.CancelFunc

	mu      sync.Mutex
	cond    *sync.Cond
	written int64
	done    bool
	err     error // final outcome once done; nil = verified and committed
	readers int   // guarded by Relay.mu
}

func (r *Relay) run(ctx context.Context, dl *download, want Digest, fetch Fetch, onCommit func(context.Context, Result) error) {
	ctx, cancel := context.WithCancel(ctx)
	dl.cancel = cancel
	body, size, err := fetch(ctx)
	if err == nil {
		dl.file, err = os.CreateTemp(r.tmpDir, "dl-*")
		if err != nil {
			body.Close()
		}
	}
	dl.size = size
	if err != nil {
		cancel()
		dl.openErr = err
		r.mu.Lock()
		delete(r.inflight, dl.key)
		r.mu.Unlock()
		close(dl.ready)
		return
	}
	close(dl.ready)

	path := dl.file.Name()
	h1, h256 := sha1.New(), sha256.New()
	res, err := dl.copy(body, h1, h256)
	body.Close()
	if err == nil {
		err = check(want, res)
	}
	if err == nil && onCommit != nil {
		err = onCommit(ctx, res)
	}
	if err == nil {
		err = r.commit(ctx, dl.key, path)
	}
	cancel()
	// Commit or not, the key is free for a new fetch from here on.
	r.mu.Lock()
	delete(r.inflight, dl.key)
	r.mu.Unlock()
	dl.mu.Lock()
	dl.done, dl.err = true, err
	dl.cond.Broadcast()
	dl.mu.Unlock()
	// The path is no longer needed: readers hold the open file.
	os.Remove(path)
	if err != nil && !errors.Is(err, context.Canceled) {
		r.log.Warn("relay: download failed", "key", dl.key, "error", err)
	}
}

// copy writes body to the temp file and the hashes, waking readers after
// every chunk.
func (dl *download) copy(body io.Reader, h1, h256 hash.Hash) (Result, error) {
	buf := make([]byte, 256<<10)
	var total int64
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, err := dl.file.WriteAt(buf[:n], total); err != nil {
				return Result{}, err
			}
			h1.Write(buf[:n])
			h256.Write(buf[:n])
			total += int64(n)
			dl.mu.Lock()
			dl.written = total
			dl.cond.Broadcast()
			dl.mu.Unlock()
		}
		if errors.Is(rerr, io.EOF) {
			return Result{SHA1: hex.EncodeToString(h1.Sum(nil)), SHA256: hex.EncodeToString(h256.Sum(nil)), Size: total}, nil
		}
		if rerr != nil {
			return Result{}, rerr
		}
	}
}

func check(want Digest, got Result) error {
	if want.SHA256 != "" && !strings.EqualFold(want.SHA256, got.SHA256) {
		return fmt.Errorf("%w: sha256 want %s, got %s", ErrDigestMismatch, want.SHA256, got.SHA256)
	}
	if want.SHA1 != "" && !strings.EqualFold(want.SHA1, got.SHA1) {
		return fmt.Errorf("%w: sha1 want %s, got %s", ErrDigestMismatch, want.SHA1, got.SHA1)
	}
	return nil
}

// commit copies the verified temp file into the cache through its own file
// handle, so readers' offsets are untouched.
func (r *Relay) commit(ctx context.Context, key, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := r.cache.Put(ctx, key, f); err != nil {
		return fmt.Errorf("relay: cache %s: %w", key, err)
	}
	return nil
}

// leave drops one reader; the last one cancels an unfinished fetch and closes
// the temp file.
func (r *Relay) leave(dl *download) {
	r.mu.Lock()
	dl.readers--
	last := dl.readers == 0
	r.mu.Unlock()
	if !last {
		return
	}
	<-dl.ready
	if dl.openErr != nil {
		return
	}
	dl.mu.Lock()
	done := dl.done
	dl.mu.Unlock()
	if !done {
		dl.cancel()
		dl.mu.Lock()
		for !dl.done {
			dl.cond.Wait()
		}
		dl.mu.Unlock()
	}
	dl.file.Close()
}

// reader follows a download's temp file as it grows.
type reader struct {
	r      *Relay
	dl     *download
	off    int64
	closed bool
}

func (rd *reader) Read(p []byte) (int, error) {
	dl := rd.dl
	dl.mu.Lock()
	for rd.off >= dl.written && !dl.done {
		dl.cond.Wait()
	}
	avail, done, err := dl.written-rd.off, dl.done, dl.err
	dl.mu.Unlock()
	if avail > 0 {
		n, rerr := dl.file.ReadAt(p[:min(int64(len(p)), avail)], rd.off)
		rd.off += int64(n)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return n, rerr
		}
		return n, nil
	}
	if done && err != nil {
		return 0, err
	}
	return 0, io.EOF
}

func (rd *reader) Close() error {
	if rd.closed {
		return nil
	}
	rd.closed = true
	rd.r.leave(rd.dl)
	return nil
}

// verifying wraps a cache hit: read in order from the start to the end, its
// bytes must match want, else the last Read fails and the entry is dropped.
// A Seek away from the current position turns the check off (ranged
// requests read only part of the object).
func (r *Relay) verifying(rc io.ReadCloser, key string, want Digest) io.ReadCloser {
	if want == (Digest{}) {
		return rc
	}
	v := &verifier{rc: rc, relay: r, key: key, want: want, h1: sha1.New(), h256: sha256.New(), on: true}
	if _, ok := rc.(io.Seeker); ok {
		return &seekingVerifier{v}
	}
	return v
}

type verifier struct {
	rc       io.ReadCloser
	relay    *Relay
	key      string
	want     Digest
	h1, h256 hash.Hash
	n        int64
	on       bool
}

func (v *verifier) Read(p []byte) (int, error) {
	n, err := v.rc.Read(p)
	if v.on {
		v.h1.Write(p[:n])
		v.h256.Write(p[:n])
		v.n += int64(n)
	}
	if errors.Is(err, io.EOF) && v.on {
		got := Result{SHA1: hex.EncodeToString(v.h1.Sum(nil)), SHA256: hex.EncodeToString(v.h256.Sum(nil)), Size: v.n}
		if cerr := check(v.want, got); cerr != nil {
			if derr := v.relay.cache.Delete(context.Background(), v.key); derr != nil {
				v.relay.log.Warn("relay: dropping a corrupt cache entry failed", "key", v.key, "error", derr)
			}
			return n, cerr
		}
	}
	return n, err
}

func (v *verifier) Close() error { return v.rc.Close() }

type seekingVerifier struct{ *verifier }

func (s *seekingVerifier) Seek(offset int64, whence int) (int64, error) {
	abs, err := s.rc.(io.Seeker).Seek(offset, whence)
	if err == nil && abs != s.n {
		s.on = false
	}
	if err == nil && abs == 0 && s.n == 0 {
		s.on = true // http.ServeContent seeks to the end and back before reading
	}
	return abs, err
}
