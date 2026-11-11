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
	"sync/atomic"
	"time"

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

// ErrStalled is returned by readers of a download whose upstream sent nothing
// for the idle timeout.
var ErrStalled = errors.New("relay: upstream stalled")

// defaultIdle is how long an upstream may send nothing before its download
// fails. There is no total timeout: multi-GB artifacts take as long as they
// take while bytes keep arriving.
const defaultIdle = 2 * time.Minute

// ErrDigestMismatch is returned by a reader whose artifact did not match
// the expected digest.
var ErrDigestMismatch = errors.New("relay: digest mismatch")

// Relay shares one fetch per key among concurrent readers.
type Relay struct {
	cache  *storage.Cache
	tmpDir string
	log    *slog.Logger
	idle   time.Duration

	mu       sync.Mutex
	inflight map[string]*download
	finished uint64 // downloads that left inflight after starting to stream

	runs sync.WaitGroup // fetches still running, cache writes included

	afterMiss func() // test hook: runs after Open's first cache miss
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
	return &Relay{cache: cache, tmpDir: tmpDir, log: log, idle: defaultIdle, inflight: map[string]*download{}}, nil
}

// Open returns the cached object under key, or starts (or joins) the one
// fetch for key and returns a reader that streams it as it arrives. A failure
// to open the upstream is returned here; anything later comes from Read.
//
// The reader withholds the artifact's last byte until the digest matched and
// onCommit (if any) succeeded, so a client never gets the whole artifact
// before it is verified; then it hands the byte out and returns io.EOF. The
// cache write runs on in the background and doesn't hold readers up. On a
// mismatch the reader returns ErrDigestMismatch and nothing is cached. A cache
// hit is re-checked against want while it streams, its last byte likewise
// withheld until the check passed: a mismatch fails the read and drops the
// entry. The returned size is -1 when unknown; hit reports a cache hit.
func (r *Relay) Open(ctx context.Context, key string, want Digest, fetch Fetch, onCommit func(context.Context, Result) error) (body io.ReadCloser, size int64, hit bool, err error) {
	var dl *download
	joined := false
	// A download that finished between the cache miss and the in-flight
	// check has committed (or failed) and left the in-flight set: look in the
	// cache once more before starting a second fetch. Cache misses wait out a
	// commit in progress, so this window spans the whole cache write.
	for retried := false; ; retried = true {
		r.mu.Lock()
		gen := r.finished
		r.mu.Unlock()
		if rc, size, err := r.cache.Open(ctx, key); err == nil {
			return r.verifying(rc, key, want, size), size, true, nil
		} else if !errors.Is(err, storage.ErrNotFound) {
			return nil, 0, false, err
		}
		if r.afterMiss != nil {
			r.afterMiss()
		}

		r.mu.Lock()
		dl, joined = r.inflight[key]
		if !joined && r.finished != gen && !retried {
			r.mu.Unlock()
			continue
		}
		var runCtx context.Context
		if joined {
			dl.readers++
		} else {
			// The fetch outlives this request (others may join) but not its
			// last reader: leave cancels it.
			runCtx, dl = r.newDownload(ctx, key)
		}
		r.mu.Unlock()
		if !joined {
			r.runs.Go(func() { r.run(runCtx, dl, want, fetch, onCommit) })
		}
		break
	}
	select {
	case <-dl.ready:
	case <-ctx.Done():
		r.leave(dl)
		return nil, 0, false, ctx.Err()
	}
	if dl.openErr != nil {
		r.leave(dl)
		return nil, 0, false, dl.openErr
	}
	rd := &reader{r: r, dl: dl, ctx: ctx}
	// Wake a Read waiting for bytes when the request ends.
	rd.stop = context.AfterFunc(ctx, func() {
		dl.mu.Lock()
		dl.cond.Broadcast()
		dl.mu.Unlock()
	})
	return rd, dl.size, false, nil
}

// Wait blocks until every fetch started so far has ended, its cache write
// included: readers finish before that write does.
func (r *Relay) Wait() { r.runs.Wait() }

// newDownload registers a download for key with one reader. r.mu is held.
func (r *Relay) newDownload(ctx context.Context, key string) (context.Context, *download) {
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	dl := &download{key: key, readers: 1, ready: make(chan struct{}), cancel: cancel}
	dl.cond = sync.NewCond(&dl.mu)
	r.inflight[key] = dl
	return runCtx, dl
}

type download struct {
	key   string
	ready chan struct{} // closed once the upstream answered (openErr or file set)

	openErr error
	file    *os.File // temp file; read with ReadAt, closed once run ended and no reader is left
	size    int64
	cancel  context.CancelFunc // cancels the fetch; set before the download is shared

	mu         sync.Mutex
	cond       *sync.Cond
	written    int64
	committing bool // digest matched; the last reader leaving no longer cancels
	verified   bool // digest matched and onCommit succeeded: readers may finish
	done       bool
	err        error // final outcome once done; nil = verified and committed

	// Guarded by Relay.mu.
	readers    int
	runEnded   bool
	fileClosed bool
}

func (r *Relay) run(ctx context.Context, dl *download, want Digest, fetch Fetch, onCommit func(context.Context, Result) error) {
	cancel := dl.cancel
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
		r.forget(dl)
		dl.runEnded = true
		r.mu.Unlock()
		close(dl.ready)
		return
	}
	close(dl.ready)

	path := dl.file.Name()
	h1, h256 := sha1.New(), sha256.New()
	var stalled atomic.Bool
	timer := time.AfterFunc(r.idle, func() { stalled.Store(true); cancel() })
	res, err := dl.copy(body, h1, h256, func() { timer.Reset(r.idle) })
	timer.Stop()
	body.Close()
	if err != nil && stalled.Load() {
		err = ErrStalled
	}
	if err == nil {
		err = check(want, res)
	}
	if err == nil {
		// Under dl.mu, as leave cancels under it: either leave saw this
		// flag, or the cancellation is visible here.
		dl.mu.Lock()
		if err = ctx.Err(); err == nil {
			dl.committing = true
		}
		dl.mu.Unlock()
	}
	if err == nil && onCommit != nil {
		err = onCommit(ctx, res)
	}
	if err == nil {
		dl.mu.Lock()
		dl.verified = true
		dl.cond.Broadcast()
		dl.mu.Unlock()
		err = r.commit(ctx, dl.key, path)
	}
	cancel()
	// Commit or not, the key is free for a new fetch from here on.
	r.mu.Lock()
	r.forget(dl)
	r.finished++
	dl.runEnded = true
	r.closeIfIdle(dl)
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
func (dl *download) copy(body io.Reader, h1, h256 hash.Hash, progress func()) (Result, error) {
	buf := make([]byte, 256<<10)
	var total int64
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			progress()
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

// leave drops one reader without waiting for anything. The last one cancels
// an unfinished fetch that isn't committing yet and takes it out of the
// in-flight set, so a later reader starts afresh instead of joining it.
func (r *Relay) leave(dl *download) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dl.readers--
	if dl.readers > 0 {
		return
	}
	dl.mu.Lock()
	if !dl.done && !dl.committing {
		dl.cancel()
		r.forget(dl)
	}
	dl.mu.Unlock()
	r.closeIfIdle(dl)
}

// forget takes dl out of the in-flight set unless a newer download for its
// key replaced it. r.mu is held.
func (r *Relay) forget(dl *download) {
	if r.inflight[dl.key] == dl {
		delete(r.inflight, dl.key)
	}
}

// closeIfIdle closes the temp file once run has ended and no reader is
// left. r.mu is held; runEnded orders run's file assignment before this.
func (r *Relay) closeIfIdle(dl *download) {
	if dl.readers == 0 && dl.runEnded && !dl.fileClosed && dl.file != nil {
		dl.fileClosed = true
		dl.file.Close()
	}
}

// reader follows a download's temp file as it grows.
type reader struct {
	r      *Relay
	dl     *download
	ctx    context.Context // the request; Read gives up when it ends
	stop   func() bool     // unregisters the wake-up on ctx
	off    int64
	closed bool
}

// Read hands out what was written so far, except the last byte until the
// download is verified. Once verified it reads to the end, whatever the cache
// write's outcome.
func (rd *reader) Read(p []byte) (int, error) {
	dl := rd.dl
	dl.mu.Lock()
	var limit int64
	for {
		limit = dl.written
		if !dl.verified {
			limit--
		}
		if rd.off < limit || dl.verified || dl.done || rd.ctx.Err() != nil {
			break
		}
		dl.cond.Wait()
	}
	verified, done, err := dl.verified, dl.done, dl.err
	dl.mu.Unlock()
	switch {
	case !verified && done:
		return 0, err
	case rd.off < limit:
		n, rerr := dl.file.ReadAt(p[:min(int64(len(p)), limit-rd.off)], rd.off)
		rd.off += int64(n)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return n, rerr
		}
		return n, nil
	case verified:
		return 0, io.EOF
	}
	return 0, rd.ctx.Err()
}

func (rd *reader) Close() error {
	if rd.closed {
		return nil
	}
	rd.closed = true
	rd.stop()
	rd.r.leave(rd.dl)
	return nil
}

// verifying wraps a cache hit of size bytes: read in order from the start to
// the end, its bytes must match want, else the last Read fails and the entry
// is dropped. The last byte is handed out only after the check passed. A Seek
// away from the current position turns the check off (ranged requests read
// only part of the object).
func (r *Relay) verifying(rc io.ReadCloser, key string, want Digest, size int64) io.ReadCloser {
	if want == (Digest{}) {
		return rc
	}
	v := &verifier{rc: rc, relay: r, key: key, want: want, size: size, h1: sha1.New(), h256: sha256.New(), on: true}
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
	size     int64
	h1, h256 hash.Hash
	n        int64
	on       bool
}

func (v *verifier) Read(p []byte) (int, error) {
	if !v.on {
		return v.rc.Read(p)
	}
	// Read the last byte on its own, so it can be held back until checked.
	if v.n < v.size-1 {
		p = p[:min(int64(len(p)), v.size-1-v.n)]
	} else if v.n == v.size-1 && len(p) > 1 {
		p = p[:1]
	}
	n, err := v.rc.Read(p)
	v.h1.Write(p[:n])
	v.h256.Write(p[:n])
	v.n += int64(n)
	last := n > 0 && v.n == v.size
	if last || errors.Is(err, io.EOF) {
		if cerr := v.check(); cerr != nil {
			if last {
				n = 0
			}
			return n, cerr
		}
	}
	return n, err
}

// check compares what was read with want, dropping the entry on a mismatch.
func (v *verifier) check() error {
	got := Result{SHA1: hex.EncodeToString(v.h1.Sum(nil)), SHA256: hex.EncodeToString(v.h256.Sum(nil)), Size: v.n}
	err := check(v.want, got)
	if err != nil {
		if derr := v.relay.cache.Delete(context.Background(), v.key); derr != nil {
			v.relay.log.Warn("relay: dropping a corrupt cache entry failed", "key", v.key, "error", derr)
		}
	}
	return err
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
