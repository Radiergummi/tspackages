package relay

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/storage"
)

func newRelay(t *testing.T) (*Relay, *storage.Cache, string) {
	t.Helper()
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := storage.NewCache(context.Background(), d, 1<<40, nil)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(t.TempDir(), "relay")
	r, err := New(cache, tmp, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, cache, tmp
}

func digestOf(b []byte) Digest {
	s1, s2 := sha1.Sum(b), sha256.Sum256(b)
	return Digest{SHA1: hex.EncodeToString(s1[:]), SHA256: hex.EncodeToString(s2[:])}
}

// source is a Fetch over a pipe the test writes to.
type source struct {
	pr      *io.PipeReader
	pw      *io.PipeWriter
	calls   atomic.Int32
	ctxDone chan struct{}
}

func newSource() *source {
	pr, pw := io.Pipe()
	return &source{pr: pr, pw: pw, ctxDone: make(chan struct{})}
}

func (s *source) fetch(ctx context.Context) (io.ReadCloser, int64, error) {
	s.calls.Add(1)
	go func() { <-ctx.Done(); close(s.ctxDone); s.pr.CloseWithError(ctx.Err()) }()
	return s.pr, -1, nil
}

func bytesFetch(b []byte, calls *atomic.Int32) Fetch {
	return func(context.Context) (io.ReadCloser, int64, error) {
		calls.Add(1)
		return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
	}
}

func emptyDir(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ents, _ := os.ReadDir(dir)
		if len(ents) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still holds %d files", dir, len(ents))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFirstReaderGetsBytesBeforeFetchEnds(t *testing.T) {
	r, _, _ := newRelay(t)
	src := newSource()
	go src.pw.Write(make([]byte, 64<<10))
	rc, _, _, err := r.Open(context.Background(), "k", Digest{}, src.fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.ReadFull(rc, make([]byte, 64<<10)); err != nil {
		t.Fatalf("first 64 KiB while the fetch is still open: %v", err)
	}
	src.pw.Close()
}

func TestJoinersShareOneFetch(t *testing.T) {
	r, _, _ := newRelay(t)
	data := bytes.Repeat([]byte("abcdefgh"), 1<<16)
	src := newSource()
	var wg sync.WaitGroup
	got := make([][]byte, 8)
	errs := make([]error, 8)
	started := make(chan struct{}, 8)
	for i := range 8 {
		wg.Go(func() {
			rc, _, _, err := r.Open(context.Background(), "k", digestOf(data), src.fetch, nil)
			started <- struct{}{}
			if err != nil {
				errs[i] = err
				return
			}
			defer rc.Close()
			got[i], errs[i] = io.ReadAll(rc)
		})
	}
	for range 8 {
		<-started
	}
	src.pw.Write(data)
	src.pw.Close()
	wg.Wait()
	for i := range 8 {
		if errs[i] != nil || !bytes.Equal(got[i], data) {
			t.Fatalf("reader %d: %v, %d bytes", i, errs[i], len(got[i]))
		}
	}
	if n := src.calls.Load(); n != 1 {
		t.Fatalf("fetch called %d times", n)
	}
	rc, size, hit, err := r.Open(context.Background(), "k", digestOf(data), src.fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if !hit || !bytes.Equal(b, data) || size != int64(len(data)) || src.calls.Load() != 1 {
		t.Fatalf("cache hit: %d bytes, size %d, %d fetches", len(b), size, src.calls.Load())
	}
}

func TestMismatchAbortsAndCachesNothing(t *testing.T) {
	r, cache, tmp := newRelay(t)
	var calls atomic.Int32
	want := Digest{SHA256: hex.EncodeToString(make([]byte, 32))}
	rc, _, _, err := r.Open(context.Background(), "k", want, bytesFetch([]byte("payload"), &calls), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("read err = %v", err)
	}
	rc.Close()
	if _, _, err := cache.Get(context.Background(), "k"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cached after mismatch: %v", err)
	}
	emptyDir(t, tmp)
}

func TestLastReaderLeavingCancelsFetch(t *testing.T) {
	r, _, tmp := newRelay(t)
	src := newSource()
	go src.pw.Write(make([]byte, 1024))
	a, _, _, err := r.Open(context.Background(), "k", Digest{}, src.fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := r.Open(context.Background(), "k", Digest{}, src.fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadFull(a, make([]byte, 1024))
	a.Close()
	select {
	case <-src.ctxDone:
		t.Fatal("fetch cancelled while a reader remains")
	case <-time.After(50 * time.Millisecond):
	}
	b.Close()
	select {
	case <-src.ctxDone:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch not cancelled after the last reader left")
	}
	emptyDir(t, tmp)
}

func TestFirstCallerContextDoesNotCancelFetch(t *testing.T) {
	r, _, _ := newRelay(t)
	src := newSource()
	ctx, cancel := context.WithCancel(context.Background())
	a, _, _, err := r.Open(ctx, "k", Digest{}, src.fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	cancel()
	select {
	case <-src.ctxDone:
		t.Fatal("the first caller's context cancelled the shared fetch")
	case <-time.After(50 * time.Millisecond):
	}
	src.pw.Close()
}

func TestOnCommitRunsOnceBeforeEOF(t *testing.T) {
	r, _, _ := newRelay(t)
	data := []byte("committed")
	var calls atomic.Int32
	var commits atomic.Int32
	var got Result
	onCommit := func(_ context.Context, res Result) error { commits.Add(1); got = res; return nil }
	rc, _, _, err := r.Open(context.Background(), "k", digestOf(data), bytesFetch(data, &calls), onCommit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	want := digestOf(data)
	if commits.Load() != 1 || got.SHA1 != want.SHA1 || got.SHA256 != want.SHA256 || got.Size != int64(len(data)) {
		t.Fatalf("onCommit %d times with %+v", commits.Load(), got)
	}
}

func TestOnCommitErrorFailsReadersAndCachesNothing(t *testing.T) {
	r, cache, _ := newRelay(t)
	var calls atomic.Int32
	boom := errors.New("provenance store down")
	rc, _, _, err := r.Open(context.Background(), "k", Digest{}, bytesFetch([]byte("x"), &calls), func(context.Context, Result) error { return boom })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); !errors.Is(err, boom) {
		t.Fatalf("read err = %v", err)
	}
	rc.Close()
	if _, _, err := cache.Get(context.Background(), "k"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cached: %v", err)
	}
}

func TestFetchErrorReturnedFromOpen(t *testing.T) {
	r, _, _ := newRelay(t)
	boom := errors.New("404")
	_, _, _, err := r.Open(context.Background(), "k", Digest{}, func(context.Context) (io.ReadCloser, int64, error) { return nil, 0, boom }, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

// A cache hit is re-checked against the declared digest as it streams; a
// mismatch fails the read and drops the entry.
func TestCacheHitRechecked(t *testing.T) {
	r, cache, _ := newRelay(t)
	if err := cache.Put(context.Background(), "k", bytes.NewReader([]byte("tampered"))); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	rc, _, _, err := r.Open(context.Background(), "k", digestOf([]byte("original")), bytesFetch([]byte("original"), &calls), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("read err = %v", err)
	}
	rc.Close()
	if _, _, err := cache.Get(context.Background(), "k"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("bad entry kept: %v", err)
	}
}

func TestCacheHitSeekable(t *testing.T) {
	r, cache, _ := newRelay(t)
	if err := cache.Put(context.Background(), "k", bytes.NewReader([]byte("0123456789"))); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	rc, size, _, err := r.Open(context.Background(), "k", Digest{}, bytesFetch(nil, &calls), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	rs, ok := rc.(io.ReadSeeker)
	if !ok || size != 10 {
		t.Fatalf("seekable %v, size %d", ok, size)
	}
	rs.Seek(6, io.SeekStart)
	b, _ := io.ReadAll(rs)
	if string(b) != "6789" {
		t.Fatalf("after seek: %q", b)
	}
}

func TestMemoryBounded(t *testing.T) {
	r, _, _ := newRelay(t)
	const size = 256 << 20
	rnd := rand.New(rand.NewPCG(3, 4))
	fetch := func(context.Context) (io.ReadCloser, int64, error) {
		pr, pw := io.Pipe()
		go func() {
			buf := make([]byte, 1<<20)
			for range size >> 20 {
				for i := range buf {
					buf[i] = byte(rnd.Uint32())
				}
				pw.Write(buf)
			}
			pw.Close()
		}()
		return pr, size, nil
	}
	runtime.GC()
	var before, peak runtime.MemStats
	runtime.ReadMemStats(&before)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			rc, _, _, err := r.Open(context.Background(), "big", Digest{}, fetch, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer rc.Close()
			buf := make([]byte, 32<<10)
			for {
				if _, err := rc.Read(buf); err != nil {
					return
				}
			}
		})
	}
	wg.Wait()
	runtime.ReadMemStats(&peak)
	if grew := int64(peak.HeapAlloc) - int64(before.HeapAlloc); grew > 64<<20 {
		t.Fatalf("heap grew by %d MiB", grew>>20)
	}
}

func TestStartupSweepsTemp(t *testing.T) {
	d, _ := storage.NewFS(t.TempDir())
	cache, _ := storage.NewCache(context.Background(), d, 1<<30, nil)
	tmp := filepath.Join(t.TempDir(), "relay")
	os.Mkdir(tmp, 0o700)
	os.WriteFile(tmp+"/leftover", []byte("x"), 0o600)
	if _, err := New(cache, tmp, nil); err != nil {
		t.Fatal(err)
	}
	emptyDir(t, tmp)
}

// An upstream that stops sending fails the download instead of holding its
// readers forever.
func TestStalledUpstreamFails(t *testing.T) {
	r, _, tmp := newRelay(t)
	r.idle = 100 * time.Millisecond
	src := newSource()
	go src.pw.Write([]byte("partial"))
	rc, _, _, err := r.Open(context.Background(), "k", Digest{}, src.fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(rc); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrStalled) {
			t.Fatalf("err = %v, want ErrStalled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader still blocked on a stalled upstream")
	}
	emptyDir(t, tmp)
}

// TestOpenAfterCommitDuringMissDoesNotRefetch: a reader whose cache lookup
// missed while the download was still committing must not start a second
// fetch once the download has left the in-flight set.
func TestOpenAfterCommitDuringMissDoesNotRefetch(t *testing.T) {
	r, _, _ := newRelay(t)
	body := []byte("committed while the second reader looked")
	var calls atomic.Int32
	fetch := bytesFetch(body, &calls)
	ctx := context.Background()

	first, _, _, err := r.Open(ctx, "k", digestOf(body), fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The second reader misses the cache, then waits until the first
	// download has committed and left the in-flight set.
	r.afterMiss = func() {
		r.afterMiss = nil
		if _, err := io.ReadAll(first); err != nil {
			t.Error(err)
		}
		first.Close()
	}
	second, _, _, err := r.Open(ctx, "k", digestOf(body), fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got, err := io.ReadAll(second); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("second reader: %q, %v", got, err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("upstream fetched %d times", n)
	}
}

// stubbornBody streams its bytes, then blocks until released, ignoring
// cancellation, like an upstream that is slow to notice.
type stubbornBody struct {
	r       io.Reader
	release chan struct{}
}

func (b *stubbornBody) Read(p []byte) (int, error) {
	if n, err := b.r.Read(p); n > 0 || !errors.Is(err, io.EOF) {
		return n, err
	}
	<-b.release
	return 0, io.EOF
}

func (*stubbornBody) Close() error { return nil }

func within(t *testing.T, what string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// TestJoinAfterLastReaderLeft: once the last reader has left an unfinished
// download, a new reader starts a fresh fetch instead of joining the
// cancelled one, and leaving doesn't wait for the upstream.
func TestJoinAfterLastReaderLeft(t *testing.T) {
	r, _, _ := newRelay(t)
	body := []byte("abandoned then wanted again")
	var calls atomic.Int32
	first := &stubbornBody{r: bytes.NewReader(body[:4]), release: make(chan struct{})}
	defer close(first.release)
	fetch := func(context.Context) (io.ReadCloser, int64, error) {
		if calls.Add(1) == 1 {
			return first, -1, nil
		}
		return io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
	}
	a, _, _, err := r.Open(context.Background(), "k", digestOf(body), fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadFull(a, make([]byte, 4))
	within(t, "the last reader's Close", 2*time.Second, func() { a.Close() })
	b, _, _, err := r.Open(context.Background(), "k", digestOf(body), fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if got, err := io.ReadAll(b); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("new reader: %q, %v", got, err)
	}
}

// TestLeavingDuringCommitKeepsCommit: a verified download is cached even if
// its only reader leaves while it commits.
func TestLeavingDuringCommitKeepsCommit(t *testing.T) {
	r, cache, _ := newRelay(t)
	body := []byte("verified, then the client left")
	var calls atomic.Int32
	inCommit, release, committed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	onCommit := func(ctx context.Context, _ Result) error {
		close(inCommit)
		<-release
		committed <- ctx.Err()
		return ctx.Err()
	}
	a, _, _, err := r.Open(context.Background(), "k", digestOf(body), bytesFetch(body, &calls), onCommit)
	if err != nil {
		t.Fatal(err)
	}
	<-inCommit
	a.Close()
	close(release)
	if err := <-committed; err != nil {
		t.Fatalf("commit cancelled: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, err := cache.Get(context.Background(), "k"); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("verified download not cached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestOpenCancelledBeforeUpstreamAnswers: a request that gives up while the
// upstream hasn't answered returns at once and cancels the fetch.
func TestOpenCancelledBeforeUpstreamAnswers(t *testing.T) {
	r, _, _ := newRelay(t)
	fetchCancelled := make(chan struct{})
	fetch := func(ctx context.Context) (io.ReadCloser, int64, error) {
		<-ctx.Done()
		close(fetchCancelled)
		return nil, 0, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	within(t, "Open", 2*time.Second, func() {
		if _, _, _, err := r.Open(ctx, "k", Digest{}, fetch, nil); !errors.Is(err, context.Canceled) {
			t.Errorf("Open: %v", err)
		}
	})
	select {
	case <-fetchCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the fetch was not cancelled")
	}
}

// TestReadStopsWithRequest: a reader waiting for bytes returns once its
// request is cancelled, without waiting for the idle timeout.
func TestReadStopsWithRequest(t *testing.T) {
	r, _, _ := newRelay(t)
	src := newSource()
	ctx, cancel := context.WithCancel(context.Background())
	rc, _, _, err := r.Open(ctx, "k", Digest{}, src.fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	time.AfterFunc(50*time.Millisecond, cancel)
	within(t, "Read", 2*time.Second, func() {
		if _, err := rc.Read(make([]byte, 8)); !errors.Is(err, context.Canceled) {
			t.Errorf("Read: %v", err)
		}
	})
}
