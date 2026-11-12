package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/radiergummi/tspackages/internal/storage"
)

// newHeldRelay returns a relay whose verified downloads wait to start their
// cache write until release runs.
func newHeldRelay(t *testing.T) (r *Relay, cache *storage.Cache, release func()) {
	t.Helper()
	r, cache, _ = newRelay(t)
	held := make(chan struct{})
	r.beforeCommit = func() { <-held }
	release = sync.OnceFunc(func() { close(held) })
	t.Cleanup(release) // registered after newRelay's Wait, so it runs first
	return r, cache, release
}

// readAllOf opens "k" with want and reads it to the end.
func readAllOf(t *testing.T, r *Relay, want Digest, fetch Fetch) []byte {
	t.Helper()
	rc, _, _, err := r.Open(context.Background(), "k", want, fetch, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %q: %v", got, err)
	}
	return got
}

// TestJoinerWithOtherDigestGetsItsOwnBytes: a request expecting other bytes
// than a download still committing doesn't join it; it waits for that run to
// end, drops what the run cached and fetches its own.
func TestJoinerWithOtherDigestGetsItsOwnBytes(t *testing.T) {
	r, cache, release := newHeldRelay(t)
	old, fresh := []byte("old artifact"), []byte("fresh artifact")
	var oldCalls, freshCalls atomic.Int32
	if got := readAllOf(t, r, digestOf(old), bytesFetch(old, &oldCalls)); !bytes.Equal(got, old) {
		t.Fatalf("first read %q", got)
	}
	// The first download is verified and its cache write held: release it
	// once the second request waits for that run to end.
	r.beforeWait = release
	if got := readAllOf(t, r, digestOf(fresh), bytesFetch(fresh, &freshCalls)); !bytes.Equal(got, fresh) {
		t.Fatalf("second read %q", got)
	}
	if oldCalls.Load() != 1 || freshCalls.Load() != 1 {
		t.Fatalf("fetches: old %d, fresh %d", oldCalls.Load(), freshCalls.Load())
	}
	r.Wait()
	rc, _, err := cache.Get(context.Background(), "k")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if got, _ := io.ReadAll(rc); !bytes.Equal(got, fresh) {
		t.Fatalf("cached %q", got)
	}
}

// TestSameDigest: only equal digests join; a field set on one side and not
// the other makes them differ.
func TestSameDigest(t *testing.T) {
	s1, s2 := Digest{SHA1: "AB"}, Digest{SHA256: "cd"}
	for _, c := range []struct {
		a, b Digest
		same bool
	}{
		{Digest{}, Digest{}, true},
		{s1, Digest{SHA1: "ab"}, true},
		{s1, Digest{}, false},
		{Digest{}, s2, false},
		{s1, s2, false},
		{Digest{SHA1: "ab", SHA256: "cd"}, s1, false},
	} {
		if got := sameDigest(c.a, c.b); got != c.same {
			t.Errorf("sameDigest(%+v, %+v) = %v", c.a, c.b, got)
		}
	}
}

// TestEvictWaitsForCommit: an eviction while a download of other bytes is
// still being cached takes effect after that write, not before it.
func TestEvictWaitsForCommit(t *testing.T) {
	r, cache, release := newHeldRelay(t)
	old := []byte("redeclared")
	var calls atomic.Int32
	readAllOf(t, r, digestOf(old), bytesFetch(old, &calls))
	r.beforeWait = release
	if err := r.Evict(context.Background(), "k", digestOf([]byte("new"))); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if _, _, err := cache.Get(context.Background(), "k"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("after eviction: %v", err)
	}
}

// TestEvictKeepsDownloadOfWantedBytes: an eviction for the digest a download
// in flight already expects neither waits for it nor drops what it caches.
func TestEvictKeepsDownloadOfWantedBytes(t *testing.T) {
	r, cache, release := newHeldRelay(t)
	fresh := []byte("fresh")
	var calls atomic.Int32
	readAllOf(t, r, digestOf(fresh), bytesFetch(fresh, &calls))
	r.beforeWait = func() { t.Error("Evict waited for a download of the wanted bytes"); release() }
	if err := r.Evict(context.Background(), "k", digestOf(fresh)); err != nil {
		t.Fatal(err)
	}
	release()
	r.Wait()
	if _, _, err := cache.Get(context.Background(), "k"); err != nil {
		t.Fatalf("after eviction: %v", err)
	}
}

// TestEvictKeepsCommittedWantedBytes: an eviction that waits out a download
// expecting another digest keeps what it cached when that matches want.
func TestEvictKeepsCommittedWantedBytes(t *testing.T) {
	r, cache, release := newHeldRelay(t)
	fresh := []byte("fresh")
	var calls atomic.Int32
	readAllOf(t, r, Digest{}, bytesFetch(fresh, &calls))
	r.beforeWait = release
	if err := r.Evict(context.Background(), "k", digestOf(fresh)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Get(context.Background(), "k"); err != nil {
		t.Fatalf("after eviction: %v", err)
	}
}
