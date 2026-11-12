package goproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"

	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

// testSumDB is an offline sum.golang.org: a sumdb.TestServer behind an
// httptest server that counts requests, captures bodies and injects faults.
type testSumDB struct {
	srv *httptest.Server

	mu      sync.Mutex
	handler http.Handler
	hits    map[string]int
	bodies  map[string][]byte
	fail    map[string]int    // path → status to answer once
	body    map[string][]byte // path → body to answer instead
	stall   map[string]bool
	stop    chan struct{}
}

func newTestSumDB(t testing.TB, signer string, mods map[string]string) *testSumDB {
	t.Helper()
	s := &testSumDB{
		hits: map[string]int{}, bodies: map[string][]byte{}, fail: map[string]int{},
		body: map[string][]byte{}, stall: map[string]bool{}, stop: make(chan struct{}),
	}
	s.serve(signer, mods)
	s.srv = httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	t.Cleanup(func() { close(s.stop); s.srv.Close() })
	return s
}

// serve replaces the database with a fresh one signed by signer that knows
// mods ("path@version" → hash suffix).
func (s *testSumDB) serve(signer string, mods map[string]string) {
	recs := map[string]string{}
	for pv, h := range mods {
		path, vers, _ := strings.Cut(pv, "@")
		recs[pv] = fmt.Sprintf("%s %s h1:zip%s=\n%s %s/go.mod h1:mod%s=\n", path, vers, h, path, vers, h)
	}
	s.serveRecords(signer, recs)
}

// serveRecords replaces the database with a fresh one signed by signer whose
// records are recs ("path@version" → go.sum lines).
func (s *testSumDB) serveRecords(signer string, recs map[string]string) {
	ts := sumdb.NewTestServer(signer, func(path, vers string) ([]byte, error) {
		r, ok := recs[path+"@"+vers]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(r), nil
	})
	s.mu.Lock()
	s.handler = sumdb.NewServer(ts)
	s.mu.Unlock()
}

func (s *testSumDB) serveHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	s.mu.Lock()
	s.hits[p]++
	stall := s.stall[p]
	code := s.fail[p]
	delete(s.fail, p)
	body, override := s.body[p]
	h := s.handler
	s.mu.Unlock()
	switch {
	case stall:
		select {
		case <-r.Context().Done():
		case <-s.stop:
		}
		return
	case code != 0:
		http.Error(w, "injected", code)
		return
	case override:
		w.Write(body)
		return
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	s.mu.Lock()
	s.bodies[p] = rec.Body.Bytes()
	s.mu.Unlock()
	maps.Copy(w.Header(), rec.Header())
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes())
}

func (s *testSumDB) count(p string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[p]
}

func (s *testSumDB) total(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for p, c := range s.hits {
		if strings.HasPrefix(p, prefix) {
			n += c
		}
	}
	return n
}

func (s *testSumDB) served(p string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies[p]
}

func (s *testSumDB) set(m map[string]int, p string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m[p] = code
}

type sumEnv struct {
	db     *testSumDB
	signer string
	key    string
	state  storage.Driver
	cache  *storage.Cache
	clock  time.Time
	cmu    sync.Mutex
}

var testMods = map[string]string{"example.com/m@v1.0.0": "AAAA", "example.com/m@v1.1.0": "BBBB"}

func newSumEnv(t testing.TB) *sumEnv {
	t.Helper()
	signer, key, err := note.GenerateKey(rand.Reader, SumDBName)
	if err != nil {
		t.Fatal(err)
	}
	newDriver := func() storage.Driver {
		d, err := storage.NewFS(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	cache, err := storage.NewCache(context.Background(), newDriver(), 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &sumEnv{db: newTestSumDB(t, signer, testMods), signer: signer, key: key, state: newDriver(), cache: cache, clock: time.Now()}
}

func (e *sumEnv) verifier() *Verifier {
	c := upstream.New(upstream.Options{FetchHosts: []string{"127.0.0.1"}, AllowPrivateForTesting: true})
	v := NewVerifier(VerifierOptions{Key: e.key, URL: e.db.srv.URL, Client: c, State: e.state, Cache: e.cache, TTL: time.Minute})
	v.now = func() time.Time {
		e.cmu.Lock()
		defer e.cmu.Unlock()
		return e.clock
	}
	return v
}

func (e *sumEnv) advance(d time.Duration) {
	e.cmu.Lock()
	defer e.cmu.Unlock()
	e.clock = e.clock.Add(d)
}

const lookupM = "/lookup/example.com/m@v1.0.0"

func TestVerifierLookup(t *testing.T) {
	e := newSumEnv(t)
	v := e.verifier()
	got, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.ZipHash != "h1:zipAAAA=" || got.ModHash != "h1:modAAAA=" {
		t.Fatalf("hashes %q %q", got.ZipHash, got.ModHash)
	}
	if want := e.db.served(lookupM); len(want) == 0 || !bytes.Equal(got.Record, want) {
		t.Fatalf("record %q, served %q", got.Record, want)
	}
	if e.db.count(lookupM) != 1 {
		t.Fatalf("%d lookups upstream", e.db.count(lookupM))
	}
	if h := v.Health(context.Background()); len(h) != 1 || !h[0].OK || !strings.Contains(h[0].Detail, "tree 1") {
		t.Fatalf("health %+v", h)
	}
}

func TestVerifierPersistsLatest(t *testing.T) {
	e := newSumEnv(t)
	if _, err := e.verifier().Lookup(context.Background(), "example.com/m", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	rc, _, err := e.state.Get(context.Background(), "go-sumdb/sum.golang.org/latest")
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := io.ReadAll(rc)
	rc.Close()
	vk, err := note.NewVerifier(e.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(msg, note.VerifierList(vk)); err != nil {
		t.Fatalf("stored latest is not a signed note: %v\n%s", err, msg)
	}
	// A new verifier starts from the stored head and verifies a newer record
	// against it.
	got, err := e.verifier().Lookup(context.Background(), "example.com/m", "v1.1.0")
	if err != nil || got.ZipHash != "h1:zipBBBB=" {
		t.Fatalf("got %+v, %v", got, err)
	}
	rc, _, err = e.state.Get(context.Background(), "go-sumdb/sum.golang.org/latest")
	if err != nil {
		t.Fatal(err)
	}
	msg2, _ := io.ReadAll(rc)
	rc.Close()
	if bytes.Equal(msg, msg2) {
		t.Fatal("latest did not advance")
	}
}

func TestVerifierDetectsFork(t *testing.T) {
	e := newSumEnv(t)
	if _, err := e.verifier().Lookup(context.Background(), "example.com/m", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	// Tree B: one record, like tree A, with other contents.
	e.db.serve(e.signer, map[string]string{"example.com/other@v1.0.0": "CCCC"})
	v := e.verifier()
	if _, err := v.Lookup(context.Background(), "example.com/other", "v1.0.0"); err == nil {
		t.Fatal("fork not detected")
	}
	if v.SecurityError() == "" {
		t.Fatal("no security error recorded")
	}
	before := e.db.total("/")
	for range 2 {
		_, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0")
		if err == nil || errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("lookup after a security error: %v", err)
		}
	}
	if e.db.total("/") != before {
		t.Fatal("lookups after a security error reached the database")
	}
	if h := v.Health(context.Background()); len(h) != 1 || h[0].OK || !strings.Contains(h[0].Detail, "SECURITY ERROR") {
		t.Fatalf("health %+v", h)
	}
}

// raceDriver lets a concurrent writer win between Get and PutIfMatch.
type raceDriver struct {
	storage.Driver
	before func()
}

func (d *raceDriver) PutIfMatch(ctx context.Context, key string, r io.Reader, etag string) (storage.Info, error) {
	if d.before != nil {
		d.before()
	}
	return d.Driver.PutIfMatch(ctx, key, r, etag)
}

func TestWriteConfigConflicts(t *testing.T) {
	const file = SumDBName + "/latest"
	ctx := context.Background()
	e := newSumEnv(t)
	rd := &raceDriver{Driver: e.state}
	e.state = rd
	o := e.verifier().newInstance().ops

	// Bootstrapping with no object writes.
	if err := o.WriteConfig(file, nil, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if got, err := o.ReadConfig(file); err != nil || string(got) != "one" {
		t.Fatalf("got %q, %v", got, err)
	}
	// Stored bytes differ from old.
	if err := o.WriteConfig(file, []byte("zero"), []byte("two")); err != sumdb.ErrWriteConflict { //nolint:errorlint // must be the bare value
		t.Fatalf("got %v", err)
	}
	// A concurrent writer wins between the read and the write.
	rd.before = func() {
		rd.before = nil
		if _, err := rd.Put(ctx, "go-sumdb/sum.golang.org/latest", strings.NewReader("other")); err != nil {
			t.Error(err)
		}
	}
	if err := o.WriteConfig(file, []byte("one"), []byte("two")); err != sumdb.ErrWriteConflict { //nolint:errorlint // must be the bare value
		t.Fatalf("got %v", err)
	}
	if got, _ := o.ReadConfig(file); string(got) != "other" {
		t.Fatalf("got %q", got)
	}
	if err := o.WriteConfig(file, []byte("other"), []byte("three")); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierSwapsAfterError(t *testing.T) {
	e := newSumEnv(t)
	v := e.verifier()
	e.db.set(e.db.fail, lookupM, http.StatusInternalServerError)
	if _, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("want a failure, got %v", err)
	}
	got, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0")
	if err != nil || got.ZipHash != "h1:zipAAAA=" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if n := e.db.count(lookupM); n != 2 {
		t.Fatalf("%d lookups upstream, want 2", n)
	}
}

func TestVerifierSwapsHourly(t *testing.T) {
	e := newSumEnv(t)
	v := e.verifier()
	first, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	old := v.cur.Load()
	old.ops.mu.Lock()
	old.ops.records[lookupM] = []byte("stale")
	old.ops.mu.Unlock()

	e.advance(59 * time.Minute)
	if _, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0"); err != nil || v.cur.Load() != old {
		t.Fatalf("swapped early (%v)", err)
	}
	e.advance(2 * time.Minute)
	got, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if v.cur.Load() == old {
		t.Fatal("not swapped after an hour")
	}
	if !bytes.Equal(got.Record, first.Record) {
		t.Fatalf("record %q, want %q", got.Record, first.Record)
	}
	if n := e.db.count(lookupM); n != 1 {
		t.Fatalf("%d lookups upstream, want 1 (the new client reads the cache)", n)
	}
}

func TestUnknownVersionIsNotFound(t *testing.T) {
	e := newSumEnv(t)
	v := e.verifier()
	const p = "/lookup/example.com/m@v9.0.0"
	for range 2 {
		if _, err := v.Lookup(context.Background(), "example.com/m", "v9.0.0"); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	}
	if n := e.db.count(p); n != 1 {
		t.Fatalf("%d lookups upstream, want 1", n)
	}
	e.advance(2 * time.Minute)
	if _, err := v.Lookup(context.Background(), "example.com/m", "v9.0.0"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if n := e.db.count(p); n != 2 {
		t.Fatalf("%d lookups upstream after the TTL, want 2", n)
	}
	// A 410 is a miss too.
	e.db.set(e.db.fail, "/lookup/example.com/m@v1.1.0", http.StatusGone)
	if _, err := v.Lookup(context.Background(), "example.com/m", "v1.1.0"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	// Known versions still verify through the swapped client.
	if _, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func TestTile404NotNotFound(t *testing.T) {
	e := newSumEnv(t)
	v := e.verifier()
	e.db.set(e.db.fail, "/tile/8/0/x123/456", http.StatusNotFound)
	_, err := v.Tile(context.Background(), "tile/8/0/x123/456")
	if err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	// A tile 404 during a lookup is no miss either.
	e.db.set(e.db.fail, "/tile/8/0/000.p/1", http.StatusNotFound)
	_, err = v.Lookup(context.Background(), "example.com/m", "v1.0.0")
	if err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if v.SecurityError() != "" {
		t.Fatalf("security error %q", v.SecurityError())
	}
}

func TestVerifierTile(t *testing.T) {
	e := newSumEnv(t)
	v := e.verifier()
	if _, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	const p = "tile/8/0/000.p/1"
	got, err := v.Tile(context.Background(), p)
	if err != nil || len(got) != 32 {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
	n := e.db.count("/" + p)
	if again, err := v.Tile(context.Background(), p); err != nil || !bytes.Equal(again, got) || e.db.count("/"+p) != n {
		t.Fatalf("not served from the cache: %v", err)
	}
	e.db.mu.Lock()
	e.db.body["/tile/8/0/000.p/2"] = got
	e.db.body["/tile/8/data/000.p/2"] = []byte("short is fine")
	e.db.mu.Unlock()
	if _, err := v.Tile(context.Background(), "tile/8/0/000.p/2"); err == nil {
		t.Fatal("short hash tile accepted")
	}
	if b, err := v.Tile(context.Background(), "tile/8/data/000.p/2"); err != nil || string(b) != "short is fine" {
		t.Fatalf("data tile: %q, %v", b, err)
	}
	if _, err := v.Tile(context.Background(), "tile/../x"); err == nil {
		t.Fatal("bad tile path accepted")
	}
}

func TestLookupCapsAndTimeout(t *testing.T) {
	e := newSumEnv(t)
	v := e.verifier()
	e.db.mu.Lock()
	e.db.body[lookupM] = bytes.Repeat([]byte("x"), 65<<10)
	e.db.mu.Unlock()
	if _, err := v.Lookup(context.Background(), "example.com/m", "v1.0.0"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("oversized lookup: %v", err)
	}

	const p = "/lookup/example.com/m@v1.1.0"
	e.db.mu.Lock()
	e.db.stall[p] = true
	e.db.mu.Unlock()
	v.remoteTimeout = 200 * time.Millisecond
	start := time.Now()
	_, err := v.Lookup(context.Background(), "example.com/m", "v1.1.0")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled lookup: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("stalled lookup hung")
	}
	// A cancelled caller returns at once.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	v.remoteTimeout = time.Minute
	if _, err := v.Lookup(ctx, "example.com/m", "v1.1.0"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled lookup: %v", err)
	}
}
