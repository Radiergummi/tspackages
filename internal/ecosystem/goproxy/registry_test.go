package goproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"

	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/relay"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

type fakeProxy struct {
	srv   *httptest.Server
	mu    sync.Mutex
	pages map[string]fakePage
	hits  map[string]int
	down  bool
}

type fakePage struct {
	status int
	ctype  string
	body   string
}

func newFakeProxy(t *testing.T) *fakeProxy {
	t.Helper()
	f := &fakeProxy{pages: map[string]fakePage{}, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits[r.URL.Path]++
		if f.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		p, ok := f.pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if p.ctype != "" {
			w.Header().Set("Content-Type", p.ctype)
		}
		if p.status != 0 {
			w.WriteHeader(p.status)
		}
		w.Write([]byte(p.body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeProxy) set(path, ctype, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages[path] = fakePage{ctype: ctype, body: body}
}

func (f *fakeProxy) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fakeProxy) setDown(d bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = d
}

type regEnv struct {
	px    *fakeProxy
	src   *RegistrySource
	clock time.Time
}

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	px := newFakeProxy(t)
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := storage.NewCache(context.Background(), d, 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := upstream.New(upstream.Options{FetchHosts: []string{"127.0.0.1"}, AllowPrivateForTesting: true})
	e := &regEnv{px: px, clock: time.Now()}
	e.src = NewRegistrySource(RegistryOptions{Name: "proxy", BaseURL: px.srv.URL, Client: c, Cache: cache, TTL: time.Minute, MaxArtifact: 1 << 20})
	e.src.now = func() time.Time { return e.clock }
	return e
}

const textCT = "text/plain; charset=utf-8"

func TestRegistryListValidated(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/example.com/m/@v/list", textCT, "v1.0.0\nv1.1.0 2026-01-01T00:00:00Z\nv0.0.0-20260101000000-abcdefabcdef\ngarbage\nv2.0.0\n")
	got, err := e.src.List(context.Background(), "example.com/m")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "\n") != "v1.0.0\nv1.1.0" {
		t.Fatalf("got %q", got)
	}
}

func TestRegistryListHTMLIsAFailure(t *testing.T) {
	for name, page := range map[string]fakePage{
		"html":    {ctype: "text/html", body: "<html>v1.0.0</html>"},
		"doctype": {ctype: textCT, body: "<!doctype html><title>x</title>"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newRegEnv(t)
			p := "/example.com/m/@v/list"
			e.px.set(p, page.ctype, page.body)
			if _, err := e.src.List(context.Background(), "example.com/m"); err == nil || errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("want a failure, got %v", err)
			}
			// Never cached: a good answer is fetched at once.
			e.px.set(p, textCT, "v1.0.0\n")
			got, err := e.src.List(context.Background(), "example.com/m")
			if err != nil || len(got) != 1 {
				t.Fatalf("got %q, %v", got, err)
			}
			// And with a cached copy, the failure serves it stale.
			e.px.set(p, "text/html", "<html>")
			e.clock = e.clock.Add(2 * time.Minute)
			got, err = e.src.List(context.Background(), "example.com/m")
			if err != nil || len(got) != 1 {
				t.Fatalf("stale: got %q, %v", got, err)
			}
		})
	}
}

func TestRegistryListNamingAnotherModule(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/example.com/m/@v/list", textCT, "example.com/other v1.0.0\n")
	got, err := e.src.List(context.Background(), "example.com/m")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRegistryInfoStripped(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	e.px.set("/example.com/m/@v/v1.0.0.info", "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05+01:00","Origin":{"VCS":"git"}}`)
	in, err := e.src.Info(ctx, "example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if b, _, ok := e.src.readCached(ctx, "go/proxy/"+mustSeg("example.com/m")+"/"+mustSeg("v1.0.0")+".info"); !ok || string(b) != `{"Version":"v1.0.0","Time":"2026-01-02T02:04:05Z"}` {
		t.Fatalf("cached %q", b)
	}
	if in.Version != "v1.0.0" || !in.Time.Equal(time.Date(2026, 1, 2, 2, 4, 5, 0, time.UTC)) || in.Time.Location() != time.UTC {
		t.Fatalf("got %+v", in)
	}
	e.px.set("/example.com/m/@v/v1.1.0.info", "application/json", `{"Version":"v1.2.0","Time":"2026-01-02T03:04:05Z"}`)
	if _, err := e.src.Info(ctx, "example.com/m", "v1.1.0"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("version mismatch: %v", err)
	}
	e.px.set("/example.com/m/@v/main.info", "application/json", `{"Version":"v0.0.0-20260101000000-abcdefabcdef","Time":"2026-01-01T00:00:00Z"}`)
	in, err = e.src.Info(ctx, "example.com/m", "main")
	if err != nil || in.Version != "v0.0.0-20260101000000-abcdefabcdef" {
		t.Fatalf("query: %+v, %v", in, err)
	}
	e.px.set("/example.com/m/@v/v1.3.0.info", "application/json", `{"Version":"v1.3.0","Time":"yesterday"}`)
	if _, err := e.src.Info(ctx, "example.com/m", "v1.3.0"); err == nil {
		t.Fatal("bad time accepted")
	}
	e.px.set("/example.com/m/@latest", "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
	if in, err := e.src.Latest(ctx, "example.com/m"); err != nil || in.Version != "v1.0.0" {
		t.Fatalf("latest: %+v, %v", in, err)
	}
}

func TestRegistryCanonicalInfoImmutable(t *testing.T) {
	e := newRegEnv(t)
	p := "/example.com/m/@v/v1.0.0.info"
	e.px.set(p, "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
	if _, err := e.src.Info(context.Background(), "example.com/m", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	e.clock = e.clock.Add(24 * time.Hour)
	if _, err := e.src.Info(context.Background(), "example.com/m", "v1.0.0"); err != nil || e.px.count(p) != 1 {
		t.Fatalf("hits %d, %v", e.px.count(p), err)
	}
}

func TestRegistryCanonicalInfoMissThenPublished(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	p := "/example.com/m/@v/v1.0.0.info"
	if _, err := e.src.Info(ctx, "example.com/m", "v1.0.0"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	e.px.set(p, "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
	e.clock = e.clock.Add(2 * time.Minute)
	if in, err := e.src.Info(ctx, "example.com/m", "v1.0.0"); err != nil || in.Version != "v1.0.0" {
		t.Fatalf("got %+v, %v", in, err)
	}
	if n := e.px.count(p); n != 2 {
		t.Fatalf("%d requests, want 2", n)
	}
}

func TestRegistryExpiredMissRefreshFailureIsNotAMiss(t *testing.T) {
	e := newRegEnv(t)
	ctx := context.Background()
	if _, err := e.src.List(ctx, "example.com/m"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	e.px.setDown(true)
	e.clock = e.clock.Add(2 * time.Minute)
	if _, err := e.src.List(ctx, "example.com/m"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("expired marker, upstream down: got %v", err)
	}
	// An unexpired marker is still a miss.
	e.px.setDown(false)
	if _, err := e.src.List(ctx, "example.com/m"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	e.clock = time.Now() // the cache stamps writes with the wall clock
	e.px.setDown(true)
	if _, err := e.src.List(ctx, "example.com/m"); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("unexpired marker: got %v", err)
	}
}

func TestRegistryQueryInfoMustBeCanonical(t *testing.T) {
	e := newRegEnv(t)
	for _, v := range []string{"v1.0", "1.0.0", "v1.0.0+meta"} {
		e.px.set("/example.com/m/@v/main.info", "application/json", `{"Version":"`+v+`","Time":"2026-01-02T03:04:05Z"}`)
		if _, err := e.src.Info(context.Background(), "example.com/m", "main"); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}

func TestRegistry410IsNotFound(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusNotFound} {
		e := newRegEnv(t)
		p := "/example.com/m/@v/list"
		e.px.mu.Lock()
		e.px.pages[p] = fakePage{status: status, ctype: textCT, body: "gone"}
		e.px.mu.Unlock()
		for range 2 {
			if _, err := e.src.List(context.Background(), "example.com/m"); !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("%d: got %v", status, err)
			}
		}
		if n := e.px.count(p); n != 1 {
			t.Fatalf("%d: %d requests, want 1", status, n)
		}
		e.clock = e.clock.Add(2 * time.Minute)
		e.src.List(context.Background(), "example.com/m")
		if n := e.px.count(p); n != 2 {
			t.Fatalf("%d: %d requests after TTL, want 2", status, n)
		}
	}
}

func TestRegistryStaleOnUpstreamDown(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/example.com/m/@v/list", textCT, "v1.0.0\n")
	if _, err := e.src.List(context.Background(), "example.com/m"); err != nil {
		t.Fatal(err)
	}
	e.px.setDown(true)
	e.clock = e.clock.Add(2 * time.Minute)
	got, err := e.src.List(context.Background(), "example.com/m")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %q, %v", got, err)
	}
	if h := e.src.Health(context.Background()); h[0].OK || h[0].Detail != "serving stale" {
		t.Fatalf("health %+v", h)
	}
	if _, err := e.src.List(context.Background(), "example.com/other"); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("uncached: %v", err)
	}
}

func TestRegistryTooLarge(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/example.com/m/@v/v1.0.0.info", "application/json", `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z","X":"`+strings.Repeat("a", 65<<10)+`"}`)
	if _, err := e.src.Info(context.Background(), "example.com/m", "v1.0.0"); !errors.Is(err, upstream.ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestRegistryURLsEscaped(t *testing.T) {
	e := newRegEnv(t)
	e.px.set("/github.com/!acme/x/@v/list", textCT, "v1.0.0\n")
	e.px.set("/github.com/!acme/x/@v/v1.0.0-!r!c1.info", "application/json", `{"Version":"v1.0.0-RC1","Time":"2026-01-02T03:04:05Z"}`)
	got, err := e.src.List(context.Background(), "github.com/Acme/x")
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %q, %v", got, err)
	}
	if in, err := e.src.Info(context.Background(), "github.com/Acme/x", "v1.0.0-RC1"); err != nil || in.Version != "v1.0.0-RC1" {
		t.Fatalf("info: %+v, %v", in, err)
	}
}

func mustSeg(s string) string { e, _ := seg(s); return e }

func FuzzRegistryList(f *testing.F) {
	for _, s := range []string{"v1.0.0\n", "<html>", "v1.0.0 x\r\nv2.0.0\n", "\xff", "v0.0.0-20260101000000-abcdefabcdef\n", "example.com/m v1.0.0"} {
		f.Add(s)
	}
	e := &RegistrySource{name: "p", log: slog.New(slog.DiscardHandler)}
	f.Fuzz(func(t *testing.T, body string) {
		out, err := e.cleanList("example.com/m", []byte(body))
		if err != nil {
			return
		}
		for line := range strings.SplitSeq(strings.TrimSuffix(string(out), "\n"), "\n") {
			if line == "" {
				continue
			}
			if module.Check("example.com/m", line) != nil || module.IsPseudoVersion(line) {
				t.Fatalf("served %q", line)
			}
		}
	})
}

func FuzzRegistryInfo(f *testing.F) {
	for _, s := range []string{`{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`, `{}`, `[]`, `{"Version":"v1.0.0","Time":"x","Origin":1}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		out, err := cleanInfo("example.com/m", "", []byte(body))
		if err != nil {
			return
		}
		if _, err := cleanInfo("example.com/m", "", out); err != nil {
			t.Fatalf("served %q does not re-validate: %v", out, err)
		}
		var in Info
		if json.Unmarshal(out, &in) != nil {
			t.Fatalf("served %q does not decode", out)
		}
		if out2, err := cleanInfo("example.com/m", in.Version, out); err != nil || string(out2) != string(out) {
			t.Fatalf("served %q with want %q: %q, %v", out, in.Version, out2, err)
		}
		if _, err := cleanInfo("example.com/m", "v9.9.9", out); err == nil && in.Version != "v9.9.9" {
			t.Fatalf("want mismatch accepted: %q", out)
		}
	})
}

// testModule is a module version as a GOPROXY serves it.
type testModule struct {
	path, version string
	gomod, zip    []byte
}

func newTestModule(t testing.TB, path, version string) testModule {
	t.Helper()
	dir := t.TempDir()
	gomod := []byte("module " + path + "\n\ngo 1.22\n")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), gomod, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := modzip.CreateFromDir(&buf, module.Version{Path: path, Version: version}, dir); err != nil {
		t.Fatal(err)
	}
	return testModule{path: path, version: version, gomod: gomod, zip: buf.Bytes()}
}

// record returns the checksum database record for m's go.mod and zip.
func (m testModule) record(t testing.TB) string {
	t.Helper()
	zh, err := dirhash.HashZip(writeTemp(t, m.zip), dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	mh, err := modHash(m.gomod)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", m.path, m.version, zh, m.path, m.version, mh)
}

func (m testModule) url(ext string) string {
	p, _ := module.EscapePath(m.path)
	v, _ := module.EscapeVersion(m.version)
	return "/" + p + "/@v/" + v + ext
}

type artEnv struct {
	sum *sumEnv
	px  *fakeProxy
	rl  *relay.Relay
	rec *records.Store
	src *RegistrySource
	c   *upstream.Client
}

// newArtEnv serves mods from a fake proxy; the test database knows the
// records in recs ("path@version" → go.sum lines).
func newArtEnv(t *testing.T, recs map[string]string, mods ...testModule) *artEnv {
	t.Helper()
	sum := newSumEnv(t)
	sum.db.serveRecords(sum.signer, recs)
	px := newFakeProxy(t)
	for _, m := range mods {
		px.set(m.url(".mod"), textCT, string(m.gomod))
		px.set(m.url(".zip"), "application/zip", string(m.zip))
	}
	rl, err := relay.New(sum.cache, filepath.Join(t.TempDir(), "relay"), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := upstream.New(upstream.Options{FetchHosts: []string{"127.0.0.1"}, AllowPrivateForTesting: true})
	e := &artEnv{sum: sum, px: px, rl: rl, rec: records.New(sum.state), c: c}
	e.src = NewRegistrySource(RegistryOptions{
		Name: "proxy", BaseURL: px.srv.URL, Client: c, Cache: sum.cache, Relay: rl, Records: e.rec,
		Verifier: sum.verifier(), TTL: time.Minute, MaxArtifact: 64 << 20,
	})
	return e
}

func recordsOf(t testing.TB, mods ...testModule) map[string]string {
	t.Helper()
	recs := map[string]string{}
	for _, m := range mods {
		recs[m.path+"@"+m.version] = m.record(t)
	}
	return recs
}

func readArtifact(a Artifact, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer a.Body.Close()
	return io.ReadAll(a.Body)
}

func (e *artEnv) key(t testing.TB, m testModule, ext string) string {
	t.Helper()
	k, err := e.src.artKey(m.path, m.version, ext)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (e *artEnv) cached(t testing.TB, key string) ([]byte, bool) {
	t.Helper()
	rc, _, err := e.sum.cache.Open(context.Background(), key)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return b, true
}

func TestRegistryZipVerified(t *testing.T) {
	for _, mv := range []module.Version{
		{Path: "example.com/m", Version: "v1.0.0"},
		{Path: "golang.org/toolchain", Version: "v0.0.1-go1.27.4.linux-amd64"},
	} {
		t.Run(mv.Path, func(t *testing.T) {
			m := newTestModule(t, mv.Path, mv.Version)
			e := newArtEnv(t, recordsOf(t, m), m)
			ctx := context.Background()
			got, err := readArtifact(e.src.Zip(ctx, m.path, m.version))
			if err != nil || !bytes.Equal(got, m.zip) {
				t.Fatalf("zip: %d bytes, %v", len(got), err)
			}
			if got, err := readArtifact(e.src.Mod(ctx, m.path, m.version)); err != nil || !bytes.Equal(got, m.gomod) {
				t.Fatalf("mod: %q, %v", got, err)
			}
			e.rl.Wait()
			sum := sha256.Sum256(m.zip)
			sha := hex.EncodeToString(sum[:])
			if z, ok := e.cached(t, e.key(t, m, ".zip")); !ok || !bytes.Equal(z, m.zip) {
				t.Fatal("zip not cached")
			}
			if s, ok := e.cached(t, e.key(t, m, ".zip.sha256")); !ok || string(s) != sha {
				t.Fatalf("sidecar %q", s)
			}
			if b, ok := e.cached(t, e.key(t, m, ".mod")); !ok || !bytes.Equal(b, m.gomod) {
				t.Fatal("go.mod not cached")
			}
			p, err := e.rec.GetProvenance(ctx, "go", m.path, m.version, sha)
			if err != nil {
				t.Fatal(err)
			}
			zh := strings.Fields(m.record(t))[2]
			if p.SourceType != "registry" || p.Source != "proxy" || p.DeclaredDigest != zh || !strings.HasPrefix(zh, "h1:") ||
				p.UpstreamURL != e.px.srv.URL+m.url(".zip") || p.SHA256 != sha {
				t.Fatalf("provenance %+v", p)
			}
			// Served from the cache from now on.
			for range 2 {
				if got, err := readArtifact(e.src.Zip(ctx, m.path, m.version)); err != nil || !bytes.Equal(got, m.zip) {
					t.Fatalf("cached zip: %v", err)
				}
				if got, err := readArtifact(e.src.Mod(ctx, m.path, m.version)); err != nil || !bytes.Equal(got, m.gomod) {
					t.Fatalf("cached mod: %v", err)
				}
			}
			if e.px.count(m.url(".zip")) != 1 || e.px.count(m.url(".mod")) != 1 {
				t.Fatalf("upstream fetched %d zips, %d go.mods", e.px.count(m.url(".zip")), e.px.count(m.url(".mod")))
			}
		})
	}
}

// localData returns the offset of the first entry's data in z.
func localData(t testing.TB, z []byte) int {
	t.Helper()
	if binary.LittleEndian.Uint32(z) != 0x04034b50 {
		t.Fatal("no local header")
	}
	return 30 + int(binary.LittleEndian.Uint16(z[26:])) + int(binary.LittleEndian.Uint16(z[28:]))
}

func TestRegistryZipTampered(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	flipped := bytes.Clone(m.zip)
	flipped[localData(t, flipped)+1] ^= 0xff
	// A well-formed zip of the same version with other contents.
	other := manyEntryZip(t, 1, func(int) string { return "example.com/m@v1.0.0/go.mod" })
	for name, bad := range map[string][]byte{"byte flipped": flipped, "other contents": other} {
		t.Run(name, func(t *testing.T) {
			e := newArtEnv(t, recordsOf(t, m), m)
			e.px.set(m.url(".zip"), "application/zip", string(bad))
			got, err := readArtifact(e.src.Zip(context.Background(), m.path, m.version))
			if err == nil || len(got) >= len(bad) {
				t.Fatalf("tampered zip served: %d of %d bytes, %v", len(got), len(bad), err)
			}
			e.rl.Wait()
			if _, ok := e.cached(t, e.key(t, m, ".zip")); ok {
				t.Fatal("tampered zip cached")
			}
			if _, ok := e.cached(t, e.key(t, m, ".zip.sha256")); ok {
				t.Fatal("sidecar written for a tampered zip")
			}
		})
	}
}

func TestRegistryZipTooManyEntries(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	prefix := m.path + "@" + m.version + "/"
	m.zip = manyEntryZip(t, maxZipEntries+1, func(i int) string { return fmt.Sprintf("%sf%d", prefix, i) })
	e := newArtEnv(t, map[string]string{m.path + "@" + m.version: m.record(t)}, m)
	got, err := readArtifact(e.src.Zip(context.Background(), m.path, m.version))
	if err == nil || len(got) >= len(m.zip) {
		t.Fatalf("zip of %d entries served: %d of %d bytes, %v", maxZipEntries+1, len(got), len(m.zip), err)
	}
	e.rl.Wait()
	if _, ok := e.cached(t, e.key(t, m, ".zip")); ok {
		t.Fatal("zip cached")
	}
	if _, ok := e.cached(t, e.key(t, m, ".zip.sha256")); ok {
		t.Fatal("sidecar cached")
	}
}

func TestRegistryZipWithoutSidecarRefetched(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	e := newArtEnv(t, recordsOf(t, m), m)
	ctx := context.Background()
	// A zip in the cache that nothing verified.
	if err := e.sum.cache.Put(ctx, e.key(t, m, ".zip"), strings.NewReader("not verified")); err != nil {
		t.Fatal(err)
	}
	got, err := readArtifact(e.src.Zip(ctx, m.path, m.version))
	if err != nil || !bytes.Equal(got, m.zip) {
		t.Fatalf("zip: %q, %v", got, err)
	}
	if e.px.count(m.url(".zip")) != 1 {
		t.Fatal("upstream not fetched")
	}
	e.rl.Wait()
	sum := sha256.Sum256(m.zip)
	if s, ok := e.cached(t, e.key(t, m, ".zip.sha256")); !ok || string(s) != hex.EncodeToString(sum[:]) {
		t.Fatalf("sidecar %q", s)
	}
	if z, _ := e.cached(t, e.key(t, m, ".zip")); !bytes.Equal(z, m.zip) {
		t.Fatal("verified zip not cached")
	}
}

func TestRegistryCachedServedWhenSumDBDown(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	m2 := newTestModule(t, "example.com/m", "v1.1.0")
	e := newArtEnv(t, recordsOf(t, m, m2), m, m2)
	ctx := context.Background()
	if _, err := readArtifact(e.src.Zip(ctx, m.path, m.version)); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifact(e.src.Mod(ctx, m.path, m.version)); err != nil {
		t.Fatal(err)
	}
	e.rl.Wait()
	// A verifier that can't reach any database and knows nothing.
	e.sum.db.srv.Close()
	fresh := newSumEnv(t)
	fresh.db.srv.Close()
	e.src.verifier = NewVerifier(VerifierOptions{Key: e.sum.key, URL: fresh.db.srv.URL, Client: e.c, State: fresh.state, Cache: fresh.cache, TTL: time.Minute})
	if got, err := readArtifact(e.src.Zip(ctx, m.path, m.version)); err != nil || !bytes.Equal(got, m.zip) {
		t.Fatalf("cached zip: %v", err)
	}
	if got, err := readArtifact(e.src.Mod(ctx, m.path, m.version)); err != nil || !bytes.Equal(got, m.gomod) {
		t.Fatalf("cached mod: %v", err)
	}
	for name, f := range map[string]func(context.Context, string, string) (Artifact, error){"zip": e.src.Zip, "mod": e.src.Mod} {
		if _, err := readArtifact(f(ctx, m2.path, m2.version)); err == nil || errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("uncached %s with the database down: %v", name, err)
		}
	}
	if e.px.count(m2.url(".zip")) != 0 || e.px.count(m2.url(".mod")) != 0 {
		t.Fatal("upstream fetched without a checksum database answer")
	}
}

func TestRegistryModMismatch(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	e := newArtEnv(t, recordsOf(t, m), m)
	ctx := context.Background()
	e.px.set(m.url(".mod"), textCT, "module example.com/m\n\ngo 1.23\n")
	_, err := readArtifact(e.src.Mod(ctx, m.path, m.version))
	if err == nil || resolve.HTTPStatus(resolve.Wrap("proxy", err)) != http.StatusBadGateway {
		t.Fatalf("mismatching go.mod: %v", err)
	}
	if _, ok := e.cached(t, e.key(t, m, ".mod")); ok {
		t.Fatal("mismatching go.mod cached")
	}
	e.px.set(m.url(".mod"), textCT, string(m.gomod))
	if got, err := readArtifact(e.src.Mod(ctx, m.path, m.version)); err != nil || !bytes.Equal(got, m.gomod) {
		t.Fatalf("mod: %q, %v", got, err)
	}
}

func TestRegistryModTooLarge(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	e := newArtEnv(t, recordsOf(t, m), m)
	e.px.set(m.url(".mod"), textCT, strings.Repeat("x", maxMod+1))
	if _, err := readArtifact(e.src.Mod(context.Background(), m.path, m.version)); !errors.Is(err, upstream.ErrTooLarge) {
		t.Fatal(err)
	}
}

func TestRegistryNoSumDBLine(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	e := newArtEnv(t, nil, m)
	ctx := context.Background()
	for name, f := range map[string]func(context.Context, string, string) (Artifact, error){"zip": e.src.Zip, "mod": e.src.Mod} {
		_, err := readArtifact(f(ctx, m.path, m.version))
		if !errors.Is(err, resolve.ErrNotFound) || resolve.HTTPStatus(resolve.Wrap("proxy", err)) != http.StatusNotFound {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if e.px.count(m.url(".zip")) != 0 || e.px.count(m.url(".mod")) != 0 {
		t.Fatal("upstream fetched for a version the database doesn't know")
	}
}

func TestRegistryUpstreamMissIsNotFound(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	e := newArtEnv(t, recordsOf(t, m))
	e.px.mu.Lock()
	e.px.pages[m.url(".zip")] = fakePage{status: http.StatusGone, body: "gone"}
	e.px.mu.Unlock()
	ctx := context.Background()
	for name, f := range map[string]func(context.Context, string, string) (Artifact, error){"zip": e.src.Zip, "mod": e.src.Mod} {
		if _, err := readArtifact(f(ctx, m.path, m.version)); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestRegistrySecurityErrorFailsClosed(t *testing.T) {
	m := newTestModule(t, "example.com/m", "v1.0.0")
	m2 := newTestModule(t, "example.com/m", "v1.1.0")
	e := newArtEnv(t, recordsOf(t, m, m2), m, m2)
	ctx := context.Background()
	if _, err := readArtifact(e.src.Zip(ctx, m.path, m.version)); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifact(e.src.Mod(ctx, m.path, m.version)); err != nil {
		t.Fatal(err)
	}
	e.rl.Wait()
	(&verifierOps{v: e.src.verifier}).SecurityError("injected fork")
	for name, f := range map[string]func(context.Context, string, string) (Artifact, error){"zip": e.src.Zip, "mod": e.src.Mod} {
		if _, err := readArtifact(f(ctx, m.path, m.version)); err != nil {
			t.Fatalf("cached %s: %v", name, err)
		}
		_, err := readArtifact(f(ctx, m2.path, m2.version))
		if resolve.HTTPStatus(resolve.Wrap("proxy", err)) != http.StatusBadGateway {
			t.Fatalf("uncached %s: %v", name, err)
		}
	}
	if e.px.count(m2.url(".zip")) != 0 || e.px.count(m2.url(".mod")) != 0 {
		t.Fatal("upstream fetched after a security error")
	}
}
