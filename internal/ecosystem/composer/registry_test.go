package composer

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiergummi/tspackages/internal/records"
	"github.com/radiergummi/tspackages/internal/resolve"
	"github.com/radiergummi/tspackages/internal/storage"
	"github.com/radiergummi/tspackages/internal/upstream"
)

// fakeRegistry is a mutable fake Packagist.
type fakeRegistry struct {
	srv *httptest.Server
	mu  sync.Mutex
	// files maps a request path to its body; a missing path is a 404.
	files  map[string][]byte
	status int // when non-zero, every request gets this status
	hits   map[string]int
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{files: map[string][]byte{}, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits[r.URL.Path]++
		if f.status != 0 {
			http.Error(w, "boom", f.status)
			return
		}
		b, ok := f.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) set(path string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = b
}

func (f *fakeRegistry) setStatus(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = code
}

func (f *fakeRegistry) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fakeRegistry) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.hits {
		n += c
	}
	return n
}

type regEnv struct {
	f     *fakeRegistry
	src   *RegistrySource
	cache *storage.Cache
	d     storage.Driver
	rec   *records.Store
	clock time.Time
}

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	f := newFakeRegistry(t)
	d, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := storage.NewCache(context.Background(), d, 1<<30, nil)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := storage.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := records.New(rd)
	host := strings.TrimPrefix(f.srv.URL, "http://")
	c := upstream.New(upstream.Options{FetchHosts: []string{strings.Split(host, ":")[0]}, AllowPrivateForTesting: true})
	e := &regEnv{f: f, cache: cache, d: d, rec: rec, clock: time.Now()}
	e.src = NewRegistrySource("packagist", nil, f.srv.URL, c, cache, rec, time.Minute, 1<<20, 0, nil, nil)
	e.src.now = func() time.Time { return e.clock }
	return e
}

func fixture(t *testing.T, name, base string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(b, []byte("{{BASE}}"), []byte(base))
}

// distMeta is a one-version p2 document whose dist points at the fake server.
func distMeta(base, shasum, ref string) []byte {
	return fmt.Appendf(nil, `{"minified":"composer/2.0","packages":{"acme/pkg":[{"name":"acme/pkg","version":"1.0.0","version_normalized":"1.0.0.0","dist":{"url":"%s/dist/pkg.zip","type":"zip","shasum":%q,"reference":%q}}]}}`, base, shasum, ref)
}

func sum1(b []byte) string { s := sha1.Sum(b); return hex.EncodeToString(s[:]) }
func sum256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func distKeys(t *testing.T, d storage.Driver) []string {
	t.Helper()
	var keys []string
	for info, err := range d.List(context.Background(), "composer/packagist/dist/") {
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, info.Key)
	}
	return keys
}

func TestVersionsFromMinified(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/monolog/monolog.json", fixture(t, "packagist-monolog.json", e.f.srv.URL))
	vs, err := e.src.Versions(context.Background(), "monolog/monolog", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 3 {
		t.Fatalf("got %d versions", len(vs))
	}
	want := map[string]string{"3.8.0": "55b265fe03500dcd5c45b8ca4e4a1330e262ac29", "3.7.0": "87407b1e7346a961c59934c1d0cf703f147c87fa", "2.9.3": ""}
	for _, v := range vs {
		dist := v.Package["dist"].(map[string]any)
		if dist["shasum"] != want[v.Version] {
			t.Errorf("%s shasum = %v", v.Version, dist["shasum"])
		}
		if v.Reference != dist["reference"] || v.Reference == "" {
			t.Errorf("%s reference = %q", v.Version, v.Reference)
		}
		if v.Package["name"] != "monolog/monolog" || v.Dev {
			t.Errorf("%s package not expanded: %v", v.Version, v.Package)
		}
	}
	// __unset removed "suggest" on 3.7.0 and the removal carries over.
	if _, ok := vs[1].Package["suggest"]; ok {
		t.Error("suggest should be unset on 3.7.0")
	}
	if _, ok := vs[0].Package["suggest"]; !ok {
		t.Error("suggest missing on 3.8.0")
	}
	if n := e.f.count("/p2/monolog/monolog~dev.json"); n != 0 {
		t.Errorf("~dev fetched %d times for stable versions", n)
	}
	// The fixture shasums are the real sha1 of these bodies.
	e.f.set("/dist/monolog-3.8.0.zip", []byte("monolog-3.8.0-zip"))
	a, err := e.src.Dist(context.Background(), "monolog/monolog", "3.8.0", "aef6ee73a77a66e404dd6540934a9ef1b3c855b4")
	if err != nil {
		t.Fatal(err)
	}
	a.Body.Close()
}

func TestVersionsDevOnlyAndDevFlag(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg~dev.json", []byte(`{"packages":{"acme/pkg":[{"name":"acme/pkg","version":"dev-main","version_normalized":"dev-main","dist":{"url":"x","type":"zip","reference":"abc"}}]}}`))
	vs, err := e.src.Versions(context.Background(), "Acme/Pkg", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Version != "dev-main" || !vs[0].Dev {
		t.Fatalf("got %+v", vs)
	}
	// Only the requested file is fetched; a missing stable file is a miss.
	if n := e.f.count("/p2/acme/pkg.json"); n != 0 {
		t.Errorf("stable fetched %d times for dev versions", n)
	}
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("stable err = %v", err)
	}
}

func TestVersionsUnknownIsNotFoundAndNegativeCached(t *testing.T) {
	e := newRegEnv(t)
	for range 2 {
		_, err := e.src.Versions(context.Background(), "acme/none", false)
		if !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	}
	if n := e.f.count("/p2/acme/none.json"); n != 1 {
		t.Fatalf("stable file fetched %d times", n)
	}
	// After the TTL the marker expires and upstream is asked again.
	e.clock = e.clock.Add(2 * time.Minute)
	if _, err := e.src.Versions(context.Background(), "acme/none", false); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if n := e.f.count("/p2/acme/none.json"); n != 2 {
		t.Fatalf("stable file fetched %d times", n)
	}
}

func TestMetadataFreshWithinTTL(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	for range 3 {
		if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.f.count("/p2/acme/pkg.json"); n != 1 {
		t.Fatalf("fetched %d times", n)
	}
}

func TestMetadataStaleOnUpstreamError(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil {
		t.Fatal(err)
	}
	e.f.setStatus(500)
	e.clock = e.clock.Add(time.Hour)
	vs, err := e.src.Versions(context.Background(), "acme/pkg", false)
	if err != nil || len(vs) != 1 {
		t.Fatalf("vs=%v err=%v", vs, err)
	}
	if e.f.count("/p2/acme/pkg.json") < 2 {
		t.Fatal("expected a refetch attempt")
	}
}

func TestMetadataErrorWithoutCache(t *testing.T) {
	e := newRegEnv(t)
	e.f.setStatus(500)
	_, err := e.src.Versions(context.Background(), "acme/pkg", false)
	if err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestMetadataRejectsForeignPackages(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[],"evil/other":[{"version":"1.0.0"}]},"extra":1}`))
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestMetadataIgnoresExtraTopLevelKeys(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[{"version":"1.0.0","dist":{"url":"u","reference":"r"}}]},"security-advisories":[{"x":1}]}`))
	vs, err := e.src.Versions(context.Background(), "acme/pkg", false)
	if err != nil || len(vs) != 1 {
		t.Fatalf("vs=%v err=%v", vs, err)
	}
}

func TestWaiterCalledBeforeEveryRequest(t *testing.T) {
	e := newRegEnv(t)
	n := 0
	e.src.wait = func(context.Context) error { n++; return nil }
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil {
		t.Fatal(err)
	}
	if n != e.f.total() || n != 1 {
		t.Fatalf("waits=%d requests=%d", n, e.f.total())
	}
	e.src.wait = func(context.Context) error { return errors.New("limited") }
	e.clock = e.clock.Add(time.Hour)
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil {
		t.Fatalf("stale should cover a waiter error: %v", err)
	}
}

func TestDistVerifiesShasum(t *testing.T) {
	e := newRegEnv(t)
	zip := []byte("PK-good-zip")
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, sum1(zip), "r1"))
	e.f.set("/dist/pkg.zip", zip)
	a, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(a.Body)
	a.Body.Close()
	if !bytes.Equal(got, zip) || a.Size != int64(len(zip)) {
		t.Fatalf("artifact = %q %+v", got, a)
	}
	if keys := distKeys(t, e.d); len(keys) != 1 || !strings.HasSuffix(keys[0], sum256(zip)+".zip") {
		t.Fatalf("keys = %v", keys)
	}
	// Second call is served from cache.
	if _, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1"); err != nil {
		t.Fatal(err)
	}
	if n := e.f.count("/dist/pkg.zip"); n != 1 {
		t.Fatalf("zip fetched %d times", n)
	}
	p, err := e.rec.GetProvenance(context.Background(), "composer", "acme/pkg", "1.0.0", sum256(zip))
	if err != nil {
		t.Fatal(err)
	}
	if p.SourceType != "registry" || p.Source != "packagist" || p.DeclaredDigest != "sha1:"+sum1(zip) || p.SHA1 != sum1(zip) || p.UpstreamURL != e.f.srv.URL+"/dist/pkg.zip" {
		t.Fatalf("provenance = %+v", p)
	}

	// A tampered upstream zip is rejected and nothing is cached.
	e2 := newRegEnv(t)
	e2.f.set("/p2/acme/pkg.json", distMeta(e2.f.srv.URL, sum1(zip), "r1"))
	e2.f.set("/dist/pkg.zip", []byte("PK-evil-zip"))
	if _, err := e2.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1"); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Fatalf("err = %v", err)
	}
	if keys := distKeys(t, e2.d); len(keys) != 0 {
		t.Fatalf("cached after mismatch: %v", keys)
	}
}

func TestDistEmptyShasum(t *testing.T) {
	e := newRegEnv(t)
	zip := []byte("PK-zip-without-shasum")
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	e.f.set("/dist/pkg.zip", zip)
	a, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1")
	if err != nil {
		t.Fatal(err)
	}
	a.Body.Close()
	p, err := e.rec.GetProvenance(context.Background(), "composer", "acme/pkg", "1.0.0", sum256(zip))
	if err != nil {
		t.Fatal(err)
	}
	if p.DeclaredDigest != "" || p.SHA256 == "" {
		t.Fatalf("provenance = %+v", p)
	}
}

func TestDistReferenceMismatch(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	e.f.set("/dist/pkg.zip", []byte("zip"))
	for _, c := range [][2]string{{"1.0.0", "other"}, {"2.0.0", "r1"}} {
		if _, err := e.src.Dist(context.Background(), "acme/pkg", c[0], c[1]); !errors.Is(err, resolve.ErrNotFound) {
			t.Fatalf("%v: err = %v", c, err)
		}
	}
	if n := e.f.count("/dist/pkg.zip"); n != 0 {
		t.Fatalf("artifact fetched %d times", n)
	}
}

func TestDistSourceOnlyVersionNotFound(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[{"version":"1.0.0","source":{"url":"https://example.org/x.git","type":"git","reference":"r1"}}]}}`))
	if _, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	vs, err := e.src.Versions(context.Background(), "acme/pkg", false)
	if err != nil || len(vs) != 1 {
		t.Fatalf("vs=%v err=%v", vs, err)
	}
}

func TestDistHostMustBeAllowed(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[{"version":"1.0.0","dist":{"url":"http://not-allowed.invalid/x.zip","type":"zip","shasum":"","reference":"r1"}}]}}`))
	if _, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1"); !errors.Is(err, upstream.ErrHostNotAllowed) {
		t.Fatalf("err = %v", err)
	}
}

func TestRegistrySourceBasics(t *testing.T) {
	e := newRegEnv(t)
	if e.src.Name() != "packagist" {
		t.Fatal("identity")
	}
}

func TestDistCacheHitRechecksDeclaredShasum(t *testing.T) {
	e := newRegEnv(t)
	old, fresh := []byte("PK-old"), []byte("PK-new")
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, sum1(old), "r1"))
	e.f.set("/dist/pkg.zip", old)
	a, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1")
	if err != nil {
		t.Fatal(err)
	}
	a.Body.Close()
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, sum1(fresh), "r1"))
	e.f.set("/dist/pkg.zip", fresh)
	e.clock = e.clock.Add(time.Hour)
	a, err = e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(a.Body)
	if !bytes.Equal(got, fresh) {
		t.Fatalf("got %q", got)
	}
}

func TestDistEmptyShasumSHA1IsObserved(t *testing.T) {
	e := newRegEnv(t)
	zip := []byte("PK-observed")
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	e.f.set("/dist/pkg.zip", zip)
	for range 2 { // miss, then hit
		a, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1")
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(a.Body)
		a.Body.Close()
		if !bytes.Equal(got, zip) {
			t.Fatalf("got %q", got)
		}
	}
}

func TestMetadataGarbageDoesNotReplaceCache(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil {
		t.Fatal(err)
	}
	e.clock = e.clock.Add(time.Hour)
	e.f.set("/p2/acme/pkg.json", []byte("<html>oops</html>"))
	if vs, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil || len(vs) != 1 {
		t.Fatalf("garbage: vs=%v err=%v", vs, err)
	}
	e.f.setStatus(500)
	if vs, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil || len(vs) != 1 {
		t.Fatalf("500: vs=%v err=%v", vs, err)
	}
	rc, _, err := e.cache.Get(context.Background(), "composer/packagist/p2/acme/pkg.json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Contains(b, []byte(`"version":"1.0.0"`)) {
		t.Fatalf("cache holds %q", b)
	}
}

func TestDistRefKeyInjective(t *testing.T) {
	e := newRegEnv(t)
	if e.src.distRefKey("a/b", "1", "A") == e.src.distRefKey("a/b", "1", "84") {
		t.Fatal("collision")
	}
	if err := storage.ValidKey(e.src.distRefKey("a/b", "1.0", "AbC/..")); err != nil {
		t.Fatal(err)
	}
}

func TestDistEmptyReferenceNotFound(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[{"version":"1.0.0","dist":{"url":"http://x/y.zip","type":"zip","shasum":""}}]}}`))
	if _, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", ""); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestMetadataDuplicateNormalisedNamesRejected(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[{"version":"1.0.0"}],"Acme/Pkg":[{"version":"2.0.0"}]}}`))
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestMetadataEmptyPackagesNotFound(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", []byte(`{"packages":{}}`))
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); !errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestDistUpstream404IsNotAMiss(t *testing.T) {
	e := newRegEnv(t)
	e.f.set("/p2/acme/pkg.json", distMeta(e.f.srv.URL, "", "r1"))
	_, err := e.src.Dist(context.Background(), "acme/pkg", "1.0.0", "r1")
	if err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestMetadataRejectsForeignVersionName(t *testing.T) {
	e := newRegEnv(t)
	good := distMeta(e.f.srv.URL, "", "r1")
	e.f.set("/p2/acme/pkg.json", good)
	if _, err := e.src.Versions(context.Background(), "acme/pkg", false); err != nil {
		t.Fatal(err)
	}
	// A version entry naming another package is invalid metadata: it is never
	// cached, and stale good metadata is served instead.
	e.f.set("/p2/acme/pkg.json", []byte(`{"minified":"composer/2.0","packages":{"acme/pkg":[{"name":"acme/pkg","version":"1.0.0","dist":{"url":"u","reference":"r"}},{"name":"evil/other","version":"2.0.0"}]}}`))
	e.clock = e.clock.Add(time.Hour)
	vs, err := e.src.Versions(context.Background(), "acme/pkg", false)
	if err != nil || len(vs) != 1 || vs[0].Version != "1.0.0" {
		t.Fatalf("stale not served: vs=%v err=%v", vs, err)
	}
	if h := e.src.Health(context.Background()); h[0].OK {
		t.Fatalf("invalid metadata not reported: %+v", h)
	}
	// Without a cache it is an error, not a miss. Case differences are fine.
	e2 := newRegEnv(t)
	e2.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[{"name":"ACME/Pkg","version":"1.0.0"},{"name":"evil/other","version":"2.0.0"}]}}`))
	if _, err := e2.src.Versions(context.Background(), "acme/pkg", false); err == nil || errors.Is(err, resolve.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	e2.f.set("/p2/acme/pkg.json", []byte(`{"packages":{"acme/pkg":[{"name":"ACME/Pkg","version":"1.0.0"}]}}`))
	e2.clock = e2.clock.Add(time.Hour)
	if vs, err := e2.src.Versions(context.Background(), "acme/pkg", false); err != nil || len(vs) != 1 {
		t.Fatalf("vs=%v err=%v", vs, err)
	}
}
